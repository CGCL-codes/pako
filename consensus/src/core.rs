use std::collections::{HashMap, BTreeMap};
use std::sync::{Arc, Mutex};

use crate::aggregator::Aggregator;
use crate::config::{Committee, Parameters, EpochNumber, ViewNumber};
use crate::filter::FilterInput;
use crate::mempool::MempoolDriver;
use crate::synchronizer::{DoneState, DoneFuture, transmit};
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::*;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use log::{debug, warn, error};
use threshold_crypto::{PublicKeySet, SignatureShare};
use tokio::sync::mpsc::{Receiver, Sender};
use store::Store;

pub struct Core {
    name: PublicKey,
    committee: Committee,
    parameters: Parameters,
    store: Store,
    signature_service: SignatureService,
    pk_set: PublicKeySet,
    mempool_driver: MempoolDriver,
    core_channel: Receiver<ConsensusMessage>,
    network_filter: Sender<FilterInput>,
    commit_channel: Sender<Block>,
    votes_aggregators: HashMap<Digest, Aggregator>, // n-f votes collector
    locks: HashMap<Digest, Block>,  // blocks received in current view with sigma1
    random_coin: HashMap<Digest, RandomCoin>,   // random coins of each <epoch, view>
    synchrony_states: HashMap<Digest, Arc<Mutex<DoneState>>>, // stores states of leader election and block delivery
    blocks_received: HashMap<(PublicKey, EpochNumber, ViewNumber), Block>,  // blocks received from others and the node itself, will be updated as consensus proceeds
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        signature_service: SignatureService,
        pk_set: PublicKeySet,
        store: Store,
        mempool_driver: MempoolDriver,
        core_channel: Receiver<ConsensusMessage>,
        network_filter: Sender<FilterInput>,
        commit_channel: Sender<Block>,
    ) -> Self {
        Self {
            name,
            committee,
            parameters,
            signature_service,
            pk_set,
            store,
            mempool_driver,
            network_filter,
            commit_channel,
            core_channel,
            votes_aggregators: HashMap::new(),
            locks: HashMap::new(),
            random_coin: HashMap::new(),
            synchrony_states: HashMap::new(),
            blocks_received: HashMap::new(),
        }
    }

    // Get block by digest <epoch, view, author>.
    async fn read(&mut self, digest: &Digest) -> ConsensusResult<Block> {
        // Wait until block is stored.
        let store_state = self.synchrony_states
            .entry(digest.clone())
            .or_insert(Arc::new(Mutex::new(DoneState { done: false, wakers: Vec::new() })));
        let store_fut = DoneFuture {
            done_state: Arc::clone(store_state),
        };
        store_fut.await;

        // Retreive block when future done.
        match self.store.read(digest.to_vec()).await? {
            Some(bytes) => {
                let block: Block = bincode::deserialize(&bytes)?;
                Ok(block)
            }
            None => Err(ConsensusError::DigestError),
        }
    }

    async fn store(&mut self, block: &Block) {
        // Store block with key <epoch, view, author>.
        let digest = digest!(block.epoch.to_le_bytes(), block.view.to_le_bytes(), block.author.0);
        let key = digest.to_vec();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store.write(key, value).await;

        // Notify store futures undone.
        let mut store_state = self.synchrony_states
            .entry(digest)
            .or_insert(Arc::new(Mutex::new(DoneState { done: false, wakers: Vec::new() })))
            .lock()
            .unwrap();
        store_state.done = true;
        while let Some(waker) = store_state.wakers.pop() {
            waker.wake();
        }
    }

    // Update the proof of the block.
    fn update_block(&mut self, block: Block) {
        self.blocks_received.insert((block.author, block.epoch, block.view), block);
    }

    fn get_block(&self, author: PublicKey, epoch: EpochNumber, view: ViewNumber) -> Option<&Block> {
        self.blocks_received.get(&(author, epoch, view))
    }

    // Generate a new block.
    async fn generate_block(&mut self, epoch: EpochNumber, view: ViewNumber, proof: Proof) -> ConsensusResult<Block> {
        // Get payloads.
        let payload = self
            .mempool_driver
            .get(self.parameters.max_payload_size)
            .await;

        let block = Block::new(
            payload,
            self.name,
            epoch,
            view,
            proof,
            self.signature_service.clone(),
        ).await;

        Ok(block)
    }

    // Get the leader of <epoch, view>.
    async fn get_leader(&mut self, epoch: EpochNumber, view: ViewNumber) -> ConsensusResult<PublicKey> {
        ensure!(
            epoch > 0 && view > 0,
            ConsensusError::InvalidEpochOrView(epoch, view)
        );

        // <epoch, view> as key to get corresponding election state of from synchrony_states.
        let digest = digest!(epoch.to_le_bytes(), view.to_le_bytes());
        let election_state = self.synchrony_states
            .entry(digest.clone())
            .or_insert(Arc::new(Mutex::new(DoneState { done: false, wakers: Vec::new() })));
        let election_fut = DoneFuture {
            done_state: Arc::clone(election_state),
        };
        election_fut.await;
        Ok(self.random_coin.get(&digest).unwrap().leader)
    }

    // TODO: implement check_value()
    fn check_value(&self, block: &Block) -> bool {
        true
    }

    // Value validation.
    fn value_validation(&self, block: &Block) -> bool {
        match block.proof {
            Proof::Pi(_) => self.check_value(block),

            // Block is supposed to carry sigma1 though not explicitly matched.
            Proof::Sigma(_, _) => block.check_sigma1(&self.pk_set.public_key()),
        }
    }

    async fn transmit(&self, message: ConsensusMessage, to: Option<&PublicKey>) -> ConsensusResult<()> {
        transmit(
            message,
            &self.name,
            to,
            &self.network_filter,
            &self.committee,
        ).await
    }

    // Starts the SPB phase.
    async fn spb(&mut self, block: Block) -> ConsensusResult<()> {
        debug!("Processing {:?}", block);

        // Verify block.
        block.verify(&self.committee)?;

        // Check value.
        ensure!(
            self.check_value(&block),
            ConsensusError::InvalidVoteProof(block.proof)
        );
        
        // Start the first PB.
        self.pb(&block).await?;

        // Store the block.
        self.store(&block).await;
        self.update_block(block.without_payload());

        Ok(())
    }

    async fn pb(&self, block: &Block) -> ConsensusResult<()> {
        // Collect the node's own echo.
        self.echo(block.digest(), 
            &block.author, 
            phase, 
            block.epoch,
            block.view,
            self.signature_service.clone()).await?;

        // Broadcast VAL to all nodes.
        let message = ConsensusMessage::Val(block.clone());
        self.transmit(message, None).await?;

        Ok(())
    }

    async fn handle_val(&mut self, block: Block) -> ConsensusResult<()> {
        // Check the block is correctly formed.
        block.verify(&self.committee)?;

        // Validate block.
        ensure!(
            self.value_validation(&block),
            ConsensusError::InvalidVoteProof(block.proof.clone())
        );

        let phase = match &block.proof {
            Proof::Pi(_) => {
                self.store(&block).await;
                self.update_block(block.without_payload());
                PBPhase::Phase1
            },
            Proof::Sigma(_, _) => {
                // If block is in the second PB phase, update the block. 
                // We now get a PB-verified block with sigma1, say that this block gets locked.
                self.update_block(block.clone());

                // Output Lock.
                // The digest is in PreVote's form to simplify share verification later.
                let digest = digest!(
                    block.epoch.to_le_bytes(),
                    block.view.to_le_bytes(),
                    block.author.0,
                    "PREVOTE"
                );
                self.locks.insert(digest, block.clone());

                PBPhase::Phase2
            },
        };

        // Send echo msg.
        self.echo(block.digest(), 
            &block.author, 
            phase, 
            block.epoch,
            block.view,
            self.signature_service.clone()).await
    }

    async fn echo(&self, 
        block_digest: Digest,
        block_author: &PublicKey, 
        phase: PBPhase, 
        epoch: EpochNumber,
        view: ViewNumber,
        signature_service: SignatureService) -> ConsensusResult<()> {

        let echo = Echo::new(block_digest, 
            block_author.clone(), 
            phase,
            epoch,
            view, 
            self.name, 
            signature_service).await;

        // Send ECHO to block author.
        let message = ConsensusMessage::Echo(echo);
        self.transmit(message, Some(block_author)).await?;

        Ok(())
    }

    async fn handle_echo(&mut self, echo: &Echo) -> ConsensusResult<()> {
        echo.verify(&self.committee, &self.pk_set, self.name)?;

        self.votes_aggregators
            .entry(echo.digest())
            .or_insert_with(|| Aggregator::new())
            .append(echo.author, ConsensusMessage::Echo(echo.clone()), self.committee.stake(&echo.author))?;

        let shares = self.votes_aggregators
            .get(&echo.digest())
            .unwrap()
            .take(self.committee.quorum_threshold());

        match shares {
            None => Ok(()),

            // Combine shares into a compete signature.
            Some(msgs) => {
                let mut shares: BTreeMap<_, _> = msgs.into_iter()
                    .filter_map(|s| {
                        match s {
                            ConsensusMessage::Echo(echo) => {
                                let id = self.committee.id(echo.author);
                                Some((id, echo.signature_share))
                            },
                            _ => None,
                        }}
                    )
                    .collect();

                // Insert the node's own share.
                let share = self.signature_service.request_tss_signature(echo.block_digest.clone()).await.unwrap();
                shares.insert(self.committee.id(self.name), share);

                let threshold_signature = self.pk_set.combine_signatures(&shares).expect("not enough qualified shares");
                let mut block = self.get_block(echo.block_author, echo.epoch, echo.view).unwrap().clone();
                match echo.phase {
                    PBPhase::Phase1 => {
                        // Update proof.
                        block.proof = Proof::Sigma(Some(threshold_signature), None);
                        self.update_block(block.clone());

                        let a = block.verify(&self.committee).is_ok();

                        // Start the second PB.
                        self.pb(&block).await
                    },
                    PBPhase::Phase2 => {
                        // Finish SPB phase.
                        if let Proof::Sigma(sigma1, _) = block.proof {
                            // Update proof with sigma2.
                            block.proof = Proof::Sigma(sigma1, Some(threshold_signature));
                            self.update_block(block.clone());

                            // Broadcast finish.                
                            self.finish(&block).await
                        } else {
                            return Err(ConsensusError::InvalidThresholdSignature(block.author));
                        }
                    }
                }
            },
        }

    }

    async fn finish(&mut self, block: &Block) -> ConsensusResult<()> {
        // Collect the node's own finish.
        let finish = Finish(block.clone());
        self.votes_aggregators
            .entry(finish.digest())
            .or_insert_with(|| Aggregator::new())
            .append(finish.0.author, ConsensusMessage::Finish(finish.clone()), self.committee.stake(&finish.0.author))?;

        // Broadcast Finish to all nodes.
        let message = ConsensusMessage::Finish(finish);
        self.transmit(message, None).await
    }

    async fn handle_finish(&mut self, finish: &Finish) -> ConsensusResult<()> {
        // Verify threshold signature.
        ensure!(
            finish.0.check_sigma2(&self.pk_set.public_key()),
            ConsensusError::InvalidVoteProof(finish.0.proof.clone())
        );

        self.votes_aggregators
            .entry(finish.digest())
            .or_insert_with(|| Aggregator::new())
            .append(finish.0.author, ConsensusMessage::Finish(finish.clone()), self.committee.stake(&finish.0.author))?;

        let finishes = self.votes_aggregators
            .get(&finish.digest())
            .unwrap()
            .take(self.committee.quorum_threshold());

        match finishes {
            None => Ok(()),

            // Broadcast Done if received n-f Finish.
            Some(_) => {
                self.done(finish.0.epoch, finish.0.view).await
            },
        }
    }

    async fn done(&self, epoch: EpochNumber, view: ViewNumber) -> ConsensusResult<()> {
        let done = Done {
            epoch,
            view,
            author: self.name,
        };

        let message = ConsensusMessage::Done(done);
        self.transmit(message, None).await?;

        Ok(())
    }

    async fn handle_done(&mut self, done: &Done) -> ConsensusResult<()> {
        let msgs = self.votes_aggregators
            .entry(done.digest())
            .or_insert_with(|| Aggregator::new())
            .append(done.author, ConsensusMessage::Done(done.clone()), &self.committee);

        match msgs {
            Err(e) => return Err(e),
            Ok(None) => (),
            Ok(Some(_)) => {
                // TODO: After collecting n-f Done, abandon the rest SPB instances.
                // This can be done by set a mutex-free bool flag indicating whether n-f done have been collected.
                // In fact, the async/await strcuture of mvba protocol is sufficently fast to neglect actively abandoning.
            },
        }

        // f+1 Done to enter leader election phase.
        if let Some(aggregator) = self.votes_aggregators.get(&done.digest()) {
            if aggregator.ready_for_random_coin(&self.committee) {
                let randomness_share = RandomnessShare::new(
                    done.epoch,
                    done.view, 
                    self.name, 
                    self.signature_service.clone()
                ).await;
                let message = ConsensusMessage::RandomnessShare(randomness_share.clone());
                self.transmit(message, None).await?;
            }
        }

        Ok(())
    }

    async fn handle_randommess_share(&mut self, randomness_share: &RandomnessShare) -> ConsensusResult<()> {
        randomness_share.verify(&self.committee, &self.pk_set)?;

        // f+1 shares to form a random coin.
        let shares = self.votes_aggregators
            .entry(randomness_share.digest())
            .or_insert_with(|| Aggregator::new())
            .append(randomness_share.author, ConsensusMessage::RandomnessShare(randomness_share.clone()), &self.committee);

        match shares {
            Err(e) => Err(e),

            // Votes not enough.
            Ok(None) => Ok(()),

            Ok(Some(msgs)) => {
                let mut shares: Vec<RandomnessShare> = msgs.into_iter()
                    .filter_map(|s| {
                        match s {
                            ConsensusMessage::RandomnessShare(share) => Some(share),
                            _ => None,
                        }
                    })
                    .collect();

                // Insert the node's own share.
                let share = self.signature_service.request_tss_signature(randomness_share.digest()).await.unwrap();
                let share = RandomnessShare { 
                    epoch: randomness_share.epoch,
                    view: randomness_share.view,
                    author: self.name,
                    signature_share: share
                };
                shares.push(share);

                // Combine shares into a complete signature.
                let share_map = shares.iter()
                    .map(|s| (self.committee.id(s.author), s.signature_share.clone()))
                    .collect::<BTreeMap<_, _>>();
                let threshold_signature = self.pk_set.combine_signatures(&share_map).expect("Unqualified shares!");

                // Use coin to elect leader. 
                let id = usize::from_be_bytes((&threshold_signature.to_bytes()[0..8]).try_into().unwrap()) % self.committee.size();
                let mut keys: Vec<_> = self.committee.authorities.keys().cloned().collect();
                keys.sort();
                let leader = keys[id];
                debug!("Random coin of epoch {} view {} elects leader id {}", randomness_share.epoch, randomness_share.view, id);

                let random_coin = RandomCoin {
                    epoch: randomness_share.epoch,
                    view: randomness_share.view, 
                    leader, 
                    shares,
                };
                self.handle_random_coin(random_coin.clone()).await
            },
        }

    }

    async fn handle_random_coin(&mut self, random_coin: RandomCoin) -> ConsensusResult<()> {
        random_coin.verify(&self.committee, &self.pk_set)?;

        // Store coins not handled before.
        if self.random_coin.contains_key(&random_coin.digest()) {
            return Ok(())
        }
        self.random_coin.insert(random_coin.digest(), random_coin.clone());

        // Set ElectionState of <epoch, view> of done msg as `done`,
        // this wakes up the Waker of ElectionFuture of get_leader(),
        // then all calls of get_leader().await make progress.
        {
            let digest = digest!(random_coin.epoch.to_le_bytes(), random_coin.view.to_le_bytes());
            let mut election_state = self.synchrony_states
                .entry(digest)
                .or_insert(Arc::new(Mutex::new(DoneState { done: false, wakers: Vec::new() })))
                .lock()
                .unwrap();
            election_state.done = true;
            while let Some(waker) = election_state.wakers.pop() {
                waker.wake();
            }
        }
        
        // Multicast the random coin.
        let message = ConsensusMessage::RandomCoin(random_coin.clone());
        self.transmit(message, None).await?;

        // Had the current leader's Finish received, halt and output.
        let finish_digest = digest!(
            random_coin.epoch.to_le_bytes(), 
            random_coin.view.to_le_bytes(),
            "FINISH"
        );
        let mut finishes = self.votes_aggregators.get(&finish_digest).unwrap().votes.clone();

        // Since we won't receive the node's own finish, we rely on the block with sigma2
        // stored in block_received which equally functions as block finished.
        let block = self.get_block(self.name, random_coin.epoch, random_coin.view);
        finishes.push(ConsensusMessage::Finish(Finish(block)));

        let leader_finish = finishes.into_iter()
            .filter_map(|f| {
                match f {
                    ConsensusMessage::Finish(finish) => Some(finish),
                    _ => None,
                }
            })
            .find(|f| f.0.author == random_coin.leader);

        if let Some(leader_finish) = leader_finish {
            let halt = ConsensusMessage::Halt(leader_finish.0.clone());
            self.transmit(halt, None).await?;

            // Terminate and start a new epoch.
            self.output(leader_finish.0.clone()).await?;
            let new_block = self.generate_block(random_coin.epoch + 1, 1, Proof::Pi(Vec::new())).await?;
            self.spb(new_block).await?;
        }

        // This is a digest of PreVote msg constructed in advance to retrieve block in lock, 
        // and used to verify `No` prevotes if block in None.
        let digest = digest!(
            random_coin.epoch.to_le_bytes(),
            random_coin.view.to_le_bytes(),
            random_coin.leader.0,
            "PREVOTE"
        );
        let body = match self.locks.get(&digest) {
            Some(block) => PreVoteEnum::Yes(block.clone()),
            None => {
                let signature_share = self.signature_service.request_tss_signature(digest).await.unwrap();
                PreVoteEnum::No(signature_share)
            },
        };

        let body = match self.get_block(random_coin.leader, random_coin.epoch, random_coin.view) 

        // Broadcast PreVote message if leader's Finish was not delivered.
        self.transmit(
            ConsensusMessage::PreVote(PreVote {
                    author: self.name, 
                    epoch: random_coin.epoch,
                    view: random_coin.view,
                    leader: random_coin.leader,
                    body
                }), None).await
    }

    async fn handle_halt(&mut self, block: &Block) -> ConsensusResult<()> {
        if block.author == self.get_leader(block.epoch, block.view).await.unwrap() {
            block.verify(&self.committee)?;

            // Broadcast halt and output
            let halt = ConsensusMessage::Halt(block.clone());
            self.transmit(halt, None).await?;
            self.output(block.clone()).await?;

            // Propose next block.
            let new_block = self.generate_block(block.epoch+1, block.view+1, Proof::Pi(Vec::new())).await?;
            self.spb(new_block).await?;    
        }

        Ok(())
    }

    async fn handle_prevote(&mut self, prevote: &PreVote) -> ConsensusResult<()> {
        prevote.verify(&self.committee, &self.pk_set)?;

        let prevotes = self.votes_aggregators
            .entry(prevote.digest())
            .or_insert_with(|| Aggregator::new())
            .append(prevote.author, ConsensusMessage::PreVote(prevote.clone()), &self.committee);

        match prevotes {
            Err(e) => Err(e),
            Ok(None) => Ok(()),
            
            Ok(Some(prevotes)) => {
                let locked_block = prevotes.iter()
                .filter_map(|prevote| {
                    match prevote {
                        ConsensusMessage::PreVote(prevote) => Some(prevote),
                        _ => None,
                    }
                })
                .find_map(|prevote| 
                    match &prevote.body {
                        PreVoteEnum::Yes(block) => Some(block),
                        _ => None,
                    }
                );
                
                // Broadcast Vote.
                let body = match locked_block {
                    // Broadcast `Yes` Vote if leader's block with sigma1 was received.
                    Some(block) => {
                        // Generate the share for sigma2.
                        let signature_share = self.signature_service.request_tss_signature(block.digest()).await.unwrap();
                        VoteEnum::Yes(block.clone(), signature_share)
                    },

                    // Else broadcast `No` Vote.
                    None => {
                        let shares: Vec<_> = prevotes.into_iter()
                            .filter_map(|prevote| {
                                match prevote {
                                    ConsensusMessage::PreVote(prevote) => Some(prevote.body),
                                    _ => None,
                                }
                            })
                            .filter_map(|e| {
                                match e {
                                    PreVoteEnum::No(share) => Some(share),
                                    _ => None,
                                }
                            })
                            .collect();
                        let shares: BTreeMap<_, _> = (0..shares.len()).map(|i| (i, shares.get(i).unwrap())).collect();
                        let threshold_signature = self.pk_set.combine_signatures(shares).expect("not enough qualified shares");

                        // This is a digest of Vote msg constructed in advance, used to verify `No` votes.
                        let digest = digest!(
                            prevote.epoch.to_le_bytes(),
                            prevote.view.to_le_bytes(),
                            prevote.leader.0,
                            "VOTE"
                        ); 
                        let share = self.signature_service.request_tss_signature(digest).await.unwrap();

                        VoteEnum::No(threshold_signature, share)
                    },
                };
                let vote = Vote {
                    author: self.name, 
                    epoch: prevote.epoch,
                    view: prevote.view,
                    leader: prevote.leader,
                    body,
                };
                self.transmit(ConsensusMessage::Vote(vote), None).await
            },
        }
    }

    async fn handle_vote(&mut self, vote: Vote) -> ConsensusResult<()> {
        vote.verify(&self.committee, &self.pk_set)?;

        let votes = self.votes_aggregators
            .entry(vote.digest())
            .or_insert_with(|| Aggregator::new())
            .append(vote.author, ConsensusMessage::Vote(vote.clone()), &self.committee);

        match votes {
            Err(e) => Err(e),

            // Votes not enough.
            Ok(None) => Ok(()),

            Ok(Some(votes)) => {
                let votes: Vec<_> = votes.into_iter()
                .filter_map(|vote| {
                    match vote {
                        ConsensusMessage::Vote(vote) => Some(vote),
                        _ => None,
                    }
                }).collect();

                // n-f `Yes` votes.
                if votes.iter().all(|vote| matches!(vote.body, VoteEnum::Yes(_, _))) {
                    let shares: Vec<_> = votes.iter()
                        .filter_map(|vote| match &vote.body {
                            VoteEnum::Yes(_, share) => Some(share.clone()),
                            _ => None,
                        }).collect();
                    let shares: BTreeMap<_, _> = (0..shares.len()).map(|i| (i, shares.get(i).unwrap())).collect();
                    let sigma2 = self.pk_set.combine_signatures(shares).expect("not enough qualified shares");
                    
                    // Finish broadcasting leader's block, halt and output. 
                    if let VoteEnum::Yes(block, _) = &vote.body {
                        if let Proof::Sigma(sigma1, _) = &block.proof {
                            // Add sigma2 and broadcast finish.
                            let mut completed_block = block.clone();
                            completed_block.proof = Proof::Sigma(sigma1.clone(), Some(sigma2));
                            self.transmit(ConsensusMessage::Halt(completed_block.clone()), None).await?;
                            self.output(completed_block).await?;
                            
                            // Propose next block.
                            let new_block = self.generate_block(block.epoch+1, block.view+1, Proof::Pi(Vec::new())).await?;
                            self.transmit(ConsensusMessage::Val(new_block), None).await?
                        }
                    }
                } 
                // n-f `No` votes.
                else if votes.iter().all(|vote| matches!(vote.body, VoteEnum::No(_, _))) {
                    let shares: Vec<_> = votes.iter()
                        .filter_map(|vote| match &vote.body {
                            VoteEnum::No(_, share) => Some(share.clone()),
                            _ => None,
                        }).collect();
                    let shares_map: BTreeMap<_, _> = (0..shares.len()).map(|i| (i, shares.get(i).unwrap())).collect();
                    let quorum_for_null = self.pk_set.combine_signatures(shares_map).expect("not enough qualified shares");
                    
                    // Broadcast the same block in new round, except updated pi and view.
                    let pair = (false, vote.view, quorum_for_null);
                    let mut block = self.read(&digest!(vote.epoch.to_le_bytes(), vote.view.to_le_bytes(), self.name.0)).await?;
                    if let Proof::Pi(pi) = &mut block.proof {
                        pi.push(pair);
                    }
                    block.view += 1;
                    self.spb(block).await?;
                } 
                // Mixed `Yes` and `No` votes.
                else {
                    let sigma1 = votes.iter()
                        .find_map(|vote| {
                            match &vote.body {
                                VoteEnum::Yes(block, _) => {
                                    match &block.proof {
                                        Proof::Sigma(sigma1, _) => Some(sigma1),
                                        _ => None,
                                    }
                                },
                                _ => None,
                            }
                        }).unwrap();
                    
                    // Broadcast the leader's block in next round.
                    let pi = (true, vote.view, sigma1.as_ref().unwrap().clone());
                    let mut block = self.read(&digest!(vote.epoch.to_le_bytes(), vote.view.to_le_bytes(), vote.leader.0)).await?;
                    block.proof = Proof::Pi(vec![pi]);
                    block.view += 1;
                    self.spb(block).await?;
                }

                Ok(())
            },
        }
    }

    async fn output(&mut self, block: Block) -> ConsensusResult<()> {
        debug!("Commit block {:?} ", block);

        // Output.
        if let Err(e) = self.commit_channel.send(block.clone()).await {
            warn!("Failed to send block through the commit channel: {}", e);
        }

        // Let's see if we have the block's data. If we don't, the mempool will get it.
        if !self.mempool_driver.verify(block.clone()).await? {
            return Ok(());
        }

        // Clean up mempool.
        self.cleanup_epoch(block).await?;

        Ok(())
    }

    // TODO: Clean up blocks and payloads of non-leaders.
    async fn cleanup_epoch(&mut self, block: Block) -> ConsensusResult<()> {
        // Clean up blocks.


        // Clean up payloads.
        self.mempool_driver.cleanup_async(&block).await;

        Ok(())
    }

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block.
        let block = self.generate_block(1, 1, Proof::Pi(Vec::new()))
            .await
            .expect("Failed to generate the first block.");
        self.spb(block).await.expect("Failed to broadcast the first block.");

        loop {
            let result = tokio::select! {
                Some(msg) = self.core_channel.recv() => {
                    match msg {
                        ConsensusMessage::Val(block) => self.handle_val(block).await,
                        ConsensusMessage::Echo(echo) => self.handle_echo(&echo).await,
                        ConsensusMessage::Finish(finish) => self.handle_finish(&finish).await,
                        ConsensusMessage::Halt(block) => self.handle_halt(&block).await,
                        ConsensusMessage::Done(done) => self.handle_done(&done).await,
                        ConsensusMessage::RandomnessShare(randomness_share) => self.handle_randommess_share(&randomness_share).await,
                        ConsensusMessage::RandomCoin(coin) => self.handle_random_coin(coin).await,
                        ConsensusMessage::PreVote(prevote) => self.handle_prevote(&prevote).await,
                        ConsensusMessage::Vote(vote) => self.handle_vote(vote).await,
                        ConsensusMessage::LoopBack(block) => self.cleanup_epoch(block).await,
                    }
                }
            };

            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
        }
    }
}