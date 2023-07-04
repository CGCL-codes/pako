use std::collections::{HashMap, BTreeMap, HashSet};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use crate::aggregator::Aggregator;
use crate::config::{Committee, Parameters, EpochNumber, ViewNumber};
use crate::filter::FilterInput;
use crate::mempool::MempoolDriver;
use crate::synchronizer::{ElectionState, ElectionFuture, transmit};
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::*;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use futures::{StreamExt, Future};
use futures::stream::FuturesUnordered;
use log::{debug, warn, error, info};
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use store::Store;

pub struct Core {
    name: PublicKey,
    committee: Committee,
    parameters: Parameters,
    signature_service: SignatureService,
    pk_set: PublicKeySet,

    store: Store,
    mempool_driver: MempoolDriver,
    network_filter: Sender<FilterInput>,

    core_channel: Receiver<ConsensusMessage>,
    halt_channel: Sender<(Arc<Mutex<ElectionState>>, Block)>, // handle halts
    advance_channel: Receiver<Block>, // propose block for next epoch
    commit_channel: Sender<Block>,

    votes_aggregators: HashMap<(EpochNumber, Digest), Aggregator>, // n-f votes collector
    election_states: HashMap<(EpochNumber, ViewNumber), Arc<Mutex<ElectionState>>>, // stores states of leader election and block delivery
    blocks_received: HashMap<(PublicKey, EpochNumber, ViewNumber), Block>,  // blocks received from others and the node itself, will be updated as consensus proceeds

    halt_mark: EpochNumber,
    epochs_halted: HashSet<EpochNumber>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
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
        let (tx_halt, mut rx_halt): (_, Receiver<(Arc<Mutex<ElectionState>>, Block)>) = channel(10000);
        let (tx_advance, rx_advance): (Sender<Block>, _) = channel(10000);

        // Handle Halt till receives the leader.
        tokio::spawn(async move {
            let mut halt_mark = 0;
            let mut epochs_halted = HashSet::new();
            let mut halts_unhandled = HashMap::<EpochNumber, Vec<Block>>::new();
            let mut waiting = FuturesUnordered::<Pin<Box<dyn Future<Output=RandomCoin> + Send>>>::new();
            loop {
                tokio::select! {
                    Some((election_state, block)) = rx_halt.recv() => {
                        halts_unhandled.entry(block.epoch)
                            .or_insert_with(|| {
                                waiting.push(Box::pin(ElectionFuture{election_state}));
                                Vec::new()
                            })
                            .push(block);
                    },
                    Some(coin) = waiting.next() => {
                        let blocks = halts_unhandled.remove(&coin.epoch).unwrap();
                        let verified = blocks.into_iter()
                            .find(|b| b.author == coin.leader && !epochs_halted.contains(&coin.epoch) && coin.epoch > halt_mark);
                        if let Some(verified) = verified {
                            // Broadcast Halt and propose block of next epoch.
                            if let Err(e) = tx_advance.send(verified.clone()).await {
                                panic!("Failed to send message through advance channel: {}", e);
                            }
                            // Clean up halted.
                            epochs_halted.insert(coin.epoch);
                            if epochs_halted.remove(&(halt_mark + 1)) {
                                halt_mark += 1;
                            }
                            
                        }
                    },
                    else => break,
                }
            }
        });

        Self {
            name,
            committee,
            parameters,
            signature_service,
            pk_set,
            store,
            mempool_driver,
            network_filter,
            core_channel,
            commit_channel,
            halt_channel: tx_halt,
            advance_channel: rx_advance,
            votes_aggregators: HashMap::new(),
            election_states: HashMap::new(),
            blocks_received: HashMap::new(),
            halt_mark: 0,
            epochs_halted: HashSet::new(),
        }
    }

    // Get block by digest <epoch, view, author>.
    async fn read(&mut self, digest: &Digest) -> ConsensusResult<Block> {
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

    fn get_optimistic_leader(&self, epoch: EpochNumber) -> PublicKey {
        self.committee
            .get_public_key(epoch as usize % self.committee.size())
            .unwrap()
    } 

    // Starts the SPB phase.
    async fn spb(&mut self, block: Block) -> ConsensusResult<()> {
        debug!("Processing {:?}", block);

        // Check value.
        ensure!(
            self.check_value(&block),
            ConsensusError::InvalidVoteProof(block.proof)
        );
        
        // Start the first PB.
        self.pb(&block).await?;

        // Store the block.
        self.store(&block).await;

        Ok(())
    }

    async fn pb(&mut self, block: &Block) -> ConsensusResult<()> {
        // Update proof of the block of the node's own.
        self.update_block(block.clone());

        // Collect the node's own echo.
        let echo = Echo::new(block.digest(), 
            block.author, 
            match &block.proof {
                Proof::Pi(_) => PBPhase::Phase1,
                Proof::Sigma(_, _) => PBPhase::Phase2,
            },
            block.epoch,
            block.view, 
            self.name, 
            self.signature_service.clone()).await;
        self.votes_aggregators
            .entry((echo.epoch, echo.digest()))
            .or_insert_with(|| Aggregator::new())
            .append(echo.author, ConsensusMessage::Echo(echo.clone()), self.committee.stake(&echo.author))?;

        // Broadcast VAL to all nodes.
        let message = ConsensusMessage::Val(block.clone());
        self.transmit(message, None).await?;

        Ok(())
    }

    async fn handle_val(&mut self, block: Block) -> ConsensusResult<()> {
        // Check the block is correctly formed.
        block.verify(&self.committee, self.halt_mark, &self.epochs_halted)?;

        // Validate block.
        ensure!(
            self.value_validation(&block),
            ConsensusError::InvalidVoteProof(block.proof.clone())
        );

        let phase = match &block.proof {
            Proof::Pi(_) => {
                self.store(&block).await;
                self.update_block(block.clone());
                PBPhase::Phase1
            },
            Proof::Sigma(_, _) => {
                // If block is in the second PB phase, update block proof. 
                // We now get a PB-verified block with sigma1, say that this block gets locked.
                self.update_block(block.clone());
                PBPhase::Phase2
            },
        };

        // Send echo msg.
        self.echo(block.digest(), 
            &block.author, 
            phase, 
            block.epoch,
            block.view,
            self.signature_service.clone(),
            self.get_optimistic_leader(block.epoch) == block.author
        ).await
    }

    async fn echo(&self, 
        block_digest: Digest,
        block_author: &PublicKey, 
        phase: PBPhase, 
        epoch: EpochNumber,
        view: ViewNumber,
        signature_service: SignatureService,
        is_optimistic: bool
    ) -> ConsensusResult<()> {

        let echo = Echo::new(block_digest, 
            block_author.clone(), 
            phase,
            epoch,
            view, 
            self.name, 
            signature_service
        ).await;
        let message = ConsensusMessage::Echo(echo);

        // Broacast Echo if it's against block of optimistic leader,
        // else send Echo back to the block author.
        self.transmit(message, (!is_optimistic).then(|| block_author)).await?;

        Ok(())
    }

    async fn handle_echo(&mut self, echo: &Echo) -> ConsensusResult<()> {
        echo.verify(
            &self.committee, 
            &self.pk_set, 
            self.name,
            self.get_optimistic_leader(echo.epoch), 
            self.halt_mark, 
            &self.epochs_halted)?;

        self.votes_aggregators
            .entry((echo.epoch, echo.digest()))
            .or_insert_with(|| Aggregator::new())
            .append(echo.author, ConsensusMessage::Echo(echo.clone()), self.committee.stake(&echo.author))?;

        let shares = self.votes_aggregators
            .get_mut(&(echo.epoch, echo.digest()))
            .unwrap()
            .take(self.committee.quorum_threshold());

        match shares {
            None => Ok(()),

            // Combine shares into a compete signature.
            Some(msgs) => {
                let shares: BTreeMap<_, _> = msgs.into_iter()
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

                let threshold_signature = self.pk_set.combine_signatures(&shares).expect("not enough qualified shares");
                let mut block = self.get_block(echo.block_author, echo.epoch, echo.view).unwrap().clone();
                match echo.phase {
                    PBPhase::Phase1 => {
                        // Update proof and start PB of phase 2.
                        block.proof = Proof::Sigma(Some(threshold_signature), None);
                        self.pb(&block).await
                    },
                    PBPhase::Phase2 => {
                        // Finish SPB, update proof with sigma2 and broadcast Finish.
                        if let Proof::Sigma(sigma1, _) = block.proof {
                            block.proof = Proof::Sigma(sigma1, Some(threshold_signature));            
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
        // Update proof of the block of the node's own.
        self.update_block(block.clone());
        
        // Collect the node's own finish.
        let finish = Finish(block.clone());
        self.votes_aggregators
            .entry((finish.0.epoch, finish.digest()))
            .or_insert_with(|| Aggregator::new())
            .append(finish.0.author, ConsensusMessage::Finish(finish.clone()), self.committee.stake(&finish.0.author))?;

        // Broadcast Finish to all nodes.
        let message = ConsensusMessage::Finish(finish);
        self.transmit(message, None).await
    }

    async fn handle_finish(&mut self, finish: &Finish) -> ConsensusResult<()> {
        finish.0.verify(&self.committee, self.halt_mark, &self.epochs_halted)?;

        // Verify threshold signature.
        ensure!(
            finish.0.check_sigma2(&self.pk_set.public_key()),
            ConsensusError::InvalidVoteProof(finish.0.proof.clone())
        );

        self.votes_aggregators
            .entry((finish.0.epoch, finish.digest()))
            .or_insert_with(|| Aggregator::new())
            .append(finish.0.author, ConsensusMessage::Finish(finish.clone()), self.committee.stake(&finish.0.author))?;

        let finishes = self.votes_aggregators
            .get_mut(&(finish.0.epoch, finish.digest()))
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

    async fn done(&mut self, epoch: EpochNumber, view: ViewNumber) -> ConsensusResult<()> {
        let done = Done {
            epoch,
            view,
            author: self.name,
        };

        // Collect the node's own done.
        self.votes_aggregators
            .entry((done.epoch, done.digest()))
            .or_insert_with(|| Aggregator::new())
            .append(done.author, ConsensusMessage::Done(done.clone()), self.committee.stake(&done.author))?;

        let message = ConsensusMessage::Done(done);
        self.transmit(message, None).await?;

        Ok(())
    }

    async fn handle_done(&mut self, done: &Done) -> ConsensusResult<()> {
        done.verify(self.halt_mark, &self.epochs_halted)?;

        self.votes_aggregators
            .entry((done.epoch, done.digest()))
            .or_insert_with(|| Aggregator::new())
            .append(done.author, ConsensusMessage::Done(done.clone()), self.committee.stake(&done.author))?;

        let msgs = self.votes_aggregators
        .get_mut(&(done.epoch, done.digest()))
        .unwrap()
        .take(self.committee.random_coin_threshold());

        match msgs {
            None => (),

            // f+1 Done to enter leader election phase.
            Some(_) => {
                let randomness_share = RandomnessShare::new(
                    done.epoch,
                    done.view, 
                    self.name, 
                    self.signature_service.clone()
                ).await;

                // Collect the node's own randomness share.
                self.votes_aggregators
                    .entry((randomness_share.epoch, randomness_share.digest()))
                    .or_insert_with(|| Aggregator::new())
                    .append(randomness_share.author, 
                        ConsensusMessage::RandomnessShare(randomness_share.clone()), 
                        self.committee.stake(&randomness_share.author))?;

                let message = ConsensusMessage::RandomnessShare(randomness_share.clone());
                self.transmit(message, None).await?;
            },
        }

        if let Some(aggregator) = self.votes_aggregators.get(&(done.epoch, done.digest())) {
            if aggregator.weight == self.committee.quorum_threshold() {
                // TODO: After collecting n-f Done, abandon the rest SPB instances.
                // This can be done by set a mutex-free bool flag indicating whether n-f done have been collected.
                // In fact, the async/await strcuture of mvba protocol is sufficently fast to neglect actively abandoning.
            }
        }

        Ok(())
    }

    async fn handle_randommess_share(&mut self, randomness_share: &RandomnessShare) -> ConsensusResult<()> {
        randomness_share.verify(&self.committee, &self.pk_set, self.halt_mark, &self.epochs_halted)?;

        // f+1 shares to form a random coin.
        self.votes_aggregators
            .entry((randomness_share.epoch, randomness_share.digest()))
            .or_insert_with(|| Aggregator::new())
            .append(randomness_share.author, 
                ConsensusMessage::RandomnessShare(randomness_share.clone()), 
                self.committee.stake(&randomness_share.author))?;

        let shares = self.votes_aggregators
            .get_mut(&(randomness_share.epoch, randomness_share.digest()))
            .unwrap()
            .take(self.committee.random_coin_threshold());

        match shares {
            // Votes not enough.
            None => Ok(()),

            Some(msgs) => {
                let shares: Vec<RandomnessShare> = msgs.into_iter()
                    .filter_map(|s| {
                        match s {
                            ConsensusMessage::RandomnessShare(share) => Some(share),
                            _ => None,
                        }
                    })
                    .collect();

                // Combine shares into a complete signature.
                let share_map = shares.iter()
                    .map(|s| (self.committee.id(s.author), &s.signature_share))
                    .collect::<BTreeMap<_, _>>();
                let threshold_signature = self.pk_set.combine_signatures(share_map).expect("Unqualified shares!");

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
        random_coin.verify(&self.committee, &self.pk_set, self.halt_mark, &self.epochs_halted)?;

        // This wakes up the waker of ElectionFuture in task for handling Halt.
        let mut is_handled_before = false;
        {
            let mut election_state = self.election_states
                .entry((random_coin.epoch, random_coin.view))
                .and_modify(|e| {
                    match e.lock().unwrap().coin {
                        Some(_) => is_handled_before = true,
                        _ => (),
                    }
                })
                .or_insert(Arc::new(Mutex::new(ElectionState { coin: Some(random_coin.clone()), wakers: Vec::new() })))
                .lock()
                .unwrap();
            while let Some(waker) = election_state.wakers.pop() {
                waker.wake();
            }
        }

        // Skip coins already handled.
        if is_handled_before {
            return Ok(())
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

        let leader_finish = self.votes_aggregators
            .get(&(random_coin.epoch, finish_digest))
            .and_then(|ag| {
                ag.votes.iter()
                    .filter_map(|m| {
                        match m {
                            ConsensusMessage::Finish(finish) => Some(finish),
                            _ => None,
                        }
                    })
                    .find(|f| f.0.author == random_coin.leader)
            });

        if let Some(leader_finish) = leader_finish {
            self.handle_halt(leader_finish.0.clone()).await?;
        }

        // Enter two-vote phase.
        let body: Option<_> = match self.get_block(random_coin.leader, random_coin.epoch, random_coin.view) {
            Some(block) => {
                match &block.proof {
                    Proof::Sigma(_, _) => Some(PreVoteEnum::Yes(block.clone())),
                    Proof::Pi(_) => None,
                }
            },
            _ => None,
        };

        // Construct digest for `No` prevote.
        let digest = digest!(
            random_coin.epoch.to_le_bytes(),
            random_coin.view.to_le_bytes(),
            random_coin.leader.0,
            "NULL"
        );
        let body = match body {
            Some(body) => body,
            None => {
                let signature_share = self.signature_service.request_tss_signature(digest).await.unwrap();
                PreVoteEnum::No(signature_share)
            }
        };

        let prevote = PreVote {
            author: self.name, 
            epoch: random_coin.epoch,
            view: random_coin.view,
            leader: random_coin.leader,
            body,
        };
        // Collect the node's own Prevote.
        self.votes_aggregators
            .entry((prevote.epoch, prevote.digest()))
            .or_insert_with(|| Aggregator::new())
            .append(prevote.author, ConsensusMessage::PreVote(
                prevote.clone()), 
                self.committee.stake(&prevote.author
            ))?;

        // Broadcast PreVote message if leader's Finish was not delivered.
        self.transmit(ConsensusMessage::PreVote(prevote), None).await
    }

    async fn handle_prevote(&mut self, prevote: &PreVote) -> ConsensusResult<()> {
        prevote.verify(&self.committee, &self.pk_set, self.halt_mark, &self.epochs_halted)?;

        self.votes_aggregators
            .entry((prevote.epoch, prevote.digest()))
            .or_insert_with(|| Aggregator::new())
            .append(prevote.author, ConsensusMessage::PreVote(prevote.clone()), self.committee.stake(&prevote.author))?;

        let prevotes = self.votes_aggregators
            .get_mut(&(prevote.epoch, prevote.digest()))
            .unwrap()
            .take(self.committee.quorum_threshold());

        match prevotes {
            None => Ok(()),
            
            Some(prevotes) => {
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
                        let shares: BTreeMap<_, _> = prevotes.into_iter()
                            .filter_map(|prevote| {
                                match prevote {
                                    ConsensusMessage::PreVote(prevote) => Some(prevote),
                                    _ => None,
                                }
                            })
                            .filter_map(|prevote| {
                                match prevote.body {
                                    PreVoteEnum::No(share) => Some((self.committee.id(prevote.author), share)),
                                    _ => None,
                                }
                            })
                            .collect();
                        let threshold_signature = self.pk_set.combine_signatures(&shares).expect("not enough qualified shares");

                        let digest = digest!(
                            prevote.epoch.to_le_bytes(),
                            prevote.view.to_le_bytes(),
                            prevote.leader.0,
                            "UNLOCK"
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

                // Collect the node's own Vote.
                self.votes_aggregators
                    .entry((vote.epoch, vote.digest()))
                    .or_insert_with(|| Aggregator::new())
                    .append(vote.author, ConsensusMessage::Vote(vote.clone()), self.committee.stake(&vote.author))?;

                self.transmit(ConsensusMessage::Vote(vote), None).await
            },
        }
    }

    async fn handle_vote(&mut self, vote: Vote) -> ConsensusResult<()> {
        vote.verify(&self.committee, &self.pk_set, self.halt_mark, &self.epochs_halted)?;

        self.votes_aggregators
            .entry((vote.epoch, vote.digest()))
            .or_insert_with(|| Aggregator::new())
            .append(vote.author, ConsensusMessage::Vote(vote.clone()), self.committee.stake(&vote.author))?;

        let votes = self.votes_aggregators
            .get_mut(&(vote.epoch, vote.digest()))
            .unwrap()
            .take(self.committee.quorum_threshold());

        match votes {
            // Votes not enough.
            None => Ok(()),

            Some(votes) => {
                let votes: Vec<_> = votes.into_iter()
                .filter_map(|vote| {
                    match vote {
                        ConsensusMessage::Vote(vote) => Some(vote),
                        _ => None,
                    }
                }).collect();

                // n-f `Yes` votes.
                if votes.iter().all(|vote| matches!(vote.body, VoteEnum::Yes(_, _))) {
                    let shares: BTreeMap<_, _> = votes.iter()
                        .filter_map(|vote| match &vote.body {
                            VoteEnum::Yes(_, share) => Some((self.committee.id(vote.author), share)),
                            _ => None,
                        }).collect();
                    let sigma2 = self.pk_set.combine_signatures(shares).expect("not enough qualified shares");
                    
                    // Add sigma2 and halt.
                    if let VoteEnum::Yes(block, _) = &vote.body {
                        if let Proof::Sigma(sigma1, _) = &block.proof {
                            let mut completed_block = block.clone();
                            completed_block.proof = Proof::Sigma(sigma1.clone(), Some(sigma2));
                            self.handle_halt(completed_block).await?;
                        }
                    }
                } 
                // n-f `No` votes.
                else if votes.iter().all(|vote| matches!(vote.body, VoteEnum::No(_, _))) {
                    let shares: BTreeMap<_, _> = votes.iter()
                        .filter_map(|vote| match &vote.body {
                            VoteEnum::No(_, share) => Some((self.committee.id(vote.author), share)),
                            _ => None,
                        }).collect();
                    let quorum_for_null = self.pk_set.combine_signatures(shares).expect("not enough qualified shares");
                    
                    // Broadcast the same block in new round, except updated pi and view.
                    let pi = (false, vote.view, quorum_for_null);
                    let mut block = self.get_block(self.name, vote.epoch, vote.view).unwrap().clone();

                    // Update block and start SPB of next view.
                    block.proof = Proof::Pi(vec![pi]);
                    block.view += 1;
                    block.signature = self.signature_service.request_signature(block.digest()).await;
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
                    let mut block = self.get_block(self.name, vote.epoch, vote.view).unwrap().clone();

                    block.proof = Proof::Pi(vec![pi]);
                    block.view += 1;
                    block.signature = self.signature_service.request_signature(block.digest()).await;
                    self.spb(block).await?;
                }

                Ok(())
            },
        }
    }

    async fn handle_halt(&mut self, block: Block) -> ConsensusResult<()> {
        block.verify(&self.committee, self.halt_mark, &self.epochs_halted)?;

        ensure!(
            block.check_sigma1(&self.pk_set.public_key()) && block.check_sigma2(&self.pk_set.public_key()),
            ConsensusError::InvalidVoteProof(block.proof)
        );

        let election_state = self.election_states
            .entry((block.epoch, block.view))
            .or_insert(Arc::new(Mutex::new(ElectionState { coin: None, wakers: Vec::new() })))
            .clone();

        self.halt_channel.send((election_state, block)).await.expect("Failed to send Halt through halt channel.");

        Ok(())
    }

    async fn output(&mut self, block: Block) -> ConsensusResult<()> {
        // Output block with payloads.
        if let Err(e) = self.commit_channel.send(block.clone()).await {
            panic!("Failed to send message through commit channel: {}", e);
        } else {
            info!("Commit block {} of member {} in epoch {}, view {}", 
                block.digest(),
                block.author,
                block.epoch,
                block.view,    
            );
        }

        // Clean up mempool.
        self.cleanup_epoch(block).await?;

        Ok(())
    }

    async fn cleanup_epoch(&mut self, block: Block) -> ConsensusResult<()> {
        // Mark epoch as halted.
        self.epochs_halted.insert(block.epoch);
        if self.epochs_halted.remove(&(self.halt_mark + 1)) {
            self.halt_mark += 1;
        }

        self.blocks_received.retain(|&(_, e, _), _| e != block.epoch);
        self.votes_aggregators.retain(|&(e, _), _| e != block.epoch);
        self.election_states.retain(|&(e, _), _| e != block.epoch);

        // Clean up payloads.
        self.mempool_driver.cleanup_async(&block).await;

        Ok(())
    }

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block.
        let block = self.generate_block(1, 1, Proof::Pi(Vec::new()))
            .await
            .expect("Failed to generate the first block.");
        self.spb(block).await.expect("Failed to start spb the first block.");

        loop {
            let result = tokio::select! {
                Some(msg) = self.core_channel.recv() => {
                    match msg {
                        ConsensusMessage::Val(block) => self.handle_val(block).await,
                        ConsensusMessage::Echo(echo) => self.handle_echo(&echo).await,
                        ConsensusMessage::Finish(finish) => self.handle_finish(&finish).await,
                        ConsensusMessage::Halt(block) => self.handle_halt(block).await,
                        ConsensusMessage::Done(done) => self.handle_done(&done).await,
                        ConsensusMessage::RandomnessShare(randomness_share) => self.handle_randommess_share(&randomness_share).await,
                        ConsensusMessage::RandomCoin(coin) => self.handle_random_coin(coin).await,
                        ConsensusMessage::PreVote(prevote) => self.handle_prevote(&prevote).await,
                        ConsensusMessage::Vote(vote) => self.handle_vote(vote).await,
                    }
                },
                Some(block) = self.advance_channel.recv() => {                    
                    let new_block = self.generate_block(block.epoch+1, 1, Proof::Pi(Vec::new())).await
                        .expect(&format!("Failed to generate block of epoch {}", block.epoch));
                    self.spb(new_block).await.expect(&format!("Failed to start spb block of epoch {}", block.epoch+1));

                    // Forward Halt to others.
                    self.transmit(ConsensusMessage::Halt(block.clone()), None).await
                        .expect(&format!("Failed to forward Halt of epoch {}", block.epoch));

                    // Clean up this epoch.
                    self.output(block).await
                },
                else => break,
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