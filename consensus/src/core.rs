use std::collections::{HashMap, BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use crate::aggregator::Aggregator;
use crate::config::{Committee, Parameters, EpochNumber, ViewNumber};
use crate::filter::ConsensusFilterInput;
use crate::mempool::MempoolDriver;
use crate::synchronizer::{ElectionState, transmit, Synchronizer, BAState, TimeoutState};
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::*;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
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
    network_filter: Sender<ConsensusFilterInput>,

    core_channel: Receiver<ConsensusMessage>,
    timeout_channel: Sender<Arc<Mutex<TimeoutState>>>, // handle timeout if didn't receive optimistic sigma1
    timeout_result_channel: Receiver<EpochNumber>, // signal main loop to enter amplify phase
    aba_sync_sender: Sender<(EpochNumber, Arc<Mutex<BAState>>)>, // invoke aba, wait for done
    aba_sync_feedback_receiver: Receiver<(EpochNumber, bool)>,
    halt_channel: Sender<(Arc<Mutex<ElectionState>>, Block)>, // handle halts
    advance_channel: Receiver<Halt>, // propose block for next epoch
    commit_channel: Sender<Block>,

    votes_aggregators: HashMap<(EpochNumber, Digest), Aggregator<ConsensusMessage>>, // n-f votes collector
    election_states: HashMap<(EpochNumber, ViewNumber), Arc<Mutex<ElectionState>>>, // stores states of leader election
    ba_states: HashMap<EpochNumber, Arc<Mutex<BAState>>>, // store states of ABA, indicating whether ABA result is arrived
    ba_inputs: HashMap<EpochNumber, Arc<Mutex<TimeoutState>>>, // store input states of ABA, indicating whether ABA input is prepared
    blocks_received: HashMap<(PublicKey, EpochNumber, ViewNumber), Block>,  // blocks received from others and the node itself, will be updated as consensus proceeds

    halt_mark: EpochNumber,
    epochs_halted: HashSet<EpochNumber>,
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
        aba_channel: Sender<(EpochNumber, bool)>,
        aba_feedback_channel: Receiver<(EpochNumber, bool)>,
        network_filter: Sender<ConsensusFilterInput>,
        commit_channel: Sender<Block>,
    ) -> Self {
        let (tx_halt, rx_halt): (_, Receiver<(Arc<Mutex<ElectionState>>, Block)>) = channel(10000);
        let (tx_advance, rx_advance) = channel(10000);
        let (aba_sync_sender, aba_sync_receiver)  = channel(10000);
        let (aba_sync_feedback_sender, aba_sync_feedback_receiver)  = channel(10000);
        let (timeout_tx, timeout_rx) = channel(10000);
        let (timeout_result_tx, tinmeout_result_rx) = channel(10000);

        // Handle Halt till receives the leader.
        let tx_advance_cloned = tx_advance.clone();
        tokio::spawn(async move {
            Synchronizer::run_sync_halt(rx_halt, tx_advance_cloned).await;
        });

        // Timeout synchronization.
        tokio::spawn(async move {
            Synchronizer::run_sync_timeout(parameters.timeout_delay, timeout_rx, timeout_result_tx).await;
        });

        // ABA synchronization.
        tokio::spawn(async move {
            Synchronizer::run_sync_aba(
                aba_channel,
                aba_feedback_channel,
                aba_sync_receiver,
                aba_sync_feedback_sender,
                tx_advance,
            ).await;
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
            timeout_channel: timeout_tx,
            timeout_result_channel: tinmeout_result_rx,
            aba_sync_sender,
            aba_sync_feedback_receiver,
            commit_channel,
            halt_channel: tx_halt,
            advance_channel: rx_advance,
            votes_aggregators: HashMap::new(),
            election_states: HashMap::new(),
            ba_states: HashMap::new(),
            ba_inputs: HashMap::new(),
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

        if !block.payload.is_empty() {
            #[cfg(feature = "benchmark")]
            for x in &block.payload {
                info!("Created B{}({}) by id{{{}}}", block.epoch, base64::encode(x), self.committee.id(self.name));
            }
        }

        debug!("Created {:?}", block);

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
        transmit(message, &self.name, to, &self.network_filter, &self.committee).await
    }

    fn get_optimistic_leader(&self, epoch: EpochNumber) -> PublicKey {
        self.committee
            .get_public_key(epoch as usize % self.committee.size())
            .unwrap()
    } 

    // Starts the SPB phase.
    async fn spb(&mut self, block: &Block) -> ConsensusResult<()> {
        debug!("Processing block {:?}", block);

        // Check value.
        ensure!(
            self.check_value(&block),
            ConsensusError::InvalidVoteProof(block.proof.clone())
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
            .or_insert_with(|| Aggregator::<ConsensusMessage>::new())
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

        // Let's see if we have the block's data. If we don't, the mempool
        // will get it and then make us resume processing this block.
        if !self.mempool_driver.verify(block.clone()).await? {
            debug!("Processing of {} suspended: missing payload", block.digest());
            return Ok(())
        }
        
        // Update block.
        self.update_block(block.clone());

        let phase = match &block.proof {
            Proof::Pi(_) => {
                // Store block received at the first time.
                self.store(&block).await;
                PBPhase::Phase1
            },
            Proof::Sigma(_, _) => PBPhase::Phase2,
        };

        // Send echo msg.
        self.echo(block.digest(), 
            &block.author, 
            phase, 
            block.epoch,
            block.view,
            self.signature_service.clone(),
        ).await
    }

    async fn handle_amplify(&mut self, amplify: &Amplify) -> ConsensusResult<()> {
        amplify.verify(
            &self.committee, 
            self.get_optimistic_leader(amplify.epoch), 
            &self.pk_set,
            self.halt_mark, 
            &self.epochs_halted
        )?;

        let aggregator = self.votes_aggregators
            .entry((amplify.epoch, amplify.digest()))
            .or_insert_with(|| Aggregator::<ConsensusMessage>::new());
        
        aggregator.append(
            amplify.author, 
            ConsensusMessage::Amplify(amplify.clone()),
            self.committee.stake(&amplify.author)
        )?;

        let amplifies = aggregator.take(self.committee.quorum_threshold());
        match amplifies {
            None => (),
            Some(amplifies) => {
                let amplifies: Vec<_> = amplifies.into_iter()
                    .filter_map(|s| {
                        match s {
                            ConsensusMessage::Amplify(amplify) => Some(amplify),
                            _ => None,
                        }
                    })
                    .collect();
                let optimistic_sigma1 = amplifies.into_iter().find_map(|a| a.optimistic_sigma1.clone());
                
                // Vote for ABA.
                let ba_state = Arc::new(Mutex::new(
                    BAState {
                        output: None, 
                        optimistic_sigma1, 
                        wakers: Vec::new(), 
                        epoch: amplify.epoch 
                    }
                ));
                self.ba_states.insert(amplify.epoch, ba_state.clone());
                self.invoke_ba(amplify.epoch, ba_state).await;
            }
        }

        Ok(())
    }

    async fn echo(&mut self, 
        block_digest: Digest,
        block_author: &PublicKey, 
        phase: PBPhase, 
        epoch: EpochNumber,
        view: ViewNumber,
        signature_service: SignatureService,
    ) -> ConsensusResult<()> {
        let echo = Echo::new(block_digest, 
            block_author.clone(), 
            phase,
            epoch,
            view, 
            self.name, 
            signature_service
        ).await;
        let message = ConsensusMessage::Echo(echo.clone());
        self.transmit(message, Some(block_author)).await
    }

    async fn handle_echo(&mut self, echo: &Echo) -> ConsensusResult<()> {
        echo.verify(
            &self.committee, 
            &self.pk_set, 
            self.name,
            self.halt_mark, 
            &self.epochs_halted)?;

        self.votes_aggregators
            .entry((echo.epoch, echo.digest()))
            .or_insert_with(|| Aggregator::<ConsensusMessage>::new())
            .append(echo.author, ConsensusMessage::Echo(echo.clone()), self.committee.stake(&echo.author))?;

        let shares = self.votes_aggregators
            .get_mut(&(echo.epoch, echo.digest()))
            .unwrap()
            .take(self.committee.quorum_threshold());

        match shares {
            None => Ok(()),

            // Combine shares into a complete signature.
            Some(msgs) => {
                let shares: BTreeMap<_, _> = msgs.into_iter()
                    .filter_map(|s| {
                        match s {
                            ConsensusMessage::Echo(echo) => {
                                let id = self.committee.id(echo.author);
                                Some((id, &echo.signature_share))
                            },
                            _ => None,
                        }}
                    )
                    .collect();

                let threshold_signature = self.pk_set.combine_signatures(shares).expect("not enough qualified shares");
                
                let mut block = self.get_block(self.name, echo.epoch, echo.view).unwrap().clone();
                match echo.phase {
                    PBPhase::Phase1 => {
                        // Update proof with sigma1.
                        block.proof = Proof::Sigma(Some(threshold_signature), None);
                        self.pb(&block).await
                    },
                    // Update proof with sigma2.
                    PBPhase::Phase2 => {
                        if let Proof::Sigma(sigma1, _) = block.proof {
                            block.proof = Proof::Sigma(sigma1, Some(threshold_signature));     

                            if block.view == 1 && self.name == self.get_optimistic_leader(block.epoch) {
                                self.handle_halt(Halt { block, is_optimistic: true }).await
                            } else {
                                self.finish(&block).await
                            }
                        } else {
                            return Err(ConsensusError::InvalidThresholdSignature(block.author));
                        }
                    }
                }
            },
        }

    }

    async fn handle_timout(&mut self, epoch: EpochNumber) -> ConsensusResult<()> {
        let optimistic_sigma1 = self.get_block(self.get_optimistic_leader(epoch), epoch, 1).cloned();
        let amplify = Amplify { author: self.name, epoch, optimistic_sigma1 };
        let _ = self.handle_amplify(&amplify).await;
        self.transmit(ConsensusMessage::Amplify(amplify), None).await
    }

    async fn finish(&mut self, block: &Block) -> ConsensusResult<()> {
        // Update proof of the block of the node's own.
        self.update_block(block.clone());
        
        // Handle finish.
        let finish = Finish(block.clone());
        self.handle_finish(&finish).await?;
        
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
            .or_insert_with(|| Aggregator::<ConsensusMessage>::new())
            .append(finish.0.author, ConsensusMessage::Finish(finish.clone()), self.committee.stake(&finish.0.author))?;

        // Since the optimistic leader won't broadcast its Finish, minus quorum threshold by 1. 
        let finishes = self.votes_aggregators
            .get_mut(&(finish.0.epoch, finish.digest()))
            .unwrap()
            .take(self.committee.quorum_threshold());

        match finishes {
            None => Ok(()),

            Some(_) => {
                let randomness_share = RandomnessShare::new(
                    finish.0.epoch,
                    finish.0.view, 
                    self.name, 
                    self.signature_service.clone()
                ).await;
                self.handle_randommess_share(&randomness_share).await?;
                self.transmit(ConsensusMessage::RandomnessShare(randomness_share.clone()), None).await
            },
        }
    }

    async fn handle_randommess_share(&mut self, randomness_share: &RandomnessShare) -> ConsensusResult<()> {
        randomness_share.verify(&self.committee, &self.pk_set, self.halt_mark, &self.epochs_halted)?;

        self.votes_aggregators
            .entry((randomness_share.epoch, randomness_share.digest()))
            .or_insert_with(|| Aggregator::<ConsensusMessage>::new())
            .append(randomness_share.author, 
                ConsensusMessage::RandomnessShare(randomness_share.clone()), 
                self.committee.stake(&randomness_share.author))?;
        
        // n-f randomness shares to reveal fallback leader. 
        let shares = self.votes_aggregators
            .get(&(randomness_share.epoch, randomness_share.digest()))
            .unwrap()
            .take(self.committee.quorum_threshold());

        match shares {
            // Votes not enough.
            None => Ok(()),

            Some(msgs) => {
                let shares: Vec<_> = msgs.into_iter()
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
                    author: self.name,
                    epoch: randomness_share.epoch,
                    view: randomness_share.view, 
                    fallback_leader: leader, 
                    threshold_sig: threshold_signature,
                };

                // Handle and forward coin.
                self.handle_random_coin(&random_coin).await?;

                Ok(())
            },
        }

    }

    async fn invoke_ba(&self, epoch: EpochNumber, ba_state: Arc<Mutex<BAState>>) {
        // Send vote to ABA.
        self.aba_sync_sender
            .send((epoch, ba_state))
            .await.expect(&format!("Failed to invoke aba at epoch {}", epoch));
    }

    async fn handle_random_coin(&mut self, random_coin: &RandomCoin) -> ConsensusResult<()> {
        random_coin.verify(&self.committee, &self.pk_set, self.halt_mark, &self.epochs_halted)?;

        // This wakes up the waker of ElectionFuture in task for handling Halt.
        let mut is_handled_before = false;
        {
            let mut election_state = self.election_states
                .entry((random_coin.epoch, random_coin.view))
                .and_modify(|e| {
                    let mut state = e.lock().unwrap();
                    match state.coin {
                        Some(_) => is_handled_before = true,
                        _ => state.coin = Some(random_coin.clone()),
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
                    .find(|f| f.0.author == random_coin.fallback_leader)
            });

        if let Some(leader_finish) = leader_finish {
            self.handle_halt(Halt{block: leader_finish.0.clone(), is_optimistic: false}).await?;
        }

        // Enter two-vote phase.
        let body: Option<_> = match self.get_block(random_coin.fallback_leader, random_coin.epoch, random_coin.view) {
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
            random_coin.fallback_leader.0,
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
            leader: random_coin.fallback_leader,
            body,
        };
        self.handle_prevote(&prevote).await?;
        self.transmit(ConsensusMessage::PreVote(prevote), None).await
    }

    async fn handle_prevote(&mut self, prevote: &PreVote) -> ConsensusResult<()> {
        prevote.verify(&self.committee, &self.pk_set, self.halt_mark, &self.epochs_halted)?;

        self.votes_aggregators
            .entry((prevote.epoch, prevote.digest()))
            .or_insert_with(|| Aggregator::<ConsensusMessage>::new())
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
                                match &prevote.body {
                                    PreVoteEnum::No(share) => Some((self.committee.id(prevote.author), share)),
                                    _ => None,
                                }
                            })
                            .collect();
                        let threshold_signature = self.pk_set.combine_signatures(shares).expect("not enough qualified shares");

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
                self.handle_vote(&vote).await?;
                self.transmit(ConsensusMessage::Vote(vote), None).await
            },
        }
    }

    async fn handle_vote(&mut self, vote: &Vote) -> ConsensusResult<()> {
        vote.verify(&self.committee, &self.pk_set, self.halt_mark, &self.epochs_halted)?;

        self.votes_aggregators
            .entry((vote.epoch, vote.digest()))
            .or_insert_with(|| Aggregator::<ConsensusMessage>::new())
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
                            self.handle_halt(Halt{block: completed_block, is_optimistic: false}).await?;
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
                    self.spb(&block).await?;
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
                    self.spb(&block).await?;
                }

                Ok(())
            },
        }
    }

    async fn handle_request_help(&self, epoch: EpochNumber, requester: PublicKey) -> ConsensusResult<()> {
        if let Some(block) = self.get_block(self.get_optimistic_leader(epoch), epoch, 1) {
            if let Proof::Sigma(_, _) = block.proof {
                self.transmit(ConsensusMessage::Help(block.clone()), Some(&requester)).await?;
            }
        }
        Ok(())
    }

    async fn handle_help(&mut self, optimistic_sigma1: Block) -> ConsensusResult<()> {
        // Verify optimistic sigma1 from others to help commit from optimistic path.
        optimistic_sigma1.verify(&self.committee, self.halt_mark, &self.epochs_halted)?;
        ensure!(
            optimistic_sigma1.check_sigma1(&self.pk_set.public_key()),
            ConsensusError::InvalidSignatureShare(optimistic_sigma1.author)
        );

        // Modify ba_state to wake up BAFuture in aba sync task.
        let mut ba_state = self.ba_states.get_mut(&optimistic_sigma1.epoch)
            .unwrap()
            .lock()
            .unwrap();
        if ba_state.optimistic_sigma1.is_none() {
            ba_state.optimistic_sigma1 = Some(optimistic_sigma1);
            while let Some(waker) = ba_state.wakers.pop() {
                waker.wake();
            }
        }

        Ok(())
    }

    async fn handle_halt(&mut self, halt: Halt) -> ConsensusResult<()> {
        halt.verify(&self.committee, &self.pk_set, self.halt_mark, &self.epochs_halted)?;

        if halt.is_optimistic {
            // If receive optimistic halt from others, commit directly.
            self.advance(halt).await?;
        } else {
            let election_state = self.election_states
            .entry((halt.block.epoch, halt.block.view))
            .or_insert(Arc::new(Mutex::new(
                ElectionState { coin: None, wakers: Vec::new() }
            )))
            .clone();

            self.halt_channel.send((election_state, halt.block)).await
                .expect("Failed to send Halt through halt channel.");
        }
        Ok(())
    }

    async fn advance(&mut self, halt: Halt) -> ConsensusResult<()> {
        // Output block with payloads.
        if let Err(e) = self.commit_channel.send(halt.block.clone()).await {
            panic!("Failed to send message through commit channel: {}", e);
        } else {
            debug!("Commit block {} of member {} in epoch {}, view {}", 
            halt.block.digest(),
            halt.block.author,
            halt.block.epoch,
            halt.block.view,
            );
        }

        #[cfg(feature = "benchmark")]
        for x in &halt.block.payload {
            info!("Committed B{}({}) proposed by id{{{}}}", &halt.block.epoch, base64::encode(x), self.committee.id(halt.block.author));
        }

        // Clean up mempool.
        self.cleanup_epoch(&halt.block).await?;

        // Start new epoch.
        self.start_new_epoch(halt.block.epoch+1).await?;

        // Forward Halt to others.
        let epoch = halt.block.epoch.clone();
        self.transmit(ConsensusMessage::Halt(halt), None).await
            .expect(&format!("Failed to forward Halt of epoch {}", epoch));

        Ok(())

    }

    async fn start_new_epoch(&mut self, epoch: EpochNumber) -> ConsensusResult<()> {
        debug!("Start new epoch {} with optimistic leader {}", epoch, self.get_optimistic_leader(epoch));

        // Init timeout task to input 0 to ABA at bad cases.
        let ba_input = Arc::new(Mutex::new(
            TimeoutState { epoch, prepared: false, wakers: Vec::new() }
        ));
        self.ba_inputs.insert(epoch, ba_input.clone());
        self.timeout_channel.send(ba_input).await.expect("Failed to send ABA prepare message through channel");

        if self.name != self.get_optimistic_leader(epoch) {
            return Ok(());
        }

        // Generate new block.
        let new_block = self.generate_block(epoch, 1, Proof::Pi(Vec::new())).await
            .expect(&format!("Failed to generate block of epoch {}", epoch));
        self.spb(&new_block).await
    }

    async fn cleanup_epoch(&mut self, block: &Block) -> ConsensusResult<()> {
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
        self.start_new_epoch(1).await.expect("Failed to start the initial epoch of protocol.");

        loop {
            let result = tokio::select! {
                Some(msg) = self.core_channel.recv() => {
                    match msg {
                        ConsensusMessage::Val(block) => self.handle_val(block).await,
                        ConsensusMessage::Echo(echo) => self.handle_echo(&echo).await,
                        ConsensusMessage::TimeOut(epoch) => self.handle_timout(epoch).await,
                        ConsensusMessage::Amplify(amplify) => self.handle_amplify(&amplify).await,
                        ConsensusMessage::Finish(finish) => self.handle_finish(&finish).await,
                        ConsensusMessage::Halt(halt) => self.handle_halt(halt).await,
                        ConsensusMessage::RandomnessShare(randomness_share) => self.handle_randommess_share(&randomness_share).await,
                        ConsensusMessage::RandomCoin(random_coin) => self.handle_random_coin(&random_coin).await,
                        ConsensusMessage::PreVote(prevote) => self.handle_prevote(&prevote).await,
                        ConsensusMessage::Vote(vote) => self.handle_vote(&vote).await,
                        ConsensusMessage::RequestHelp(epoch, requester) => self.handle_request_help(epoch, requester).await,
                        ConsensusMessage::Help(optimistic_sigma1) => self.handle_help(optimistic_sigma1).await,
                    }
                },
                Some(halt) = self.advance_channel.recv() => {                    
                    self.advance(halt).await
                },
                Some(epoch) = self.timeout_result_channel.recv() => {
                    self.transmit(ConsensusMessage::TimeOut(epoch), Some(&self.name)).await
                },
                Some((epoch, is_optimistic_path_success)) = self.aba_sync_feedback_receiver.recv() => {
                    if is_optimistic_path_success {
                        // Request help for commiting from optimistic path.
                        self.transmit(ConsensusMessage::RequestHelp(epoch, self.name), None).await
                    } else {
                        // Generate new block, enter the second view.
                        let new_block = self.generate_block(epoch, 2, Proof::Pi(Vec::new())).await
                            .expect(&format!("Failed to generate block of epoch {}", epoch));
                        self.spb(&new_block).await
                    }
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