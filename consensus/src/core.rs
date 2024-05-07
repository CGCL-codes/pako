use crate::aggregator::Aggregator;
use crate::config::{Committee, EpochNumber, Parameters, ViewNumber};
use crate::error::{ConsensusError, ConsensusResult};
use crate::filter::ConsensusFilterInput;
use crate::mempool::MempoolDriver;
use crate::messages::*;
use crate::synchronizer::{transmit, BAState, ElectionState, Synchronizer};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use log::{debug, error, info, warn};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use store::Store;
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::{channel, Receiver, Sender};

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
    aba_sync_sender: Sender<(
        EpochNumber,
        ViewNumber,
        Arc<Mutex<BAState>>,
        Arc<Mutex<ElectionState>>,
    )>, // invoke aba, wait for done
    aba_sync_feedback_receiver: Receiver<(EpochNumber, ViewNumber, bool)>,
    advance_channel: Receiver<Block>,                          // propose block for next epoch
    commit_channel: Sender<Block>,

    votes_aggregators: HashMap<(EpochNumber, Digest), Aggregator<ConsensusMessage>>, // n-f votes collector
    election_states: HashMap<(EpochNumber, ViewNumber), Arc<Mutex<ElectionState>>>, // stores states of leader election
    ba_states: HashMap<(EpochNumber, ViewNumber), Arc<Mutex<BAState>>>, // store states of ABA, indicating whether ABA result is arrived
    blocks_received: HashMap<(PublicKey, EpochNumber), Block>, // blocks received from others and the node itself, will be updated as consensus proceeds
    commit_vectors_received: HashMap<(PublicKey, EpochNumber), CommitVector>, // commit-vectors received within each epoch

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
        aba_channel: Sender<(EpochNumber, ViewNumber, bool)>,
        aba_feedback_channel: Receiver<(EpochNumber, ViewNumber, bool)>,
        network_filter: Sender<ConsensusFilterInput>,
        commit_channel: Sender<Block>,
    ) -> Self {
        let (tx_advance, rx_advance) = channel(10000);
        let (aba_sync_sender, aba_sync_receiver) = channel(10000);
        let (aba_sync_feedback_sender, aba_sync_feedback_receiver) = channel(10000);

        // ABA synchronization.
        tokio::spawn(async move {
            Synchronizer::run_sync_aba(
                aba_channel,
                aba_feedback_channel,
                aba_sync_receiver,
                aba_sync_feedback_sender,
                tx_advance,
            )
            .await;
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
            aba_sync_sender,
            aba_sync_feedback_receiver,
            commit_channel,
            advance_channel: rx_advance,
            votes_aggregators: HashMap::new(),
            election_states: HashMap::new(),
            ba_states: HashMap::new(),
            blocks_received: HashMap::new(),
            commit_vectors_received: HashMap::new(),
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
        let digest = digest!(block.epoch.to_le_bytes(), block.author.0);
        let key = digest.to_vec();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store.write(key, value).await;
    }

    fn update_val(&mut self, val: Val) {
        match val {
            Val::Block(block) => {
                self.blocks_received
                    .insert((block.author, block.epoch), block);
            }
            Val::CommitVector(cv) => {
                self.commit_vectors_received
                    .insert((cv.author, cv.epoch), cv);
            }
        }
    }

    fn get_block(&self, author: PublicKey, epoch: EpochNumber) -> Option<&Block> {
        self.blocks_received.get(&(author, epoch))
    }

    fn get_cv(&self, author: PublicKey, epoch: EpochNumber) -> Option<&CommitVector> {
        self.commit_vectors_received.get(&(author, epoch))
    }

    // Generate a new block.
    async fn generate_block(&mut self, epoch: EpochNumber, proof: Sigma) -> ConsensusResult<Block> {
        // Get payloads.
        let payload = self
            .mempool_driver
            .get(self.parameters.max_payload_size)
            .await;

        let block = Block::new(
            payload,
            self.name,
            epoch,
            proof,
            self.signature_service.clone(),
        )
        .await;

        if !block.payload.is_empty() {
            info!("Created {}", block);

            #[cfg(feature = "benchmark")]
            for x in &block.payload {
                info!(
                    "Created B{}({}) by id{{{}}}",
                    block.epoch,
                    base64::encode(x),
                    self.committee.id(self.name)
                );
            }
        }

        debug!("Created {:?}", block);

        Ok(block)
    }

    // Value validation.
    fn value_validation(&self, block: &Block) -> bool {
        block.check_sigma(&self.pk_set.public_key())
    }

    async fn transmit(
        &self,
        message: ConsensusMessage,
        to: Option<&PublicKey>,
    ) -> ConsensusResult<()> {
        transmit(
            message,
            &self.name,
            to,
            &self.network_filter,
            &self.committee,
        )
        .await
    }

    // Starts the SPB phase.
    async fn spb(&mut self, block: Block) -> ConsensusResult<()> {
        debug!("Processing block {:?}", block);

        // Store the block.
        self.store(&block).await;

        // The first PB phase.
        self.pb(Val::Block(block)).await?;

        Ok(())
    }

    async fn pb(&mut self, val: Val) -> ConsensusResult<()> {
        self.update_val(val.clone());

        let (digest, author, phase, epoch) = match &val {
            Val::Block(block) => (block.digest(), block.author, PBPhase::Phase1, block.epoch),
            Val::CommitVector(cv) => (cv.digest(), cv.author, PBPhase::Phase2, cv.epoch),
        };

        // Collect the node's own echo.
        let echo = Echo::new(
            digest,
            author,
            phase,
            epoch,
            self.name,
            self.signature_service.clone(),
        )
        .await;

        self.votes_aggregators
            .entry((echo.epoch, echo.digest()))
            .or_insert_with(|| Aggregator::<ConsensusMessage>::new())
            .append(
                echo.author,
                ConsensusMessage::Echo(echo.clone()),
                self.committee.stake(&echo.author),
            )?;

        // Broadcast VAL to all nodes.
        let message = ConsensusMessage::Val(val);
        self.transmit(message, None).await?;

        Ok(())
    }

    async fn handle_val(&mut self, val: Val) -> ConsensusResult<()> {
        let (digest, author, phase, epoch) = match val.clone() {
            Val::Block(block) => {
                // Ensure val is correctly formed.
                block.verify(&self.committee, self.halt_mark, &self.epochs_halted)?;

                // Validate block.
                ensure!(
                    self.value_validation(&block),
                    ConsensusError::InvalidVoteProof(block.proof.clone())
                );

                // Let's see if we have the block's data. If we don't, the mempool
                // will get it and then make us resume processing this block.
                if !self.mempool_driver.verify(block.clone()).await? {
                    debug!(
                        "Processing of {} suspended: missing payload",
                        block.digest()
                    );
                    return Ok(());
                }

                self.store(&block).await;

                (block.digest(), block.author, PBPhase::Phase1, block.epoch)
            }
            Val::CommitVector(cv) => {
                cv.verify(&self.committee, self.halt_mark, &self.epochs_halted)?;

                (cv.digest(), cv.author, PBPhase::Phase2, cv.epoch)
            }
        };

        // Send/Broadcast echo msg.
        self.echo(
            digest,
            &author,
            phase,
            epoch,
            self.signature_service.clone(),
        )
        .await?;

        // Update val.
        self.update_val(val);

        Ok(())
    }

    async fn echo(
        &mut self,
        block_digest: Digest,
        block_author: &PublicKey,
        phase: PBPhase,
        epoch: EpochNumber,
        signature_service: SignatureService,
    ) -> ConsensusResult<()> {
        // Broacast Echo if it's against block of optimistic leader,
        // else send Echo back to the block author.
        let echo = Echo::new(
            block_digest,
            block_author.clone(),
            phase,
            epoch,
            self.name,
            signature_service,
        )
        .await;
        let message = ConsensusMessage::Echo(echo.clone());
        self.transmit(message, None).await?;
        Ok(())
    }

    async fn handle_echo(&mut self, echo: &Echo) -> ConsensusResult<()> {
        echo.verify(
            &self.committee,
            &self.pk_set,
            self.name,
            self.halt_mark,
            &self.epochs_halted,
        )?;

        self.votes_aggregators
            .entry((echo.epoch, echo.digest()))
            .or_insert_with(|| Aggregator::<ConsensusMessage>::new())
            .append(
                echo.author,
                ConsensusMessage::Echo(echo.clone()),
                self.committee.stake(&echo.author),
            )?;

        let shares = self
            .votes_aggregators
            .get_mut(&(echo.epoch, echo.digest()))
            .unwrap()
            .take(self.committee.quorum_threshold());

        match shares {
            None => Ok(()),

            // Combine shares into a complete signature.
            Some(msgs) => {
                let shares: BTreeMap<_, _> = msgs
                    .into_iter()
                    .filter_map(|s| match s {
                        ConsensusMessage::Echo(echo) => {
                            let id = self.committee.id(echo.author);
                            Some((id, &echo.signature_share))
                        }
                        _ => None,
                    })
                    .collect();

                let threshold_signature = self
                    .pk_set
                    .combine_signatures(shares)
                    .expect("not enough qualified shares");

                match echo.phase {
                    // Update block with proof.
                    PBPhase::Phase1 => {
                        let mut block = self.get_block(self.name, echo.epoch).unwrap().clone();
                        block.proof = Some(threshold_signature);
                        self.finish(Val::Block(block)).await
                    }
                    // Update commit vector wirh proof.
                    PBPhase::Phase2 => {
                        let mut cv = self.get_cv(self.name, echo.epoch).unwrap().clone();
                        cv.proof = Some(threshold_signature);
                        self.finish(Val::CommitVector(cv)).await
                    }
                }
            }
        }
    }

    async fn finish(&mut self, val: Val) -> ConsensusResult<()> {
        // Update proof of the block of the node's own.
        self.update_val(val.clone());

        // Handle finish.
        let finish = Finish(val);
        self.handle_finish(&finish).await?;

        // Broadcast Finish to all nodes.
        let message = ConsensusMessage::Finish(finish);
        self.transmit(message, None).await
    }

    async fn handle_finish(&mut self, finish: &Finish) -> ConsensusResult<()> {
        let (epoch, digest, author, phase) = match &finish.0 {
            Val::Block(block) => {
                block.verify(&self.committee, self.halt_mark, &self.epochs_halted)?;

                // Verify threshold signature.
                ensure!(
                    block.check_sigma(&self.pk_set.public_key()),
                    ConsensusError::InvalidVoteProof(block.proof.clone())
                );

                (block.epoch, block.digest(), block.author, PBPhase::Phase1)
            }
            Val::CommitVector(cv) => {
                cv.verify(&self.committee, self.halt_mark, &self.epochs_halted)?;
                ensure!(
                    cv.check_sigma(&self.pk_set.public_key()),
                    ConsensusError::InvalidVoteProof(cv.proof.clone())
                );
                (cv.epoch, cv.digest(), cv.author, PBPhase::Phase2)
            }
        };

        // Update val with proof received from others.
        self.update_val(finish.0.clone());

        // Aggregate and see if there exists 2f+1 vals.
        self.votes_aggregators
            .entry((epoch, digest))
            .or_insert_with(|| Aggregator::<ConsensusMessage>::new())
            .append(
                author,
                ConsensusMessage::Finish(finish.clone()),
                self.committee.stake(&author),
            )?;

        let finishes = self
            .votes_aggregators
            .get_mut(&(epoch, finish.digest()))
            .unwrap()
            .take(self.committee.quorum_threshold());

        match finishes {
            None => Ok(()),
            Some(quorum) => match phase {
                PBPhase::Phase1 => {
                    let randomness_share =
                        RandomnessShare::new(epoch, 1, self.name, self.signature_service.clone())
                            .await;
                    self.handle_randommess_share(&randomness_share).await?;
                    self.transmit(
                        ConsensusMessage::RandomnessShare(randomness_share.clone()),
                        None,
                    )
                    .await
                }
                PBPhase::Phase2 => {
                    let received = quorum
                        .into_iter()
                        .filter_map(|m| {
                            if let ConsensusMessage::Val(Val::CommitVector(cv)) = m {
                                Some(cv.author)
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>();
                    let cv = CommitVector::new(
                        epoch,
                        self.name,
                        received,
                        None,
                        self.signature_service.clone(),
                    )
                    .await;
                    self.handle_val(Val::CommitVector(cv.clone())).await?;
                    self.transmit(ConsensusMessage::Val(Val::CommitVector(cv)), None)
                        .await
                }
            },
        }
    }

    async fn handle_randommess_share(
        &mut self,
        randomness_share: &RandomnessShare,
    ) -> ConsensusResult<()> {
        randomness_share.verify(
            &self.committee,
            &self.pk_set,
            self.halt_mark,
            &self.epochs_halted,
        )?;

        self.votes_aggregators
            .entry((randomness_share.epoch, randomness_share.digest()))
            .or_insert_with(|| Aggregator::<ConsensusMessage>::new())
            .append(
                randomness_share.author,
                ConsensusMessage::RandomnessShare(randomness_share.clone()),
                self.committee.stake(&randomness_share.author),
            )?;

        // n-f randomness shares to reveal fallback leader.
        let shares = self
            .votes_aggregators
            .get(&(randomness_share.epoch, randomness_share.digest()))
            .unwrap()
            .take(self.committee.quorum_threshold());

        match shares {
            // Votes not enough.
            None => Ok(()),

            Some(msgs) => {
                let shares: Vec<_> = msgs
                    .into_iter()
                    .filter_map(|s| match s {
                        ConsensusMessage::RandomnessShare(share) => Some(share),
                        _ => None,
                    })
                    .collect();

                // Combine shares into a complete signature.
                let share_map = shares
                    .iter()
                    .map(|s| (self.committee.id(s.author), &s.signature_share))
                    .collect::<BTreeMap<_, _>>();
                let threshold_signature = self
                    .pk_set
                    .combine_signatures(share_map)
                    .expect("Unqualified shares!");

                // Use coin to elect leader.
                let id = usize::from_be_bytes(
                    (&threshold_signature.to_bytes()[0..8]).try_into().unwrap(),
                ) % self.committee.size();
                let mut keys: Vec<_> = self.committee.authorities.keys().cloned().collect();
                keys.sort();
                let leader = keys[id];
                debug!(
                    "Random coin of epoch {} view {} elects leader id {}",
                    randomness_share.epoch, randomness_share.view, id
                );

                let random_coin = RandomCoin {
                    author: self.name,
                    epoch: randomness_share.epoch,
                    view: randomness_share.view,
                    leader,
                    threshold_sig: threshold_signature,
                };

                // Handle and forward coin.
                self.handle_random_coin(&random_coin).await?;

                Ok(())
            }
        }
    }

    async fn invoke_ba(
        &mut self,
        epoch: EpochNumber,
        view: ViewNumber,
        ba_state: Arc<Mutex<BAState>>,
    ) {
        let election_state = self
            .election_states
            .entry((epoch, view))
            .or_insert(Arc::new(Mutex::new(ElectionState {
                coin: None,
                wakers: Vec::new(),
            })))
            .clone();

        // Send vote to ABA.
        self.aba_sync_sender
            .send((epoch, view, ba_state, election_state))
            .await
            .expect(&format!("Failed to invoke aba at epoch {}", epoch));
    }

    async fn handle_random_coin(&mut self, random_coin: &RandomCoin) -> ConsensusResult<()> {
        random_coin.verify(
            &self.committee,
            &self.pk_set,
            self.halt_mark,
            &self.epochs_halted,
        )?;

        // This wakes up the waker of ElectionFuture in task for handling Halt.
        let mut is_handled_before = false;
        {
            let mut election_state = self
                .election_states
                .entry((random_coin.epoch, random_coin.view))
                .and_modify(|e| {
                    let mut state = e.lock().unwrap();
                    match state.coin {
                        Some(_) => is_handled_before = true,
                        _ => state.coin = Some(random_coin.clone()),
                    }
                })
                .or_insert(Arc::new(Mutex::new(ElectionState {
                    coin: Some(random_coin.clone()),
                    wakers: Vec::new(),
                })))
                .lock()
                .unwrap();
            while let Some(waker) = election_state.wakers.pop() {
                waker.wake();
            }
        }

        // Skip coins already handled.
        if is_handled_before {
            return Ok(());
        }

        // Multicast the random coin.
        let message = ConsensusMessage::RandomCoin(random_coin.clone());
        self.transmit(message, None).await?;

        // Multicast done that indicates whether the node has received the leader's block of current epoch.
        self.done(random_coin).await
    }

    async fn done(&mut self, random_coin: &RandomCoin) -> ConsensusResult<()> {
        // Enter Done phase.
        let proof = self
            .get_block(random_coin.leader, random_coin.epoch)
            .map(|block| block.proof.clone())
            .flatten();

        let done = Done {
            author: self.name,
            coin: random_coin.clone(),
            proof,
        };
        self.handle_done(&done).await?;
        self.transmit(ConsensusMessage::Done(done), None).await
    }

    async fn handle_done(&mut self, done: &Done) -> ConsensusResult<()> {
        done.verify(
            &self.committee,
            &self.pk_set,
            self.halt_mark,
            &self.epochs_halted,
        )?;

        self.votes_aggregators
            .entry((done.coin.epoch, done.digest()))
            .or_insert_with(|| Aggregator::<ConsensusMessage>::new())
            .append(
                done.author,
                ConsensusMessage::Done(done.clone()),
                self.committee.stake(&done.author),
            )?;

        let dones = self
            .votes_aggregators
            .get_mut(&(done.coin.epoch, done.digest()))
            .unwrap()
            .take(self.committee.quorum_threshold());

        match dones {
            None => Ok(()),

            Some(_) => {
                // Invoke ABA.
                let leader_block = self.get_block(done.coin.leader, done.coin.epoch).and_then(
                    |block| match &block.proof {
                        Some(_) => Some(block.clone()),
                        _ => None,
                    },
                );
                debug!(
                    "Invoke binary agreement of epoch {}, vote: {}",
                    done.coin.epoch,
                    leader_block.is_some()
                );
                let ba_state = Arc::new(Mutex::new(BAState {
                    consistent: None,
                    coin: Some(done.coin.clone()),
                    leader_block,
                    wakers: Vec::new(),
                    epoch: done.coin.epoch,
                    view: done.coin.view,
                }));
                self.ba_states
                    .insert((done.coin.epoch, done.coin.view), ba_state.clone());
                self.invoke_ba(done.coin.epoch, done.coin.view, ba_state)
                    .await;

                Ok(())
            }
        }
    }

    async fn handle_halt(&mut self, halt: Halt) -> ConsensusResult<()> {
        halt.verify(
            &self.committee,
            &self.pk_set,
            self.halt_mark,
            &self.epochs_halted,
        )?;

        self.votes_aggregators
            .entry((halt.block.epoch, halt.digest()))
            .or_insert_with(|| Aggregator::<ConsensusMessage>::new())
            .append(
                halt.author,
                ConsensusMessage::Halt(halt.clone()),
                self.committee.stake(&halt.author),
            )?;
        
        // Collect f+1 halts to proceed.
        let dones = self
            .votes_aggregators
            .get_mut(&(halt.block.epoch, halt.digest()))
            .unwrap()
            .take(self.committee.random_coin_threshold());

        match dones {
            None => Ok(()),
            Some(_) => self.advance(halt.block).await
        }

    }

    async fn advance(&mut self, block: Block) -> ConsensusResult<()> {
        // Output block with payloads.
        if let Err(e) = self.commit_channel.send(block.clone()).await {
            panic!("Failed to send message through commit channel: {}", e);
        } else {
            info!(
                "Commit block {} of member {} in epoch {}",
                block.digest(),
                block.author,
                block.epoch,
            );
        }

        #[cfg(feature = "benchmark")]
        for x in &block.block.payload {
            info!(
                "Committed B{}({}) proposed by id{{{}}}",
                &halt.block.epoch,
                base64::encode(x),
                self.committee.id(halt.block.author)
            );
        }

        // Clean up mempool.
        self.cleanup_epoch(&block).await?;

        // Start new epoch.
        self.start_new_epoch(block.epoch + 1).await?;

        // Forward Halt to others.
        let epoch = block.epoch.clone();
        self.transmit(ConsensusMessage::Halt(Halt{block, author: self.name}), None)
            .await
            .expect(&format!("Failed to forward Halt of epoch {}", epoch));

        Ok(())
    }

    async fn start_new_epoch(&mut self, epoch: EpochNumber) -> ConsensusResult<()> {
        let new_block = self
            .generate_block(epoch, None)
            .await
            .expect(&format!("Failed to generate block of epoch {}", epoch));
        self.spb(new_block).await
    }

    async fn cleanup_epoch(&mut self, block: &Block) -> ConsensusResult<()> {
        // Mark epoch as halted.
        self.epochs_halted.insert(block.epoch);
        if self.epochs_halted.remove(&(self.halt_mark + 1)) {
            self.halt_mark += 1;
        }

        self.blocks_received.retain(|&(_, e), _| e != block.epoch);
        self.votes_aggregators.retain(|&(e, _), _| e != block.epoch);
        self.election_states.retain(|&(e, _), _| e != block.epoch);

        // Clean up payloads.
        self.mempool_driver.cleanup_async(&block).await;

        Ok(())
    }

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block.
        self.start_new_epoch(1)
            .await
            .expect("Failed to start the initial epoch of protocol.");

        loop {
            let result = tokio::select! {
                Some(msg) = self.core_channel.recv() => {
                    match msg {
                        ConsensusMessage::Val(val) => self.handle_val(val).await,
                        ConsensusMessage::Echo(echo) => self.handle_echo(&echo).await,
                        ConsensusMessage::Finish(finish) => self.handle_finish(&finish).await,
                        ConsensusMessage::Halt(halt) => self.handle_halt(halt).await,
                        ConsensusMessage::RandomnessShare(randomness_share) => self.handle_randommess_share(&randomness_share).await,
                        ConsensusMessage::RandomCoin(random_coin) => self.handle_random_coin(&random_coin).await,
                        ConsensusMessage::Done(prevote) => self.handle_done(&prevote).await,
                    }
                },
                Some(halt) = self.advance_channel.recv() => {
                    self.advance(halt).await
                },
                Some((epoch, view, success)) = self.aba_sync_feedback_receiver.recv() => {
                    if !success {
                        let randomness_share = RandomnessShare::new(epoch, view, self.name, self.signature_service.clone()).await;
                        let _ = self.transmit(ConsensusMessage::RandomnessShare(randomness_share), None).await;
                    }
                    Ok(())
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
