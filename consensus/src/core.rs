use std::cell::RefCell;
use std::collections::{HashMap, BTreeMap};
use std::rc::Rc;
use std::sync::Mutex;
use std::task::Waker;
use std::{default, thread};

use crate::{SeqNumber, ViewNumber};
use crate::aggregator::Aggregator;
use crate::config::{Committee, Parameters, EpochNumber};
use crate::election::{ElectionState, ElectionFuture};
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::{Block, ConsensusMessage, PBPhase, Proof, Echo, Done, Finish, RandomnessShare, RandomCoin, PreVote, PreVoteEnum};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use futures::lock;
use log::debug;
use rand::random;
use serde::{Serialize, Deserialize};
use threshold_crypto::{PublicKeySet, SecretKeyShare, PublicKeyShare, SignatureShare};
use tokio::sync::mpsc::{Receiver, Sender};
use store::Store;

pub struct Core {
    name: PublicKey,
    committee: Committee,
    parameters: Parameters,
    store: Store,
    signature_service: SignatureService,
    pk_set: PublicKeySet,
    pk_share: PublicKeyShare,
    sk_share: SecretKeyShare,
    mempool_driver: MempoolDriver,
    core_channel: Receiver<ConsensusMessage>,
    spb_channel: Receiver<ConsensusMessage>,
    network_filter: Sender<FilterInput>,
    commit_channel: Sender<Block>,
    epoch: SeqNumber, //    // current epoch
    view: ViewNumber,       // current view
    votes_aggregators: HashMap<Digest, Aggregator>, // n-f votes collector
    locks: HashMap<Digest, Block>,  // blocks received in current view with sigma1
    random_coin: HashMap<Digest, RandomCoin>,
    election_states: HashMap<Digest, Rc<RefCell<ElectionState>>>, // election states of each <epoch, view>
    abandon_channel: ,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn new(

    ) -> Self {

    }

    // TODO: Implement cached block from digest.
    fn get_block(&self, digest: &Digest) -> Block {
        if let Some(bytes) = self.store.read(digest.to_vec()).await? {
            let block: Block = bincode::deserialize(&bytes)?;
            block
        } else {
            
        }
    }

    // Get the leader of <epoch, view>.
    async fn get_leader(&mut self, epoch: EpochNumber, view: ViewNumber) -> ConsensusResult<PublicKey> {
        ensure!(
            epoch > 0 && view > 0,
            ConsensusError::InvalidEpochOrView(epoch, view)
        );

        let digest = digest!(epoch.to_le_bytes(), view.to_le_bytes(), "RANDOM_COIN");
        let election_state = self.election_states
            .entry(digest!(self.epoch.to_le_bytes(), self.view.to_le_bytes()))
            .or_insert(Rc::new(RefCell::new(ElectionState { done: false, wakers: Vec::new() })));
        let election_state = Rc::clone(election_state);
        let election_fut = ElectionFuture {
            election_state,
        };
        election_fut.await;
        Ok(self.random_coin.get(&digest).unwrap().leader)
    }

    // TODO: implement check_value()
    fn check_value(&self, block: &Block) -> bool {
        todo!()
    }

    // Value validation.
    fn value_validation(&self, block: &Block) -> bool {
        match block.proof {
            Proof::Pi(_) => self.check_value(block),

            // Block should carry sigma1 though not explicitly matched.
            Proof::Sigma(_, _) => block.check_sigma1(&self.pk_set.public_key()),
        }
    }

    async fn transmit(&self, message: ConsensusMessage, to: Option<&PublicKey>) -> ConsensusResult<()> {
        let addresses = if let Some(to) = to {
            debug!("Sending {:?} to {}", message, to);
            vec![self.committee.address(to)?]
        } else {
            debug!("Broadcasting {:?}", message);
            self.committee.broadcast_addresses(&self.name)
        };
        if let Err(e) = self.network_filter.send((message, addresses)).await {
            panic!("Failed to send message through network channel: {}", e);
        }
        Ok(())
    }

    async fn pb(&self, block: &Block) -> ConsensusResult<()> {
        // Broadcast VAL to all nodes.
        let message = ConsensusMessage::Val(block.clone());
        self.transmit(message, None).await?;

        Ok(())
    }

    async fn echo(&self, block_digest: Digest, block_author: &PublicKey, phase: PBPhase, signature_service: SignatureService) -> ConsensusResult<()> {
        let echo = Echo::new(block_digest, block_author.clone(), phase, self.name, signature_service).await;

        // Send ECHO to block author.
        let message = ConsensusMessage::Echo(echo);
        self.transmit(message, Some(block_author)).await?;

        Ok(())
    }

    async fn handle_echo(&mut self, echo: &Echo) -> ConsensusResult<()> {
        echo.verify(&self.committee, &self.pk_set)?;

        let shares = self.votes_aggregators
            .entry(echo.digest())
            .or_insert_with(|| Aggregator::new())
            .append(echo.author, ConsensusMessage::Echo(echo.clone()), &self.committee);

        match shares {
            Err(e) => Err(e),
            // Votes not enough.
            Ok(None) => Ok(()),
            // Combine shares into a compete signature.
            Ok(Some(msgs)) => {
                let shares: Vec<SignatureShare> = msgs.into_iter()
                    .filter_map(|s| {
                        match s {
                            ConsensusMessage::Echo(echo) => Some(echo.signature_share),
                            _ => None,
                        }}
                    )
                    .collect();

                let shares: BTreeMap<_, _> = (0..shares.len()).map(|i| (i, shares.get(i).unwrap())).collect();
                let threshold_signature = self.pk_set.combine_signatures(shares).expect("not enough qualified shares");

                let mut block = self.get_block(&echo.block_digest);
                match echo.phase {
                    PBPhase::Phase1 => {
                        // Start the second PB.
                        block.proof = Proof::Sigma(Some(threshold_signature), None);

                        self.pb(&block).await
                    },
                    PBPhase::Phase2 => {
                        // Finish SPB and broadcast FINISH.
                        let Proof::Sigma(sigma1, _) = block.proof;
                        block.proof = Proof::Sigma(sigma1, Some(threshold_signature));
                        self.finish(&block).await
                    }
                }
            },
        }

    }

    async fn finish(&self, block: &Block) -> ConsensusResult<()> {
        // Broadcast VAL to all nodes.
        let message = ConsensusMessage::Finish(
            Finish {
                block: block.clone(),
                author: self.name,
            }
        );
        self.transmit(message, None).await?;

        Ok(())
    }

    async fn handle_finish(&mut self, finish: &Finish) -> ConsensusResult<()> {
        // Verify threshold signature.
        ensure!(
            finish.block.check_sigma2(&self.pk_set.public_key()),
            ConsensusError::InvalidVoteProof(Some(finish.block.proof.clone()))
        );

        let finishes = self.votes_aggregators
            .entry(finish.digest())
            .or_insert_with(|| Aggregator::new())
            .append(finish.author, ConsensusMessage::Finish(finish.clone()), &self.committee);

        match finishes {
            Err(e) => Err(e),
            // Votes not enough.
            Ok(None) => Ok(()),
            // Broadcast Done if received n-f Finish.
            Ok(Some(_)) => {
                self.done(finish.block.epoch, finish.block.view).await
            },
        }
    }

    async fn handle_val(&mut self, block: &Block) -> ConsensusResult<()> {
        // Check the block is correctly formed.
        block.verify(&self.committee)?;

        // Validate block.
        ensure!(
            self.value_validation(block),
            ConsensusError::InvalidVoteProof(Some(block.proof.clone()))
        );

        let phase = match &block.proof {
            Proof::Pi(_) => PBPhase::Phase1,
            Proof::Sigma(_, _) => {
                // If block is at the second PB phase, output Lock.
                let digest = digest!(
                    block.epoch.to_le_bytes(),
                    block.view.to_le_bytes(),
                    block.author.0
                );
                self.locks.insert(digest, block.clone());

                PBPhase::Phase2
            },
        };

        // Send echo msg.
        self.echo(block.digest(), &block.author, phase, self.signature_service.clone()).await
    }

    async fn generate_block(&self, proof: Option<Proof>) -> ConsensusResult<()> {
        // TODO: generate a block in the beginning of a view
        todo!()
    }

    // Starts the SPB phase.
    async fn spb(&mut self, block: Block, proof: Option<Proof>) -> ConsensusResult<()> {
        debug!("Processing {:?}", block);

        // Verify block.
        block.verify(&self.committee)?;

        // Check value.
        ensure!(
            self.check_value(&block),
            ConsensusError::InvalidVoteProof(proof)
        );
        
        // Start the first PB.
        let message = ConsensusMessage::Val(block.clone());
        self.transmit(message, None).await?;
         
        Ok(())
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
            .append(self.name, ConsensusMessage::Done(done.clone()), &self.committee);

        match msgs {
            Err(e) => return Err(e),
            Ok(None) => (),
            Ok(Some(_)) => {
                // TODO: After collecting n-f Done, abandon the rest SPB instances.
                self.abandon();
            },
        }

        // f+1 Done to reveal coin in current round.
        if let Some(aggregator) = self.votes_aggregators.get(&done.digest()) {
            if aggregator.ready_for_random_coin(&self.committee) {
                let randomness_share = RandomnessShare::new(
                    self.epoch,
                    self.view, 
                    self.name, 
                    self.signature_service.clone()
                ).await;
                let message = ConsensusMessage::RandomnessShare(randomness_share.clone());
                self.transmit(message, None).await;
            }
        }

        Ok(())
    }

    async fn handle_randommess_share(&mut self, randomness_share: &RandomnessShare) -> ConsensusResult<()> {
        randomness_share.verify(&self.committee, &self.pk_set);

        let shares = self.votes_aggregators
            .entry(randomness_share.digest())
            .or_insert_with(|| Aggregator::new())
            .append(randomness_share.author, ConsensusMessage::RandomnessShare(randomness_share.clone()), &self.committee);

        match shares {
            Err(e) => Err(e),

            // Votes not enough.
            Ok(None) => Ok(()),

            Ok(Some(msgs)) => {
                let randomnes_shares: Vec<RandomnessShare> = msgs.into_iter()
                    .filter_map(|s| {
                        match s {
                            ConsensusMessage::RandomnessShare(randomness_share) => Some(randomness_share),
                            _ => None,
                        }
                    })
                    .collect();
                let signature_shares: Vec<SignatureShare> = randomnes_shares.iter()
                    .map(|s| s.signature_share.clone())
                    .collect();

                // Combine shares into a compete signature.
                let shares: BTreeMap<_, _> = (0..signature_shares.len()).map(|i| (i, signature_shares.get(i).unwrap())).collect();
                let threshold_signature = self.pk_set.combine_signatures(shares).expect("Unqualified shares!");

                // Use coin to elect leader. 
                let id = usize::from_be_bytes((&threshold_signature.to_bytes()[0..8]).try_into().unwrap()) % self.committee.size();
                let mut keys: Vec<_> = self.committee.authorities.keys().cloned().collect();
                keys.sort();
                let leader = keys[id];
                debug!("Random coin of epoch {} view {} elects leader id {}", randomness_share.epoch, randomness_share.view, id);

                let random_coin = RandomCoin {
                    epoch: self.epoch,
                    view: randomness_share.view, 
                    leader, 
                    shares: randomnes_shares,
                };
                self.handle_random_coin(random_coin.clone()).await
            },
        }

    }

    async fn handle_random_coin(&mut self, random_coin: RandomCoin) -> ConsensusResult<()> {
        // Ignore coins of previous epochs or views.
        if random_coin.epoch < self.epoch
        || random_coin.epoch == self.epoch && random_coin.view < self.view
        || self.random_coin.contains_key(&random_coin.digest()) {
            return Ok(())
        }

        random_coin.verify(&self.committee, &self.pk_set)?;
        
        self.random_coin.insert(random_coin.digest(), random_coin.clone());

        // Set ElectionState of <epoch, view> of done msg as `done`,
        // this wakes up the Waker of ElectionFuture of get_leader(),
        // then all calls of get_leader().await make progress.
        let digest = digest!(self.epoch.to_le_bytes(), self.view.to_le_bytes());
        let election_state = self.election_states
            .entry(digest)
            .or_insert(Rc::new(RefCell::new(ElectionState { done: false, wakers: Vec::new() })));
        election_state.borrow_mut().done = true;
        while let Some(waker) = election_state.borrow_mut().wakers.pop() {
            waker.wake();
        }

        // Multicast the random coin.
        let message = ConsensusMessage::RandomCoin(random_coin.clone());
        self.transmit(message, None).await?;

        // Having had received the current leader's Finish, halt and output.
        let finish_digest = digest!(
            self.epoch.to_le_bytes(), 
            self.view.to_le_bytes(),
            "FINISH"
        );
        let finishes = &self.votes_aggregators.get(&finish_digest).unwrap().votes;
        let leader_finish = finishes.iter()
            .filter_map(|f| {
                match f {
                    ConsensusMessage::Finish(finish) => Some(finish),
                    _ => None,
                }
            })
            .find(|f| f.author == random_coin.leader);
        if let Some(leader_finish) = leader_finish {
            let halt = ConsensusMessage::Halt(leader_finish.block.clone());
            self.transmit(halt, None).await?;

            // Terminate and advance epoch.
            self.output(&leader_finish.block);
            self.advance_epoch();

            return Ok(())
        }

        // Broadcast PreVote message if leader's Finish was not delivered.
        let digest = digest!(
            random_coin.epoch.to_le_bytes(),
            random_coin.view.to_le_bytes(),
            random_coin.leader.0,
            "PREVOTE"
        );  // This is a digest of PreVote msg constructed in advance, used to verify `No` prevotes.
        let body = match self.locks.get(&digest) {
            Some(block) => PreVoteEnum::Yes(block.clone()),
            None => {
                let signature_share = self.signature_service.request_tss_signature(digest).await.unwrap();
                PreVoteEnum::No(
                    random_coin.epoch,
                    random_coin.view,
                    random_coin.leader,
                    signature_share,
                )
            },
        };
        self.transmit(ConsensusMessage::PreVote(PreVote {author: self.name, body}), None).await
    }

    async fn handle_halt(&mut self, block: &Block) -> ConsensusResult<()> {
        if block.author == self.get_leader(block.epoch, block.view).await.unwrap() {
            block.verify(&self.committee)?;

            // Broadcast halt and output
            let halt = ConsensusMessage::Halt(block.clone());
            self.transmit(halt, None).await?;

            self.output(block);
            self.advance_epoch();      
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

            // Votes not enough.
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
                
                match locked_block {
                    // Broadcast `Yes` Vote if leader's block with sigma1 was received.
                    Some(block) => {
                        let signature_share = self.signature_service.request_tss_signature(block.digest()).await.unwrap();
                        
                    },
                    // Else broadcast `No` Vote.
                    None => {
                    },
                }

                Ok(())
            },
        }
    }

    async fn handle_vote(&mut self, vote: &Vote) -> ConsensusResult<()> {

    }

    async fn output(&self, block: &Block) -> ConsensusResult<()> {

    }

    fn advance_view(&mut self) -> ConsensusResult<()> {
        self.view += 1;

        Ok(())
    }

    fn advance_epoch(&mut self) -> ConsensusResult<()> {
        self.epoch += 1;
        self.view = 0;

        todo!()
    }

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block (if we are the sender).
        if self.name == self.leader_elector.get_leader(self.view) {
            self.spb(None)
            .await
            .expect("Failed to send the first block");
        }

        loop {
            let result = tokio::select! {
                Some(msg) = self.core_channel.recv() => {
                    match msg {
                        ConsensusMessage::Val(block) => self.handle_val(&block).await,
                        ConsensusMessage::Echo(echo) => self.handle_echo(&echo).await,
                        ConsensusMessage::Finish(finish) => self.handle_finish(&finish).await,
                        ConsensusMessage::Halt(halt) => self.advance_epoch(),
                    }
                }
            };
        }
    }
}