use std::collections::{HashMap, BTreeMap};
use std::{default, thread};

use crate::{SeqNumber, ViewNumber};
use crate::aggregator::Aggregator;
use crate::config::{Committee, Parameters, EpochNumber};
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::{Block, ConsensusMessage, PBPhase, Proof, Echo, Done, Finish, RandomnessShare, RandomCoin};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use log::debug;
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

    // Get leaders of previous <epoch, view>
    // or get current leader after leader election. 
    fn get_leader(&self, epoch: EpochNumber, view: ViewNumber) -> PublicKey {
        let mut hasher = Sha512::new();
        hasher.update(epoch.to_le_bytes());
        hasher.update(view.to_le_bytes());
        hasher.update("RANDOM_COIN");
        let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());

        self.random_coin.get(&digest).unwrap().leader
    }

    // TODO: implement check_value()
    fn check_value(&self, block: &Block) -> bool {
        todo!()
    }

    // Value validation 
    fn value_validation(&self, block: &Block) -> bool {
        match block.proof {
            Proof::Pi(_) => self.check_value(block),
            Proof::Sigma(sigma1, _) => {
                if let Some(sigma1) = sigma1 {
                    self.pk_set.public_key().verify(&sigma1, block.digest())
                } else {
                    false
                }
            },
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

    async fn echo(&self, block_digest: Digest, phase: PBPhase, signature_service: SignatureService) -> ConsensusResult<()> {
        let echo = Echo::new(block_digest, phase, self.name, signature_service).await;

        // Broadcast ECHO to all nodes.
        let message = ConsensusMessage::Echo(echo);
        self.transmit(message, None).await?;

        Ok(())
    }

    async fn handle_echo(&mut self, echo: &Echo) -> ConsensusResult<()> {
        echo.verify(&self.committee, &self.pk_set)?;

        let shares = self.votes_aggregators
            .entry(echo.block_digest.clone())
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

                let mut block = self.get_block(&echo.digest());
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

    async fn handle_finish(&self, finish: &Finish) -> ConsensusResult<()> {
        // Verify threshold signature.
        ensure!(
            finish.block.check_sigma2(&self.pk_share),
            ConsensusError::InvalidVoteProof(Some(finish.block.proof))
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
                self.done(finish.block.digest()).await
            },
        }
    }

    async fn handle_val(&self, block: &Block) -> ConsensusResult<()> {
        // Check the block is correctly formed.
        block.verify(&self.committee)?;

        // Send threshold signature share.
        // let signature_share = self.sk_share.sign(block.digest());
        let phase = match block.proof {
            Proof::Pi(_) => PBPhase::Phase1,
            Proof::Sigma(_, _) => PBPhase::Phase2,
        };
        self.echo(block.digest(), phase, self.signature_service.clone()).await
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

    async fn done(&self, block_digest: Digest) -> ConsensusResult<()> {
        let done = Done {
            block_digest,
            author: self.name,
        };

        let message = ConsensusMessage::Done(done);
        self.transmit(message, None).await?;

        Ok(())
    }

    async fn handle_done(&mut self, done: &Done) -> ConsensusResult<()> {
        // TODO: n-f Done to abandon the SPBs undone.
        let msgs = self.votes_aggregators
            .entry(done.digest())
            .or_insert_with(|| Aggregator::new())
            .append(self.name, ConsensusMessage::Done(done.clone()), &self.committee);

        match msgs {
            Err(e) => return Err(e),
            Ok(None) => (),
            Ok(Some(_)) => self.abandon();
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
        // Ignore coins of previous epoch or views.
        if random_coin.epoch < self.epoch
        || random_coin.epoch == self.epoch && random_coin.view < self.view
        || self.random_coin.contains_key(&random_coin.digest()) {
            return Ok(())
        }

        random_coin.verify(&self.committee, &self.pk_set)?;
        
        self.random_coin.insert(random_coin.digest(), random_coin.clone());

        // Multicast the random coin.
        let message = ConsensusMessage::RandomCoin(random_coin.clone());
        self.transmit(message, None).await?;

        // If receives the current leader's Finish, halt and output.
        let mut hasher = Sha512::new();
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.view.to_le_bytes());
        hasher.update("FINISH");
        let finish_digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
        let finishes = &self.votes_aggregators.get(&finish_digest).unwrap().votes;
        let leader_finish = finishes.iter()
            .filter_map(|f| {
                match f {
                    ConsensusMessage::Finish(finish) => Some(finish),
                    _ => None,
                }
            })
            .find(|f| f.author == self.get_leader(self.epoch, self.view));
        if let Some(leader_finish) = leader_finish {
            let halt = ConsensusMessage::Halt(leader_finish.block.clone());
            self.transmit(halt, None).await?;

            // Terminate and advance epoch.
            self.advance_epoch();
        }

        Ok(())
    }

    async fn handle_halt(&self, block: &Block) -> ConsensusResult<()> {
        if block.author == self.get_leader(block.epoch, block.view) {
            
        }
    }

    async fn handle_prevote(&mut self, prevote: &PreVote) -> ConsensusResult<()> {

    }

    async fn handle_vote(&mut self, vote: &Vote) -> ConsensusResult<()> {

    }

    fn advance_epoch(&mut self) -> ConsensusResult<()> {

    }

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block (if we are the leader).
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