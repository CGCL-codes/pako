use crate::{SeqNumber, messages};
use crate::config::{Committee, Parameters};
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::messages::{Block, ViewNumber, ConsensusMessage, PBPhase, Proof, ID, ThresholdSig};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::debug;
use serde::{Serialize, Deserialize};
use threshold_crypto::{PublicKeySet, SecretKeyShare, PublicKeyShare};
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
    leader_elector: LeaderElector,
    mempool_driver: MempoolDriver,
    core_channel: Receiver<ConsensusMessage>,
    network_filter: Sender<FilterInput>,
    commit_channel: Sender<Block>,
    epoch: SeqNumber, //    // current epoch
    view: ViewNumber,       // current view
    aggregator: Aggregator,
    abandon_channel: ,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn new(

    ) -> Self {

    }

    // TODO: implement value_validation (j = 1)
    fn check_value(&self, block: &Block) -> bool {
        todo!()
    }

    // Implement value_validation (j = 2)
    fn value_validation(&self, block: &Block) -> bool {
        match block.proof {
            Proof::Pi(_) => self.check_value(block),
            Proof::Sigma(ts_sig) => self.pk_set.public_key().verify(&ts_sig, block.digest()),
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

    async fn echo(&self, )

    async fn handle_val(&self, block: &Block) -> ConsensusResult<()> {
        // Check the block is correctly formed.
        block.verify(&self.committee, &self.pk_set)?;

        // TODO2: send threshold sign share: Lock(block.digest(), ts_share).
        todo!()
    }

    async fn handle_lock(&self, block: &Block, proof: Option<Proof>) -> ConsensusResult<()> {


    }

    async fn handle_val2(&self, block: &Block, proof: ThresholdSig) -> ConsensusResult<()> {
        // TODO1: Verify
        // TODO2: send threshold sign share: Lock(block.digest(), ts_share).
        todo!()
    }

    async fn generate_block(&self, proof: Option<Proof>) -> ConsensusResult<()> {
        // TODO: generate a block in the beginning of a view
        todo!()
    }

    // Starts the SPB phase.
    async fn spb(&mut self, block: Block, proof: Option<Proof>) -> ConsensusResult<()> {
        debug!("Processing {:?}", block);

        // Verify block.
        block.verify(&self.committee, &self.pk_set)?;
        

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


    async fn handle_lock(&mut self, lock: &Lock) -> ConsensusResult<()> {

    }

    async fn handle_finish(&mut self, finish: &Finish) -> ConsensusResult<()> {

    }

    async fn handle_done(&mut self, done: &Done) -> ConsensusResult<()> {

    }

    async fn handle_randommess_share(&mut self, randomness_share: &RandomnessShare) -> ConsensusResult<()> {

    }

    async fn handle_random_coin(&mut self, random_coin: RandomCoin) -> ConsensusResult<()> {

    }

    async fn handle_prevote(&mut self, prevote: &PreVote) -> ConsensusResult<()> {

    }

    async fn handle_vote(&mut self, vote: &Vote) -> ConsensusResult<()> {

    }

    async fn handle_halt(&mut self, halt: &Halt) -> ConsensusResult<()> {

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
                        ConsensusMessage::Halt(halt) => self.advance_epoch(),
                    }
                }
            };
        }
    }
}