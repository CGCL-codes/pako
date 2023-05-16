use crate::config::{Committee, Parameters};
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::messages::{Block, ViewNumber, Phase, Proof};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::debug;
use serde::{Serialize, Deserialize};
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::{Receiver, Sender};
use store::Store;

#[derive(Serialize, Deserialize, Debug)]
pub enum ConsensusMessage {
    Propose(Block),
    Lock(Lock),
    Finish(Finish),
    Done(Done),
    Halt(Halt),
    RandomnessShare(RandomnessShare),
    RandomCoin(RandomCoin),
    PreVote(PreVote),
    Vote(Vote),
}


pub struct Core {
    name: PublicKey,
    committee: Committee,
    parameters: Parameters,
    store: Store,
    signature_service: SignatureService,
    pk_set: PublicKeySet,
    leader_elector: LeaderElector,
    mempool_driver: MempoolDriver,
    core_channel: Receiver<ConsensusMessage>,
    network_filter: Sender<FilterInput>,
    commit_channel: Sender<Block>,
    view: ViewNumber,       // current view
    aggregator: Aggregator,
    abandon_channel: ,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn new(

    ) -> Self {

    }

    // TODO: implement check_value()
    fn check_value(&self, block: &Block) -> ConsensusResult<()> {
        Ok(())
    }

    fn value_validation(&self, block: &Block) -> ConsensusResult<()> {
        match block.phase {
            Phase::Phase1 => self.check_value(block),

            // TODO: implement phase2 case of value_validation()
            Phase::Phase2 => Ok(())
        }
    }

    async fn transmit(&self,
        message: ConsensusMessage,
        to: Option<&PublicKey>,
    ) -> ConsensusResult<()> {
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

    async fn plain_broadcast(&self, block: Block) -> ConsensusResult<Lock> {
        let msg = ConsensusMessage::Propose(block);
        self.transmit(msg, None);

        // TODO: redefine aggregator to collect n-f echos
        
    }

    async fn generate_block(&self, proof: Option<Proof>) -> ConsensusResult<()> {

    }

    // Starts the SPB phase.
    async fn handle_proposal(&mut self, block: &Block) -> ConsensusResult<()> {
        debug!("Processing {:?}", block);

        let digest = block.digest();
        // Ensure the block proposer is the right leader for the view.
        ensure!(
            block.author == self.leader_elector.get_leader(block.view),
            ConsensusError::WrongLeader {
                digest,
                leader: block.author,
                view: block.view
            }
        );

        // Check the block is correctly formed.
        block.verify(&self.committee, &self.pk_set)?;
        
        if self.name == self.leader_elector.get_leader(block.view) {
            // Check value.
            self.check_value(block)?;
            
            // 2-PB phases.
            let lock = self.broadcast_pb(block).await;
            let lock2 = self.broadcast_pb(lock).await;
            self.broadcast_finish(lock2).await;
        } 
        else {

        }
        
         
        Ok(())
    }

    async fn broadcast_pb_1(&mut self, block: &Block) -> ConsensusResult<()> {

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

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block (if we are the leader).
        if self.name == self.leader_elector.get_leader(self.view) {
            self.generate_proposal(None)
            .await
            .expect("Failed to send the first block");
        }

        loop {
            let result = tokio::select! {
                Some(msg) = self.core_channel.recv() => {
                    match msg {
                        ConsensusMessage::Propose(block) => self.handle_proposal(&block).await,
                        ConsensusMessage::Halt(halt) => {
                            let result = self.handle_halt(&halt).await;
                            match result {
                                Ok(()) => return,
                                Err(e) => break,
                            }
                        },
                    }
                }
            };
        }
    }
}