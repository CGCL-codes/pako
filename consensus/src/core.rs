use crate::config::{Committee, Parameters};
use crate::error::ConsensusResult;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use tokio::sync::mpsc::{Receiver, Sender};
use store::Store;

pub type SeqNumber = u64;

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
    leader_elector: LeaderElector,
    mempool_driver: MempoolDriver,
    core_channel: Receiver<ConsensusMessage>,
    network_filter: Sender<FilterInput>,
    commit_channel: Sender<Block>,
    view: SeqNumber,       // current view
    aggregator: Aggregator,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn new(

    ) -> Self {

    }

    async fn handle_proposal(&mut self, block: &Block) -> ConsensusResult<()> {

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

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block (if we are the leader).
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(None)
            .await
            .expect("Failed to send the first block");
        }

        loop {
            let result = tokio::select! {
                Some(msg) = self.rx_message.recv() => match msg {
                    match msg {
                        ConsensusMessage::Propose(block) => self.
                    }
                }
            };
        }
    }
}