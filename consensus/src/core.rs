use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use tokio::sync::mpsc::{Receiver, Sender};

pub type SeqNumber = u64;

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
    pub async fn run(&mut self) {
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(None).await;
        }

        loop {
            let result = tokio::select! {
                Some(msg) = self.rx_message.recv() => match msg {
                    
                }
            };
        }
    }
}