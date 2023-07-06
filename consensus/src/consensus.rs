use crate::aba::BAMessage;
use crate::config::{Committee, Parameters};
use crate::core::Core;
use crate::error::ConsensusResult;
use crate::filter::Filter;
use crate::mempool::{ConsensusMempoolMessage, MempoolDriver};
use crate::messages::{Block, ConsensusMessage};
use crypto::{PublicKey, SignatureService};
use log::info;
use network::{NetReceiver, NetSender};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use threshold_crypto::PublicKeySet;

#[cfg(test)]
#[path = "tests/consensus_tests.rs"]
pub mod consensus_tests;

pub struct Consensus;

impl Consensus {
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        store: Store,
        signature_service: SignatureService,
        pk_set: PublicKeySet,   // The set of tss public keys
        tx_core: Sender<ConsensusMessage>,
        rx_core: Receiver<ConsensusMessage>,
        tx_consensus_mempool: Sender<ConsensusMempoolMessage>,
        tx_commit: Sender<Block>,
    ) -> ConsensusResult<()> {
        info!(
            "Consensus timeout delay set to {} ms",
            parameters.timeout_delay
        );
        info!(
            "Consensus synchronizer retry delay set to {} ms",
            parameters.sync_retry_delay
        );
        info!(
            "Consensus max payload size set to {} B",
            parameters.max_payload_size
        );
        info!(
            "Consensus min block delay set to {} ms",
            parameters.min_block_delay
        );

        let (tx_network, rx_network) = channel(10000);
        let (tx_mvba_filter, rx_mvba_filter) = channel(10000);
        let (tx_ba_filter, rx_ba_filter) = channel(10000);

        // Make the network sender and receiver.
        let address = committee.address(&name).map(|mut x| {
            x.set_ip("0.0.0.0".parse().unwrap());
            x
        })?;
        let network_receiver = NetReceiver::new(address, tx_core.clone());
        tokio::spawn(async move {
            network_receiver.run().await;
        });

        let mut network_sender = NetSender::new(rx_network);
        tokio::spawn(async move {
            network_sender.run().await;
        });

        // Make the mempool driver which will mediate our requests to the mempool.
        let mempool_driver = MempoolDriver::new(tx_consensus_mempool);

        // Custom filter to arbitrary delay network messages.
        let mut consensus_filter = Filter::<ConsensusMessage> {
            from: rx_mvba_filter, 
            to: tx_network.clone(),
            parameters: parameters.clone() 
        };
        tokio::spawn(async move {
            consensus_filter.run().await;
        });

        // Init BA message filter.
        let mut ba_filter = Filter::<BAMessage> { 
            from: rx_ba_filter, 
            to: tx_network,
            parameters: parameters.clone() 
        };
        tokio::spawn(async move {
            ba_filter.run().await;
        });

        let mut mvba = Core::new(
            name,
            committee,
            parameters,
            signature_service,
            pk_set,
            store,
            mempool_driver,
            /* core_channel */ rx_core,
            /* network_filter */ tx_mvba_filter,
            /* commit_channel */ tx_commit,
        ).await;

        tokio::spawn(async move {
            mvba.run().await;
        });
    
        Ok(())
    }
}