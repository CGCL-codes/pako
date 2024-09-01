use crate::ConsensusMessage;
use crate::aba::BAMessage;
use crate::config::Parameters;
use bytes::Bytes;
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use network::NetMessage;
use serde::Serialize;
use std::net::SocketAddr;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration};
use rand::distributions::{Distribution, Uniform};

pub type ConsensusFilterInput = (ConsensusMessage, Vec<SocketAddr>);
pub type BAFilterInput = (BAMessage, Vec<SocketAddr>);
pub struct Filter<T> {
    pub from: Receiver<(T, Vec<SocketAddr>)>,
    pub to: Sender<NetMessage>,
    pub parameters: Parameters,
}

impl Filter<ConsensusMessage> {
    pub async fn run(&mut self) {
        let mut pending = FuturesUnordered::new();
        loop {
            tokio::select! {
                Some(input) = self.from.recv() => pending.push(Self::delay(input, &self.parameters)),
                Some(input) = pending.next() => transmit(input, &self.to).await,
                else => break
            }
        }
    }

    // TODO: fix fn delay.
    async fn delay(input: ConsensusFilterInput, parameters: &Parameters) -> ConsensusFilterInput {
        let (message, _) = &input;
        if let ConsensusMessage::Val(_) = message {
            // NOTE: Increase the delay here (you can use any value from the 'parameters').
            if parameters.ddos {
                sleep(Duration::from_millis(parameters.network_delay)).await;
            }

            // If parameters.max_random_delay is set, this will add a 
            // uniformly distributed delay in [0, parameters.max_random_delay].
            if parameters.max_random_delay > 0 {
                let between = Uniform::from(0..parameters.max_random_delay);
                let mut rng = rand::thread_rng();
                let _ = sleep(Duration::from_millis(between.sample(&mut rng)));
            }
        }
        input
    }
}

impl Filter<BAMessage> {
    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(input) = self.from.recv() => transmit(input, &self.to).await,
                else => break
            }
        }
    }
}

async fn transmit<T: Serialize>(input: (T, Vec<SocketAddr>), network: &Sender<NetMessage>) {
    let (message, addresses) = input;
    let bytes = bincode::serialize(&message).expect("Failed to serialize core message");
    let net_message = NetMessage(Bytes::from(bytes), addresses);
    if let Err(e) = network.send(net_message).await {
        panic!("Failed to send message through network channel: {}", e);
    }
}
