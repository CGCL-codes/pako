use crate::{messages::RandomCoin, Committee, error::ConsensusResult};
use crypto::PublicKey;
use futures::Future;
use log::debug;
use tokio::sync::mpsc::Sender;
use std::{task::{Waker, Poll, Context}, pin::Pin, sync::{Mutex, Arc}, net::SocketAddr, fmt::Debug};

#[cfg(test)]
#[path = "tests/synchronizer_tests.rs"]
pub mod synchronizer_tests;

#[derive(Debug)]
pub struct ElectionState {
    pub coin: Option<RandomCoin>,
    pub wakers: Vec<Waker>,
}

pub struct ElectionFuture {
    pub election_state: Arc<Mutex<ElectionState>>,
}

impl Future for ElectionFuture {
    type Output = RandomCoin;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut election_state = self.election_state.lock().unwrap();
        match &election_state.coin {
            Some(coin) => Poll::Ready(coin.clone()),
            None => {
                election_state.wakers.push(cx.waker().clone());
                Poll::Pending
            },
        }
    }
}

pub async fn transmit<T: Debug> (
    message: T, 
    from: &PublicKey, 
    to: Option<&PublicKey>,
    network_filter: &Sender<(T, Vec<SocketAddr>)>,
    committee: &Committee
) -> ConsensusResult<()> {
    let addresses = if let Some(to) = to {
        debug!("Sending {:?} to {}", message, to);
        vec![committee.address(to)?]
    } else {
        debug!("Broadcasting {:?}", message);
        committee.broadcast_addresses(from)
    };
    if let Err(e) = network_filter.send((message, addresses)).await {
        panic!("Failed to send message through network channel: {}", e);
    }
    Ok(())
}
