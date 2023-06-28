use crate::{config::Committee, messages::RandomCoin};
use crate::messages::ConsensusMessage;
use crate::error::ConsensusResult;
use crate::filter::FilterInput;
use crypto::PublicKey;
use futures::Future;
use log::debug;
use std::{task::{Waker, Poll, Context}, pin::Pin, sync::{Mutex, Arc}};
use tokio::sync::mpsc::Sender;

#[cfg(test)]
#[path = "tests/synchronizer_tests.rs"]
pub mod synchronizer_tests;

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

pub async fn transmit(
    message: ConsensusMessage,
    from: &PublicKey,
    to: Option<&PublicKey>,
    network_filter: &Sender<FilterInput>,
    committee: &Committee,
) -> ConsensusResult<()> {
    let addresses = if let Some(to) = to {
        debug!("Sending {:?} to {}", message, to);
        vec![committee.address(to)?]
    } else {
        debug!("Broadcasting {:?}", message);
        committee.broadcast_addresses(from)
    };
    if let Err(e) = network_filter.send((message, addresses)).await {
        panic!("Failed to send block through network channel: {}", e);
    }
    Ok(())
}
