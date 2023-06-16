use crate::config::Committee;
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

pub struct DoneState {
    pub done: bool,
    pub wakers: Vec<Waker>,
}

pub struct DoneFuture {
    pub done_state: Arc<Mutex<DoneState>>,
}

impl Future for DoneFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut done_state = self.done_state.lock().unwrap();
        if done_state.done {
            Poll::Ready(())
        } else {
            done_state.wakers.push(cx.waker().clone());
            Poll::Pending
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
