use crate::{config::Committee, messages::RandomCoin};
use crate::messages::ConsensusMessage;
use crate::error::ConsensusResult;
use crate::filter::FilterInput;
use crypto::PublicKey;
use futures::Future;
use log::debug;
use std::fmt;
use std::{task::{Waker, Poll, Context}, pin::Pin, sync::{Mutex, Arc}};
use tokio::sync::mpsc::Sender;

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
