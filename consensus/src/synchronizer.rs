use crate::config::Committee;
use crate::messages::{Block, ConsensusMessage};
use crate::error::{ConsensusError, ConsensusResult};
use crate::filter::FilterInput;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use futures::future::try_join_all;
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use futures::Future;
use log::{debug, error};
use std::collections::{HashMap, HashSet};
use std::{task::{Waker, Poll, Context}, pin::Pin, sync::{Mutex, Arc}};
use std::time::{SystemTime, UNIX_EPOCH};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

#[cfg(test)]
#[path = "tests/synchronizer_tests.rs"]
pub mod synchronizer_tests;

const TIMER_ACCURACY: u64 = 5_000;

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

pub struct Synchronizer {
    store: Store,
    pub inner_channel: Sender<Block>,
}

impl Synchronizer {
    pub async fn new(
        name: PublicKey,
        committee: Committee,
        store: Store,
        network_filter: Sender<FilterInput>,
        sync_retry_delay: u64,
    ) -> Self {
        let (tx_inner, mut rx_inner): (_, Receiver<Block>) = channel(10000);

        let store_copy = store.clone();
        tokio::spawn(async move {
            let mut waiting = FuturesUnordered::new();
            let mut pending = HashSet::new();
            let mut requests = HashMap::new();

            let timer = sleep(Duration::from_millis(TIMER_ACCURACY));
            tokio::pin!(timer);
            loop {
                tokio::select! {
                    Some(block) = rx_inner.recv() => {
                        if pending.insert(block.digest()) {
                            let fut = Self::waiter(store_copy.clone(), block.clone());
                            waiting.push(fut);

                            if !requests.contains_key(&block.digest()){
                                debug!("Requesting sync for block {}", block.digest());
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("Failed to measure time")
                                    .as_millis();
                                requests.insert(block.digest(), now);
                            }
                        }
                    },
                    Some(result) = waiting.next() => match result {
                        Ok(block) => {
                            debug!("consensus sync loopback");
                            let _ = pending.remove(&block.digest());
                            let _ = requests.remove(&block.digest());

                            let digest = digest!(block.epoch.to_le_bytes(), block.view.to_le_bytes(), block.author.0);
                            let message = ConsensusMessage::SyncRequest(digest, name);
                            Self::transmit(message, &name, None, &network_filter, &committee).await.unwrap();
                        },
                        Err(e) => error!("{}", e)
                    },
                    () = &mut timer => {
                        // This implements the 'perfect point to point link' abstraction.
                        for (digest, timestamp) in &requests {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Failed to measure time")
                                .as_millis();
                            if timestamp + (sync_retry_delay as u128) < now {
                                debug!("Requesting sync for block {} (retry)", digest);
                                let message = ConsensusMessage::SyncRequest(digest.clone(), name);
                                Self::transmit(message, &name, None, &network_filter, &committee).await.unwrap();
                            }
                        }
                        timer.as_mut().reset(Instant::now() + Duration::from_millis(TIMER_ACCURACY));
                    },
                    else => break,
                }
            }
        });
        Self {
            store,
            inner_channel: tx_inner,
        }
    }

    // Wait for each payload in block to be stored.
    async fn waiter(store: Store, deliver: Block) -> ConsensusResult<Block> {
        let mut waiting: Vec<_> = deliver.payload.clone().into_iter()
            .map(|x| (x, store.clone()))
            .collect();
        let waiting: Vec<_> = waiting.iter_mut()
            .map(|(x, y)| y.notify_read(x.to_vec()))
            .collect();
        let result = try_join_all(waiting).await;
        result.map(|_| deliver).map_err(|e| ConsensusError::StoreError(e))
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

}
