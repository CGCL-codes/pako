use crate::{messages::{RandomCoin, Halt}, Committee, error::ConsensusResult, EpochNumber, Block};
use crypto::PublicKey;
use futures::{Future, stream::FuturesUnordered, StreamExt};
use log::debug;
use tokio::sync::mpsc::{Sender, Receiver};
use std::{task::{Waker, Poll, Context}, pin::Pin, sync::{Mutex, Arc}, net::SocketAddr, fmt::Debug, collections::{HashSet, HashMap}};

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

#[derive(Debug)]
pub struct BAState {
    pub epoch: EpochNumber,
    pub consistent: Option<bool>,
    pub optimistic_sigma1: Option<Block>,
    pub coin: Option<RandomCoin>,
    pub wakers: Vec<Waker>,
}

pub struct BAFuture {
    pub state: Arc<Mutex<BAState>>,
}

impl Future for BAFuture {
    type Output = (EpochNumber, Option<Block>, Option<RandomCoin>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut ba_state = self.state.lock().unwrap();

        if let Some(vote) = ba_state.consistent {
            if !vote {
                if let Some(coin) = ba_state.coin.take() {
                    return Poll::Ready((ba_state.epoch, None, Some(coin)));
                }
            } else if let Some(b) = ba_state.optimistic_sigma1.take() {
                return Poll::Ready((ba_state.epoch, Some(b), None));
            }
        }

        ba_state.wakers.push(cx.waker().clone());
        Poll::Pending
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

pub struct Synchronizer;

impl Synchronizer {
    pub async fn run_sync_halt(mut rx_halt: Receiver<(Arc<Mutex<ElectionState>>, Block)>, tx_advance: Sender<Halt>) {
        // Handle Halt till receives the leader.
        let mut halt_mark = 0;
        let mut epochs_halted = HashSet::new();
        let mut halts_unhandled = HashMap::<EpochNumber, Vec<Block>>::new();
        let mut waiting = FuturesUnordered::<Pin<Box<dyn Future<Output=RandomCoin> + Send>>>::new();
        loop {
            tokio::select! {
                Some((election_state, block)) = rx_halt.recv() => {
                    halts_unhandled.entry(block.epoch)
                        .or_insert_with(|| {
                            waiting.push(Box::pin(ElectionFuture{election_state}));
                            Vec::new()
                        })
                        .push(block);
                },
                Some(coin) = waiting.next() => {
                    let blocks = halts_unhandled.remove(&coin.epoch).unwrap();
                    let verified = blocks.into_iter()
                        .find(|b| b.author == coin.fallback_leader && !epochs_halted.contains(&coin.epoch) && coin.epoch > halt_mark);
                    if let Some(verified) = verified {
                        // Broadcast Halt and propose block of next epoch.
                        if let Err(e) = tx_advance.send(
                            Halt {block: verified.clone(), is_optimistic: false}
                        ).await {
                            panic!("Failed to send message through advance channel: {}", e);
                        }
                        // Clean up halted.
                        epochs_halted.insert(coin.epoch);
                        if epochs_halted.remove(&(halt_mark + 1)) {
                            halt_mark += 1;
                        }
                        
                    }
                },
                else => break,
            }
        }
    }

    pub async fn run_sync_aba(
        aba_channel: Sender<(EpochNumber, bool)>, // channel to invoke aba consensus
        mut aba_feedback_channel: Receiver<(EpochNumber, bool)>, // read aba consensus result
        mut aba_sync_receiver: Receiver<(EpochNumber, Arc<Mutex<BAState>>, Arc<Mutex<ElectionState>>)>, // send sync result back to main protocol
        abs_sync_feedback_sender: Sender<(EpochNumber, bool, Option<RandomCoin>)>, // notify main consensus to enter fallback path
        tx_advance: Sender<Halt>, // notify main consensus to commit block of optimistic path
    ) {
        let mut waiting = HashMap::new();
        let mut waiting_fallback_leader = FuturesUnordered::<Pin<Box<dyn Future<Output=RandomCoin> + Send>>>::new();
        let mut ending = FuturesUnordered::<Pin<Box<dyn Future<Output=(EpochNumber, Option<Block>, Option<RandomCoin>)> + Send>>>::new();
        loop {
            tokio::select! {
                Some((epoch, ba_state, election_state)) = aba_sync_receiver.recv() => {
                    let vote = ba_state.lock().unwrap().optimistic_sigma1.is_some();
                    aba_channel.send((epoch, vote)).await.expect("Failed to send vote to background aba.");

                    waiting.insert(epoch, ba_state.clone());
                    waiting_fallback_leader.push(Box::pin(ElectionFuture{ election_state }));
                    ending.push(Box::pin(BAFuture{ state: ba_state }));
                },
                Some((epoch, consistent)) = aba_feedback_channel.recv() => {
                    match waiting.get_mut(&epoch) {
                        Some(ba_state) => {
                            let mut ba_state = ba_state.lock().unwrap();
                            ba_state.consistent = Some(consistent);
                            while let Some(waker) = ba_state.wakers.pop() {
                                waker.wake();
                            }
                        },
                        // Handle nodes fall behind entering aba but received aba result.
                        None => {
                            // If aba outputs 0, wait until fallback leader reveals to enter fallback,
                            // else if aba outputs 1, do nothing since other nodes will send halt to this node.
                            if !consistent {
                                let ba_state = Arc::new(Mutex::new(BAState{ 
                                    epoch, 
                                    consistent: Some(false), 
                                    optimistic_sigma1: None, 
                                    coin: None, 
                                    wakers: Vec::new() 
                                }));
                                waiting.insert(epoch, ba_state.clone());
                                ending.push(Box::pin(BAFuture{ state: ba_state }));
                            }
                        }
                    }
                },
                Some((epoch, optimistic_sigma1, coin)) = ending.next() => {
                    abs_sync_feedback_sender
                        .send((epoch, optimistic_sigma1.is_some(), coin)).await
                        .expect("Failed to send epoch through fallback channel.");

                    if let Some(block) = optimistic_sigma1 {
                        tx_advance
                            .send(Halt{block, is_optimistic: true}).await
                            .expect("Failed to send optimistic block through advance channel.");
                    }
                },
                Some(coin) = waiting_fallback_leader.next() => {
                    let mut ba_state = waiting.get_mut(&coin.epoch).unwrap().lock().unwrap();
                    ba_state.coin = Some(coin);
                    while let Some(waker) = ba_state.wakers.pop() {
                        waker.wake();
                    }
                },
                else => break,
            }
        }
    }
}