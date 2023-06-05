use std::{task::{Waker, Poll, Context}, pin::Pin, sync::{Mutex, Arc}};

use futures::Future;

pub struct DoneState {
    pub done: bool,
    pub wakers: Vec<Waker>,
}

pub struct DoneFuture {
    done_state: Arc<Mutex<DoneState>>,
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