use std::{task::{Waker, Poll, Context}, sync::Mutex, rc::Rc, pin::Pin};

use futures::Future;

struct ElectionState {
    done: bool,
    waker: Option<Waker>,
}

struct ElectionFuture {
    election_state: Rc<Mutex<ElectionState>>,
}

impl Future for ElectionFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut election_state = self.election_state.lock().unwrap();
        if election_state.done {
            Poll::Ready(())
        } else {
            election_state.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}