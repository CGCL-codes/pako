use std::{task::{Waker, Poll, Context}, sync::Mutex, rc::Rc, pin::Pin, cell::RefCell};

use futures::Future;

pub struct ElectionState {
    pub done: bool,
    pub wakers: Vec<Waker>,
}

pub struct ElectionFuture {
    election_state: Rc<RefCell<ElectionState>>,
}

impl Future for ElectionFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.election_state.borrow().done {
            Poll::Ready(())
        } else {
            self.election_state.borrow_mut().wakers.push(cx.waker().clone());
            Poll::Pending
        }
    }
}