use std::{task::{Waker, Poll, Context}, rc::Rc, pin::Pin, cell::RefCell};

use futures::Future;

pub struct DoneState {
    pub done: bool,
    pub wakers: Vec<Waker>,
}

pub struct DoneFuture {
    done_state: Rc<RefCell<DoneState>>,
}

impl Future for DoneFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.done_state.borrow().done {
            Poll::Ready(())
        } else {
            self.done_state.borrow_mut().wakers.push(cx.waker().clone());
            Poll::Pending
        }
    }
}