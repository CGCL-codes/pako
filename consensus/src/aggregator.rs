use crate::config::Stake;
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::ConsensusMessage;
use crypto::PublicKey;
use std::collections::HashSet;

#[cfg(test)]
#[path = "tests/aggregator_tests.rs"]
pub mod aggregator_tests;

pub struct Aggregator {
    pub weight: Stake,
    pub votes: Vec<ConsensusMessage>,
    pub used: HashSet<PublicKey>,
    pub is_taken: bool,
}

impl Aggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            is_taken: false,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(&mut self, author: PublicKey, vote: ConsensusMessage, weight: Stake) -> ConsensusResult<()> {
        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuseinQC(author)
        );

        self.votes.push(vote.clone());
        self.weight += weight;

        Ok(())
    }

    pub fn take(&mut self, threshold: Stake) -> Option<Vec<ConsensusMessage>> {
        if self.weight >= threshold && !self.is_taken {
            self.is_taken = true;
            return Some(self.votes.clone());
        }
        None
    }

}