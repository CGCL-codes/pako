use crate::{ConsensusMessage, Committee};
use crate::aba::BAVote;
use crate::config::Stake;
use crate::error::{ConsensusError, ConsensusResult};
use crypto::PublicKey;
use std::collections::HashSet;

#[cfg(test)]
#[path = "tests/aggregator_tests.rs"]
pub mod aggregator_tests;

pub struct Aggregator<T> {
    pub weight: Stake,
    pub votes: Vec<T>,
    pub used: HashSet<PublicKey>,
}

impl<T> Aggregator<T> {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(&mut self, author: PublicKey, vote: T, weight: Stake) -> ConsensusResult<()> {
        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuseinQC(author)
        );
        self.votes.push(vote);
        self.weight += weight;
        Ok(())
    }

}

impl Aggregator<ConsensusMessage> {
    pub fn take(&mut self, threshold: Stake) -> Option<Vec<ConsensusMessage>> {
        (self.weight == threshold).then(|| self.votes.clone())
    }
}

impl Aggregator<BAVote> {
    // To decide if there is a threshold of vote.
    pub fn is_verified(&self, committee: &Committee, vote: &bool, threshold: &Stake) -> bool {
        let stake: Stake = self.votes.iter()
        .map(|v| if v.vote == *vote { committee.stake(&v.author) } else { 0 })
        .sum();
        stake == *threshold
    }
}