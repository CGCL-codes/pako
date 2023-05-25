use crate::{SeqNumber, ViewNumber};
use crate::config::{Committee, Stake, EpochNumber};
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::ConsensusMessage;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, Signature};
use threshold_crypto::PublicKeyShare;
use std::collections::{HashMap, HashSet};
// use std::convert::TryInto;

#[cfg(test)]
#[path = "tests/aggregator_tests.rs"]
pub mod aggregator_tests;

pub struct Aggregator {
    weight: Stake,
    votes: Vec<ConsensusMessage>,
    used: HashSet<PublicKey>,
}

impl Aggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(&mut self, author: PublicKey, vote: ConsensusMessage, committee: &Committee) -> ConsensusResult<Option<Vec<ConsensusMessage>>> {
        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuseinQC(author)
        );
        self.votes.push(vote);
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures QC is only made once.
            return Ok(Some(self.votes));
        }
        Ok(None)
    }

    // To see if votes meet random coin threshold.
    pub fn ready_for_random_coin(&self, committee: &Committee) -> bool {
        self.weight == committee.random_coin_threshold()
    }
}