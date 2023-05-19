use crate::config::{Committee, Stake};
use crate::core::{SeqNumber, ConsensusMessage};
use crate::error::{ConsensusError, ConsensusResult};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, Signature};
use std::collections::{HashMap, HashSet};
// use std::convert::TryInto;

#[cfg(test)]
#[path = "tests/aggregator_tests.rs"]
pub mod aggregator_tests;

// pub struct Votes {
//     digest: Digest,
//     votes: Vec<(PublicKey, Signature)>,
// }

// impl Votes {
//     pub fn add_vote(&mut self, vote: 
// }

pub struct Aggregator {
    committee: Committee,
    votes_aggregators: HashMap<SeqNumber, HashMap<Digest, Box<QCMaker>>>,
}

impl Aggregator {
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            votes_aggregators: HashMap::new(),
        }
    }

    pub fn add_vote(&mut self, vote: Vote) -> ConsensusResult<Option<QC>> {
        // TODO: A bad node may make us run out of memory by sending many votes
        // with different round numbers or different digests.

        // Add the new vote to our aggregator and see if we have a QC.
        self.votes_aggregators
            .entry(vote.round)
            .or_insert_with(HashMap::new)
            .entry(vote.digest())
            .or_insert_with(|| Box::new(QCMaker::new()))
            .append(vote, &self.committee)
    }

    pub fn cleanup(&mut self, round: &SeqNumber) {
        self.votes_aggregators.retain(|k, _| k >= round);
    }
}

struct QCMaker {
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl QCMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(&mut self, vote: Vote, committee: &Committee) -> ConsensusResult<Option<QC>> {
        let author = vote.author;
        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuseinQC(author)
        );
        self.votes.push((author, vote.signature));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures QC is only made once.
            return Ok(Some(QC {
                hash: vote.hash.clone(),
                view: vote.view,
                round: vote.round,
                height: vote.height,
                fallback: vote.fallback,
                proposer: vote.proposer,
                acceptor: vote.proposer,
                votes: self.votes.clone(),
            }));
        }
        Ok(None)
    }
}