use crate::config::{Committee, Stake};
use crate::core::SeqNumber;
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::{Timeout, Vote, QC, TC};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, Signature};
use std::collections::{HashMap, HashSet};
// use std::convert::TryInto;

#[cfg(test)]
#[path = "tests/aggregator_tests.rs"]
pub mod aggregator_tests;

trait Aggregator {
    fn 
}