use std::collections::HashMap;
use std::fmt;

use crypto::{PublicKey, Digest, Hash};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use log::debug;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::ConsensusError;
use crate::error::ConsensusResult;
use crate::filter::FilterInput;
use crate::{Committee, Parameters, EpochNumber, aggregator::Aggregator, ViewNumber};

#[derive(Debug)]
pub enum BAMessage {
    Val(BAVote),
    Aux(BAVote),
    Conf(BAVote),
}

impl Hash for BAMessage {
    fn digest(&self) -> Digest {
        let phase = match self {
            BAMessage::Val(_) => &[0],
            BAMessage::Aux(_) => &[1],
            BAMessage::Conf(_) => &[2],
        };
        digest!(phase, "BAMessage")
    }
}

#[derive(Debug, Clone)]
pub struct BAVote {
    author: PublicKey,
    vote: bool,
    epoch: EpochNumber, // epoch that outer protocol currently in
    view: ViewNumber, // view that aba instance proceeds into
}

impl fmt::Display for BAVote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BAVote(author {}, epoch {}, view {}, vote {})",
            self.author,
            self.epoch,
            self.view,
            self.vote
        )
    }
}

impl BAVote {
    pub fn new(author: PublicKey, vote: bool, epoch: EpochNumber, view: ViewNumber) -> Self {
            Self {
                author,
                vote,
                epoch,
                view,
            }
        }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        Ok(())
    }
}

pub struct BinaryAgreement {
    name: PublicKey,
    committee: Committee,
    parameters: Parameters,
    network_filter: Sender<FilterInput>,
    votes_aggregators: HashMap<(EpochNumber, Digest), Aggregator>, // votes collector

    input_channel: Receiver<(EpochNumber, bool)>, // receive input from optimistic path
    output_channel: Sender<(EpochNumber, bool)>, // output aba result to node
    core_channel: Receiver<BAMessage>,  
}

impl BinaryAgreement {
    pub fn new(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        network_filter: Sender<FilterInput>,
        input_channel: Receiver<(EpochNumber, bool)>, 
        output_channel: Sender<(EpochNumber, bool)>, 
        core_channel: Receiver<BAMessage>, 
    ) -> Self {
        Self {
            name,
            committee,
            parameters,
            network_filter,
            votes_aggregators: HashMap::new(),
            input_channel,
            output_channel,
            core_channel,
        }
    }

    pub async fn run(&mut self) {
        loop {
            let result = tokio::select! {
                Some((epoch, vote)) = self.input_channel.recv() => {
                    
                },
                Some(msg) = self.core_channel.recv() => {

                },
            };
        }
    }
}