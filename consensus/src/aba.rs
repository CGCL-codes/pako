use std::collections::HashMap;
use std::collections::HashSet;
use crypto::PublicKey;
use log::debug;
use serde::Deserialize;
use serde::Serialize;
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::error::{ConsensusError, ConsensusResult};
use crate::filter::BAFilterInput;
use crate::messages::RandomCoin;
use crate::messages::RandomnessShare;
use crate::{Committee, Parameters, EpochNumber, aggregator::Aggregator, ViewNumber};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum BAMessage {
    Val(BAVote),
    Aux(BAVote),
    Conf(BAConf),
    RandomnessShare(RandomnessShare),
    RandomCoin(RandomCoin),
}

#[derive(Hash, PartialEq, Eq)]
pub enum BAPhase {
    Val,
    Aux,
    Conf,
    RandomnessShare,
    RandomCoin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BAVote {
    pub author: PublicKey,
    pub vote: bool,
    pub epoch: EpochNumber, // epoch that outer protocol currently in
    pub view: ViewNumber, // view that aba instance proceeds into
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BAConf {
    pub author: PublicKey,
    pub bin_val: HashSet<bool>, // bin_val carried by Conf
    pub epoch: EpochNumber, 
    pub view: ViewNumber, 
}

impl BAConf {
    pub fn verify(
        &self, 
        committee: &Committee, 
        halt_mark: &EpochNumber, 
        epochs_halted: &HashSet<EpochNumber>
    ) -> ConsensusResult<()> {
        // Discard block with halted epoch number.
        ensure!(
            self.epoch > *halt_mark && !epochs_halted.contains(&self.epoch),
            ConsensusError::MessageWithHaltedEpoch(self.epoch, halt_mark+1)
        );

         // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        Ok(())
    }
}

impl BAVote {
    pub fn verify(
        &self, 
        committee: &Committee, 
        halt_mark: &EpochNumber, 
        epochs_halted: &HashSet<EpochNumber>
    ) -> ConsensusResult<()> {
        // Discard block with halted epoch number.
        ensure!(
            self.epoch > *halt_mark && !epochs_halted.contains(&self.epoch),
            ConsensusError::MessageWithHaltedEpoch(self.epoch, halt_mark+1)
        );

         // Ensure the authority has voting rights.
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
    pk_set: PublicKeySet,
    network_filter: Sender<BAFilterInput>,

    bin_val: HashMap<(EpochNumber, ViewNumber), HashSet<bool>>, 
    votes_aggregators: HashMap<(EpochNumber, ViewNumber, BAPhase), Aggregator<BAVote>>, // BAVotes collector
    conf_aggregators: HashMap<(EpochNumber, ViewNumber, BAPhase), Aggregator<BAConf>>, // BAConfs collector
    coin_share_aggregators: HashMap<(EpochNumber, ViewNumber, BAPhase), Aggregator<RandomnessShare>>,

    input_channel: Receiver<(EpochNumber, bool)>, // receive input from optimistic path
    output_channel: Sender<(EpochNumber, bool)>, // output aba result to node
    core_channel: Receiver<BAMessage>,  

    halt_mark: EpochNumber,
    epochs_halted: HashSet<EpochNumber>,
}

impl BinaryAgreement {
    pub fn new(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        pk_set: PublicKeySet,
        network_filter: Sender<BAFilterInput>,
        input_channel: Receiver<(EpochNumber, bool)>, 
        output_channel: Sender<(EpochNumber, bool)>, 
        core_channel: Receiver<BAMessage>, 
        halt_mark: EpochNumber,
        epochs_halted: HashSet<EpochNumber>,
    ) -> Self {
        Self {
            name,
            committee,
            parameters,
            pk_set,
            network_filter,
            bin_val: HashMap::new(),
            votes_aggregators: HashMap::new(),
            conf_aggregators: HashMap::new(),
            coin_share_aggregators: HashMap::new(),
            input_channel,
            output_channel,
            core_channel,
            halt_mark: 0,
            epochs_halted: HashSet::new(),
        }
    }

    async fn transmit(&self, message: BAMessage) -> ConsensusResult<()> {
        debug!("Broadcasting BAMessage {:?}", message);
        let addresses = self.committee.broadcast_addresses(&self.name);
        if let Err(e) = &self.network_filter.send((message, addresses)).await {
            panic!("Failed to send BA message through network channel: {}", e);
        }
        Ok(())
    }

    async fn val(&self, val: BAVote) -> ConsensusResult<()> {
        // Broadcast val.
        self.transmit(BAMessage::Aux(val)).await
    }

    async fn handle_val(&mut self, vote: BAVote) -> ConsensusResult<()> {
        vote.verify(&self.committee, &self.halt_mark, &self.epochs_halted)?;

        self.votes_aggregators
        .entry((vote.epoch, vote.view, BAPhase::Val))
        .or_insert_with(|| Aggregator::<BAVote>::new())
        .append(vote.author, vote.clone(), self.committee.stake(&vote.author))?;

        let aggregator = self.votes_aggregators
            .get(&(vote.epoch, vote.view, BAPhase::Val))
            .unwrap();

        // Broadcast val if received f+1 copies.
        if aggregator.is_verified(&self.committee, &vote.vote, &self.committee.random_coin_threshold()) {
            self.val(vote.clone()).await?;
        }
        
        // Add val to bin_val if received n-f copies, 
        // broadcast aux if it's the first to collect a quorum.
        if aggregator.is_verified(&self.committee, &vote.vote, &self.committee.quorum_threshold()) {
            self.bin_val.entry((vote.epoch, vote.view))
                .or_insert({
                    let mut bin_val = HashSet::new();
                    bin_val.insert(vote.vote);
                    bin_val
                });
            if !aggregator.is_verified(&self.committee, &vote.vote, &self.committee.quorum_threshold()) {
                self.aux(vote).await?;
            }
        }

        Ok(())
    }

    async fn aux(&mut self, aux: BAVote) -> ConsensusResult<()> {
        // Collect the node's own aux.
        self.votes_aggregators
        .entry((aux.epoch, aux.view, BAPhase::Aux))
        .or_insert_with(|| Aggregator::<BAVote>::new())
        .append(aux.author, aux.clone(), self.committee.stake(&aux.author))?;
        
        // Broadcast aux.
        self.transmit(BAMessage::Aux(aux)).await
    }

    async fn handle_aux(&mut self, aux: BAVote) -> ConsensusResult<()> {
        aux.verify(&self.committee, &self.halt_mark, &self.epochs_halted)?;

        self.votes_aggregators
        .entry((aux.epoch, aux.view, BAPhase::Aux))
        .or_insert_with(|| Aggregator::<BAVote>::new())
        .append(aux.author, aux.clone(), self.committee.stake(&aux.author))?;

        let aggregator = self.votes_aggregators
            .get(&(aux.epoch, aux.view, BAPhase::Aux))
            .unwrap();

        // Broadcast conf if received n-f aux.
        if aggregator.weight == self.committee.quorum_threshold() {
            let conf = BAConf {
                author: aux.author,
                bin_val: self.bin_val.get(&(aux.epoch, aux.view)).unwrap().clone(),
                epoch: aux.epoch,
                view: aux.view,
            };
            self.conf(conf).await?;
        }

        Ok(())
    }

    async fn conf(&mut self, conf: BAConf) -> ConsensusResult<()> {
        // Collect the node's own conf.
        self.conf_aggregators
        .entry((conf.epoch, conf.view, BAPhase::Conf))
        .or_insert_with(|| Aggregator::<BAConf>::new())
        .append(conf.author, conf.clone(), self.committee.stake(&conf.author))?;

        // Broadcast conf.
        self.transmit(BAMessage::Conf(conf)).await
    }

    async fn handle_conf(&mut self, conf: BAConf) -> ConsensusResult<()> {
        conf.verify(&self.committee, &self.halt_mark, &self.epochs_halted)?;

        self.conf_aggregators
        .entry((conf.epoch, conf.view, BAPhase::Aux))
        .or_insert_with(|| Aggregator::<BAConf>::new())
        .append(conf.author, conf.clone(), self.committee.stake(&conf.author))?;

        let aggregator = self.votes_aggregators
            .get(&(conf.epoch, conf.view, BAPhase::Aux))
            .unwrap();

        Ok(())
    }

    async fn handle_randomness_share(&mut self, randomness_share: RandomnessShare) -> ConsensusResult<()> {
        randomness_share.verify(&self.committee, &self.pk_set, self.halt_mark, &self.epochs_halted)?;

        // f+1 shares to form a random coin.
        self.coin_share_aggregators
            .entry((randomness_share.epoch, randomness_share.view, BAPhase::RandomnessShare))
            .or_insert_with(|| Aggregator::<RandomnessShare>::new())
            .append(randomness_share.author, 
                randomness_share.clone(), 
                self.committee.stake(&randomness_share.author));
        
        // n-f randomness shares to reveal fallback leader. 
        let shares = self.coin_share_aggregators
            .get_mut(&(randomness_share.epoch, randomness_share.view, BAPhase::RandomnessShare))
            .unwrap()
            .take(self.committee.quorum_threshold());

        match shares {
            // Votes not enough.
            None => Ok(()),

            Some(msgs) => {
                let shares: Vec<RandomnessShare> = msgs.into_iter()
                    .filter_map(|s| {
                        match s {
                            ConsensusMessage::RandomnessShare(share) => Some(share),
                            _ => None,
                        }
                    })
                    .collect();

                // Invoke ABA, vote for 1 if among shares there is at least one containing valid sigma1 
                // of the optimistic block, otherwise 0.
                

                // Combine shares into a complete signature.
                let share_map = shares.iter()
                    .map(|s| (self.committee.id(s.author), &s.signature_share))
                    .collect::<BTreeMap<_, _>>();
                let threshold_signature = self.pk_set.combine_signatures(share_map).expect("Unqualified shares!");

                // Use coin to elect leader. 
                let id = usize::from_be_bytes((&threshold_signature.to_bytes()[0..8]).try_into().unwrap()) % self.committee.size();
                let mut keys: Vec<_> = self.committee.authorities.keys().cloned().collect();
                keys.sort();
                let leader = keys[id];
                debug!("Random coin of epoch {} view {} elects leader id {}", randomness_share.epoch, randomness_share.view, id);

                let random_coin = RandomCoin {
                    epoch: randomness_share.epoch,
                    view: randomness_share.view, 
                    leader, 
                    shares,
                };
                self.handle_random_coin(random_coin.clone()).await
            },
        }
    }

    async fn handle_random_coin(&mut self, share: RandomCoin) -> ConsensusResult<()> {
        Ok(())
    }

    pub async fn run(&mut self) {
        loop {
            let result = tokio::select! {
                Some((epoch, vote)) = self.input_channel.recv() => {
                    let vote = BAVote { author: self.name, vote, epoch, view: 1 };
                    self.handle_val(vote).await
                },
                Some(msg) = self.core_channel.recv() => {
                    match msg {
                        BAMessage::Val(vote) => self.handle_val(vote).await,
                        BAMessage::Aux(vote) => self.handle_aux(vote).await,
                        BAMessage::Conf(conf) => self.handle_conf(conf).await,
                        BAMessage::RandomnessShare(share) => self.handle_randomness_share(share).await,
                        BAMessage::RandomCoin(coin) => self.handle_random_coin(coin).await
                    }
                },
            };

            match result {
                Ok(_) => todo!(),
                Err(_) => todo!(),
            }
        }
    }
}