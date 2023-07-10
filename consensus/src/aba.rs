use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use async_recursion::async_recursion;
use crypto::PublicKey;
use crypto::SignatureService;
use log::debug;
use log::error;
use log::warn;
use serde::Deserialize;
use serde::Serialize;
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::error::{ConsensusError, ConsensusResult};
use crate::filter::BAFilterInput;
use crate::messages::RandomCoin;
use crate::messages::RandomnessShare;
use crate::synchronizer::transmit;
use crate::{Committee, Parameters, EpochNumber, aggregator::Aggregator, ViewNumber};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum BAMessage {
    Val(BAVote),
    Aux(BAVote),
    Conf(BAConf),
    RandomnessShare(RandomnessShare),
    RandomCoin(RandomCoin),
    Halt(BAVote),
}

#[derive(Hash, PartialEq, Eq)]
pub enum BAPhase {
    Val,
    Aux,
    Conf,
    RandomnessShare,
    Halt,
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
    signature_service: SignatureService,
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
        signature_service: SignatureService,
        network_filter: Sender<BAFilterInput>,
        input_channel: Receiver<(EpochNumber, bool)>, 
        output_channel: Sender<(EpochNumber, bool)>, 
        core_channel: Receiver<BAMessage>, 
    ) -> Self {
        Self {
            name,
            committee,
            parameters,
            pk_set,
            signature_service,
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

    async fn transmit(&self, msg: BAMessage) -> ConsensusResult<()> {
        transmit(
            msg, 
            &self.name, 
            None, 
            &self.network_filter, 
            &self.committee
        ).await
    }

    #[async_recursion]
    async fn handle_val(&mut self, val: &BAVote) -> ConsensusResult<()> {
        val.verify(&self.committee, &self.halt_mark, &self.epochs_halted)?;

        let aggregator = self.votes_aggregators
        .entry((val.epoch, val.view, BAPhase::Val))
        .or_insert_with(|| Aggregator::<BAVote>::new());

        aggregator.append(val.author, val.clone(), self.committee.stake(&val.author))?;

        let forward_prepared = aggregator.is_verified(&self.committee, &val.vote, &self.committee.random_coin_threshold());
        let has_qc = aggregator.is_verified(&self.committee, &val.vote, &self.committee.quorum_threshold());
        let opposite_has_qc = aggregator.is_verified(&self.committee, &!val.vote, &self.committee.quorum_threshold());

        let forward =  BAVote { 
            author: self.name, 
            vote: val.vote, 
            epoch: val.epoch, 
            view: val.view 
        };

        // Add val to bin_val if received n-f copies, 
        // broadcast aux if it's the first to collect a quorum.
        if has_qc {
            self.bin_val.entry((val.epoch, val.view))
                .or_insert({
                    let mut bin_val = HashSet::new();
                    bin_val.insert(val.vote);
                    bin_val
                });
            if !opposite_has_qc {
                self.handle_aux(&forward).await?;
                self.transmit(BAMessage::Aux(forward)).await?;
            }
        } else if forward_prepared {
            // Broadcast val if received f+1 copies.
            self.transmit(BAMessage::Val(forward)).await?;
        }

        Ok(())
    }

    async fn handle_aux(&mut self, aux: &BAVote) -> ConsensusResult<()> {
        aux.verify(&self.committee, &self.halt_mark, &self.epochs_halted)?;

        let aggregator = self.votes_aggregators
        .entry((aux.epoch, aux.view, BAPhase::Aux))
        .or_insert_with(|| Aggregator::<BAVote>::new());

        aggregator.append(aux.author, aux.clone(), self.committee.stake(&aux.author))?;

        // Broadcast conf if received n-f aux.
        let bin_val =  self.bin_val.get(&(aux.epoch, aux.view))
            .map_or_else(|| HashSet::new(), |bv| bv.clone());
        if aggregator.weight == self.committee.quorum_threshold() {
            let conf = BAConf {
                author: self.name,
                bin_val,
                epoch: aux.epoch,
                view: aux.view,
            };
            self.handle_conf(&conf).await?;
            self.transmit(BAMessage::Conf(conf)).await?;
        }

        Ok(())
    }

    async fn handle_conf(&mut self, conf: &BAConf) -> ConsensusResult<()> {
        conf.verify(&self.committee, &self.halt_mark, &self.epochs_halted)?;

        let aggregator = self.conf_aggregators
        .entry((conf.epoch, conf.view, BAPhase::Conf))
        .or_insert_with(|| Aggregator::<BAConf>::new());

        aggregator.append(conf.author, conf.clone(), self.committee.stake(&conf.author))?;

        let aggregator = aggregator.take(self.committee.quorum_threshold());
        match aggregator {
            None => Ok(()),
            Some(_) => {
                let randomness_share = RandomnessShare::new(
                    conf.epoch,
                    conf.view, 
                    self.name, 
                    None,
                    self.signature_service.clone()
                ).await;
                self.handle_randomness_share(&randomness_share).await?;
                self.transmit(BAMessage::RandomnessShare(randomness_share)).await
            }
        }
    }

    async fn handle_randomness_share(&mut self, randomness_share: &RandomnessShare) -> ConsensusResult<()> {
        randomness_share.verify(&self.committee, &self.pk_set, self.halt_mark, &self.epochs_halted)?;

        let shares = self.coin_share_aggregators
            .entry((randomness_share.epoch, randomness_share.view, BAPhase::RandomnessShare))
            .or_insert_with(|| Aggregator::<RandomnessShare>::new());

        shares.append(randomness_share.author, 
            randomness_share.clone(), 
            self.committee.stake(&randomness_share.author))?;
        
        // n-f randomness shares to reveal coin value. 
        let shares = shares.take(self.committee.quorum_threshold());
        match shares {
            // Confs not enough.
            None => Ok(()),

            Some(msgs) => {
                // Combine shares into a complete signature.
                let share_map = msgs.iter()
                    .map(|s| (self.committee.id(s.author), &s.signature_share))
                    .collect::<BTreeMap<_, _>>();
                let threshold_signature = self.pk_set.combine_signatures(share_map).expect("Unqualified shares!");

                // Use coin to elect leader. 
                let id = usize::from_be_bytes((&threshold_signature.to_bytes()[0..8]).try_into().unwrap()) % self.committee.size();
                let mut keys: Vec<_> = self.committee.authorities.keys().cloned().collect();
                keys.sort();
                let leader = keys[id];
                debug!("Random coin of epoch {} view {} choose value {{{}}}", 
                    randomness_share.epoch, 
                    randomness_share.view, 
                    self.committee.id(leader) / 2 == 0
                );

                let random_coin = RandomCoin {
                    author: self.name,
                    epoch: randomness_share.epoch,
                    view: randomness_share.view, 
                    fallback_leader: leader, 
                    threshold_sig: threshold_signature,
                };
                self.handle_random_coin(random_coin.clone()).await
            },
        }
    }

    async fn handle_random_coin(&mut self, random_coin: RandomCoin) -> ConsensusResult<()> {
        random_coin.verify(&self.committee, &self.pk_set, self.halt_mark, &self.epochs_halted)?;

        let coin = self.committee.id(random_coin.fallback_leader) / 2 == 0;
        
        let bin_vals = self.conf_aggregators
            .get(&(random_coin.epoch, random_coin.view, BAPhase::Conf))
            .unwrap()
            .votes.to_owned();

        let union = bin_vals.into_iter()
            .fold(HashSet::<bool>::new(), |intersect, conf| {
                intersect.union(&conf.bin_val).cloned().collect()
            });

        if union.len() == 2 {
            let next_vote = BAVote { 
                author: self.name, 
                vote: coin, 
                epoch: random_coin.epoch, 
                view: random_coin.view+1 
            };
            self.handle_val(&next_vote).await?;
            self.transmit(BAMessage::Val(next_vote)).await?;
        } else {
            let next_vote = union.iter().any(|vote| *vote);
            let next_vote = BAVote { 
                author: self.name, 
                vote: next_vote, 
                epoch: random_coin.epoch, 
                view: random_coin.view+1 
            };
            self.handle_val(&next_vote).await?;
            self.transmit(BAMessage::Val(next_vote.clone())).await?;

            if next_vote.vote == coin {
                // Output value to mvba.
                self.output(random_coin.epoch, coin).await;
                self.transmit(BAMessage::Halt(next_vote)).await?;
            }
        }

        Ok(())
    }

    async fn handle_halt(&mut self, halt: BAVote) -> ConsensusResult<()> {
        halt.verify(&self.committee, &self.halt_mark, &self.epochs_halted)?;

        let aggregator = self.votes_aggregators
        .entry((halt.epoch, halt.view, BAPhase::Halt))
        .or_insert_with(|| Aggregator::<BAVote>::new());

        // f+1 halts to output from Binary Agreement.
        aggregator.append(halt.author, halt.clone(), self.committee.stake(&halt.author))?;
        if aggregator.weight == self.committee.random_coin_threshold() {
            self.output(halt.epoch, halt.vote).await;
        }

        Ok(())
    }

    async fn output(&mut self, epoch: EpochNumber, vote: bool) {
        debug!("Successfully output from Binary Agreement in epoch {}, with vote {{ {} }}", epoch, vote);
        self.output_channel.send((epoch, vote)).await
            .expect("Failed to send ABA result back through output channel.");

        self.cleanup_epoch(epoch);
    }

    fn cleanup_epoch(&mut self, epoch: EpochNumber) {
        // Mark epoch as halted.
        self.epochs_halted.insert(epoch);
        if self.epochs_halted.remove(&(self.halt_mark + 1)) {
            self.halt_mark += 1;
        }

        self.votes_aggregators.retain(|&(e, _, _), _| e != epoch);
        self.conf_aggregators.retain(|&(e, _, _), _| e != epoch);
        self.coin_share_aggregators.retain(|&(e, _, _), _| e != epoch);
    }

    pub async fn run(&mut self) {
        loop {
            let result = tokio::select! {
                Some((epoch, vote)) = self.input_channel.recv() => {
                    let val = BAVote { author: self.name, vote, epoch, view: 1 };

                    if let Err(e) = self.handle_val(&val).await {
                        Err(e)
                    } else {
                        self.transmit(BAMessage::Val(val)).await
                    }
                },
                Some(msg) = self.core_channel.recv() => {
                    match msg {
                        BAMessage::Val(vote) => self.handle_val(&vote).await,
                        BAMessage::Aux(vote) => self.handle_aux(&vote).await,
                        BAMessage::Conf(conf) => self.handle_conf(&conf).await,
                        BAMessage::RandomnessShare(share) => self.handle_randomness_share(&share).await,
                        BAMessage::RandomCoin(coin) => self.handle_random_coin(coin).await,
                        BAMessage::Halt(vote) => self.handle_halt(vote).await,
                    }
                },
            };

            match result {
                Ok(()) => (),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
        }
    }
}