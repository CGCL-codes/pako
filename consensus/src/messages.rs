use crate::config::{Committee, EpochNumber, ViewNumber};
use crate::error::{ConsensusError, ConsensusResult};
use crypto::{Digest, Signature, SignatureService, Hash, PublicKey};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt;
use threshold_crypto::{SignatureShare, PublicKeySet};

#[macro_export]
macro_rules! digest {
    ($($x: expr),+) => {
        {
            let mut hasher = Sha512::new();
            $(
                hasher.update($x);
            )+
            Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
        }
    };
}

type Sigma = Option<threshold_crypto::Signature>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ConsensusMessage {
    Val(Block),
    Echo(Echo),
    Finish(Finish),
    Halt(Halt),
    RandomnessShare(RandomnessShare),
    RandomCoin(RandomCoin),
    PreVote(PreVote),
    Vote(Vote),
    RequestHelp(EpochNumber, PublicKey),
    Help(Block),
}

impl fmt::Display for ConsensusMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, 
            "ConsensusMessage {{ {} }}",
            match &self {
                ConsensusMessage::Val(_) => "VAL",
                ConsensusMessage::Echo(_) => "ECHO",
                ConsensusMessage::Finish(_) => "FINISH",
                ConsensusMessage::Halt(_) => "HALT",
                ConsensusMessage::RandomnessShare(_) => "RANDOMNESS_SHARE",
                ConsensusMessage::RandomCoin(_) => "RANDOM_COIN",
                ConsensusMessage::PreVote(_) => "PREVOTE",
                ConsensusMessage::Vote(_) => "VOTE",
                ConsensusMessage::RequestHelp(_, _) => "REQUEST_HELP",
                ConsensusMessage::Help(_) => "HELP",
            }           
        )
    }
}


#[derive(Serialize, Deserialize, Clone)]
pub struct Block {
    pub payload: Vec<Digest>,
    pub author: PublicKey,
    pub signature: Signature,
    pub epoch: EpochNumber,
    pub view: ViewNumber,
    pub proof: Sigma,
}

impl Block {
    pub async fn new(
        payload: Vec<Digest>, 
        author: PublicKey,
        epoch: EpochNumber,
        view: ViewNumber,
        proof: Sigma,
        mut signature_service: SignatureService,
    ) -> Self {
        let block = Self {
            payload,
            author,
            signature: Signature::default(),
            epoch,
            view,
            proof,
        };
        let signature = signature_service.request_signature(block.digest()).await;
        Self { signature, ..block }
    }

    pub fn verify(
        &self, 
        committee: &Committee, 
        halt_mark: EpochNumber, 
        epochs_halted: &HashSet<EpochNumber>
    ) -> ConsensusResult<()> {
        // Discard block with halted epoch number.
        ensure!(
            self.epoch > halt_mark && !epochs_halted.contains(&self.epoch),
            ConsensusError::MessageWithHaltedEpoch(self.epoch, halt_mark+1)
        );

        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check signature.
        self.signature.verify(&self.digest(), &self.author)?;

        Ok(())
    }

    pub fn check_sigma2(&self, pk: &threshold_crypto::PublicKey) -> bool {
        if let Some(sigma) = &self.proof {
            return pk.verify(&sigma, self.digest())
        }
        false
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.view.to_le_bytes());
        self.payload.iter().for_each(|p| hasher.update(p));
        hasher.update(match &self.proof {
            Some(_) => &[1],
            _ => &[0],
        });
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: Block(author {}, epoch {}, view {}, has_qc {}, payload_len {})",
            self.digest(),
            self.author,
            self.epoch,
            self.view,
            match self.proof {
                Some(_) => "Yes",
                _ => "No",
            },
            self.payload.iter().map(|x| x.size()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}", self.author)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CommitVector {
    pub epoch: EpochNumber,
    pub author: PublicKey,
    pub vector: HashMap<PublicKey, bool>,
    pub proof: Sigma,
}

impl Hash for CommitVector {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.author.0);
        hasher.update(match &self.proof {
            Some(_) => &[1],
            _ => &[0],
        });
        let mut tuples = self.vector.iter().collect::<Vec<_>>();
        tuples.sort_by_key(|e| e.0);
        tuples.into_iter().for_each(|(k, v)| {
            hasher.update(k.0);
            hasher.update(if *v { &[1] } else { &[0] });
        });
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for CommitVector {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "CommitVector(author {}, epoch {}, has_qc {})",
            self.author,
            self.epoch,
            match self.proof {
                Some(_) => "Yes",
                _ => "No",
            },
        )
    }
}

impl fmt::Display for CommitVector {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "CV{}", self.author)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Echo<T: Hash> {
    // Block info.
    pub block_digest: Digest,
    pub block_author: PublicKey,

    // Echo info.
    pub epoch: EpochNumber,
    pub view: ViewNumber,
    pub author: PublicKey,

    // Signature share against block digest.
    pub signature_share: SignatureShare,
}

impl Echo {
    pub async fn new(
        block_digest: Digest, 
        block_author: PublicKey,
        epoch: EpochNumber,
        view: ViewNumber,
        author: PublicKey,
        mut signature_service: SignatureService
    ) -> Self {
        let signature_share = signature_service.request_tss_signature(block_digest.clone()).await.unwrap();
        Self {
            block_digest,
            block_author,
            epoch,
            view,
            author,
            signature_share,
        }
    }
    pub fn verify(
        &self, 
        committee: &Committee,
        pk_set: &PublicKeySet, 
        block_author: PublicKey, 
        optimistic_leader: PublicKey,
        halt_mark: EpochNumber, 
        epochs_halted: &HashSet<EpochNumber>
    ) -> ConsensusResult<()> {
        // Check for epoch.
        ensure!(
            self.epoch > halt_mark && !epochs_halted.contains(&self.epoch),
            ConsensusError::MessageWithHaltedEpoch(self.epoch, halt_mark+1)
        );

        // Verify leader.
        ensure!(
            (self.block_author == block_author || self.block_author == optimistic_leader) &&
                self.optimistic_block.as_ref().map_or(true, |b| b.author == self.block_author),
            ConsensusError::WrongLeader {
                digest: self.block_digest.clone(),
                leader: self.block_author,
                author: block_author,
                epoch: self.epoch,
                view: self.view,
            }
        );

        // Verify block.
        self.optimistic_block.as_ref()
            .map_or_else(|| Ok(()), |b| b.verify(committee, halt_mark, epochs_halted))?;

        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        let pk_share = pk_set.public_key_share(committee.id(self.author));
        // Check the signature share.
        ensure!(
            pk_share.verify(&self.signature_share, &self.block_digest),
            ConsensusError::InvalidSignatureShare(self.author)
        );

        Ok(())
    }
}

impl fmt::Debug for Echo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f, 
            "Echo(author {}, block_author {}, epoch {}, view {}, PBPhase {}, is optimistic? {})", 
            self.author,
            self.block_author,
            self.epoch,
            self.view,
            self.phase,
            self.optimistic_block.is_some()
        )
    }
}

impl Hash for Echo {
    fn digest(&self) -> Digest {
        // Echo is distinguished by <epoch, view, phase, is_optimistic, ECHO>,
        digest!(
            self.epoch.to_le_bytes(),
            self.view.to_le_bytes(),
            match self.phase {
                PBPhase::Phase1 => &[0],
                PBPhase::Phase2 => &[1],
            },
            match self.optimistic_block {
                None => &[0],
                Some(_) => &[1],
            },
            "ECHO"
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Finish(pub Block);

impl Hash for Finish {
    fn digest(&self) -> Digest {
        // Finish is distinguished by <epoch, view, FINISH>,
        digest!(
            self.0.epoch.to_le_bytes(),
            self.0.view.to_le_bytes(),
            "FINISH"
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RandomnessShare {
    pub epoch: EpochNumber, // eopch
    pub view: ViewNumber, // view
    pub author: PublicKey,
    pub signature_share: SignatureShare,
    pub optimistic_sigma1: Option<Block>,
}

impl RandomnessShare {
    pub async fn new(
        epoch: EpochNumber,
        view: ViewNumber,
        author: PublicKey,
        optimistic_sigma1: Option<Block>,
        mut signature_service: SignatureService,
    ) -> Self {
        let digest = digest!(epoch.to_le_bytes(), view.to_le_bytes(), "RANDOMNESS_SHARE");
        let signature_share = signature_service.request_tss_signature(digest).await.unwrap();
        Self {
            epoch,
            view,
            author,
            signature_share,
            optimistic_sigma1,
        }
    }

    pub fn verify(
        &self, 
        committee: &Committee, 
        pk_set: &PublicKeySet, 
        halt_mark: EpochNumber, 
        epochs_halted: &HashSet<EpochNumber>
    ) -> ConsensusResult<()> {
        // Check for epoch.
        ensure!(
            self.epoch > halt_mark && !epochs_halted.contains(&self.epoch),
            ConsensusError::MessageWithHaltedEpoch(self.epoch, halt_mark+1)
        );

        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        let share = pk_set.public_key_share(committee.id(self.author));
        ensure!(
            share.verify(&self.signature_share, &self.digest()),
            ConsensusError::InvalidSignatureShare(self.author)
        );

        // Check optimistic block.
        self.optimistic_sigma1
            .as_ref()
            .map_or_else(|| Ok(()), |b| b.verify(committee, halt_mark, epochs_halted))
    }
}

impl Hash for RandomnessShare {
    fn digest(&self) -> Digest {
        digest!(
            self.epoch.to_le_bytes(),
            self.view.to_le_bytes(),
            "RANDOMNESS_SHARE"
        )
    }
}

impl fmt::Debug for RandomnessShare {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f, 
            "RandomnessShare(author {}, epoch {}, view {}, has optimistic sigma1? {})", 
            self.author, 
            self.epoch, 
            self.view, 
            self.optimistic_sigma1.is_some()
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RandomCoin {
    pub author: PublicKey,
    pub epoch: EpochNumber, // epoch
    pub view: ViewNumber, // view
    pub fallback_leader: PublicKey,  // elected leader of the view
    pub threshold_sig: threshold_crypto::Signature, // combined signature 
}

impl RandomCoin {
    pub fn verify(
        &self, 
        committee: &Committee,  
        pk_set: &PublicKeySet,
        halt_mark: EpochNumber, 
        epochs_halted: &HashSet<EpochNumber>
    ) -> ConsensusResult<()> {
        // Check epoch.
        ensure!(
            self.epoch > halt_mark && !epochs_halted.contains(&self.epoch),
            ConsensusError::MessageWithHaltedEpoch(self.epoch, halt_mark+1)
        );

        // Check threshold signature.
        let digest = digest!(self.epoch.to_le_bytes(), self.view.to_le_bytes(), "RANDOMNESS_SHARE");
        ensure!(
            pk_set.public_key().verify(&self.threshold_sig, digest),
            ConsensusError::InvalidThresholdSignature(self.author)
        );

        // Check leader.
        let id = usize::from_be_bytes((&self.threshold_sig.to_bytes()[0..8]).try_into().unwrap()) % committee.size();
        let mut keys: Vec<_> = committee.authorities.keys().cloned().collect();
        keys.sort();
        let leader = keys[id];
        ensure!(leader == self.fallback_leader, ConsensusError::RandomCoinWithWrongLeader);

        Ok(())
    }
}

impl fmt::Debug for RandomCoin {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "RandomCoin(epoch {}, view {}, leader {})", self.epoch, self.view, self.fallback_leader)
    }
}

impl Hash for RandomCoin {
    fn digest(&self) -> Digest {
        digest!(
            self.epoch.to_le_bytes(),
            self.view.to_le_bytes(),
            "RANDOM_COIN"
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PreVote {
    // PreVote author.
    pub author: PublicKey,

    // <epoch, view, leader>
    pub epoch: EpochNumber,
    pub view: ViewNumber,
    pub leader: PublicKey,

    // `Yes` or `No` prevote.
    pub body: PreVoteEnum,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum PreVoteEnum {
    // Leader's block
    Yes(Block),

    // SignatureShare against message digest <epoch, view, leader>.
    No(SignatureShare),
}

impl PreVote {
    pub fn verify(
        &self, 
        committee: &Committee, 
        pk_set: &PublicKeySet,
        halt_mark: EpochNumber, 
        epochs_halted: &HashSet<EpochNumber>
    ) -> ConsensusResult<()> {
        // Check for epoch.
        ensure!(
            self.epoch > halt_mark && !epochs_halted.contains(&self.epoch),
            ConsensusError::MessageWithHaltedEpoch(self.epoch, halt_mark+1)
        );

        match &self.body {
            PreVoteEnum::Yes(block) => {
                ensure!(
                    block.check_sigma1(&pk_set.public_key()),
                    ConsensusError::InvalidVoteProof(block.proof.clone())
                );
                Ok(())
            },
            PreVoteEnum::No(share) => {
                let pk_share = pk_set.public_key_share(committee.id(self.author));
                let digest = digest!(
                    self.epoch.to_le_bytes(),
                    self.view.to_le_bytes(),
                    self.leader.0,
                    "NULL"
                );
                ensure!(
                    pk_share.verify(&share, digest),
                    ConsensusError::InvalidSignatureShare(self.author)
                );
                Ok(())
            },
        }
    }
}

impl Hash for PreVote {
    fn digest(&self) -> Digest {
        digest!(
            self.epoch.to_le_bytes(),
            self.view.to_le_bytes(),
            self.leader.0,
            "PREVOTE"
        )
    }
}

impl fmt::Debug for PreVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "PreVote(author {}, epoch {}, view {}, leader {}, body {})", 
            self.author,
            self.epoch,
            self.view, 
            self.leader,
            match self.body {
                PreVoteEnum::Yes(_) => "YES",
                PreVoteEnum::No(_) => "NO",
            }
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Vote {
    // Vote author.
    pub author: PublicKey,

    // <epoch, view, leader>
    pub epoch: EpochNumber,
    pub view: ViewNumber,
    pub leader: PublicKey,

    // `Yes` or `No` vote.
    pub body: VoteEnum,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum VoteEnum {
    // Leader's block, and a share signed against this Vote.
    Yes(Block, SignatureShare),
    
    // If received a yes prevote, threshold signature is set to sigma1 carried by block,
    // else is combined through n-f shares from PreVote.
    No(threshold_crypto::Signature, SignatureShare),
}

impl Vote {
    pub fn verify(
        &self, 
        committee: &Committee, 
        pk_set: &PublicKeySet,
        halt_mark: EpochNumber, 
        epochs_halted: &HashSet<EpochNumber>
    ) -> ConsensusResult<()> {
        // Check for epoch.
        ensure!(
            self.epoch > halt_mark && !epochs_halted.contains(&self.epoch),
            ConsensusError::MessageWithHaltedEpoch(self.epoch, halt_mark+1)
        );

        match &self.body {
            VoteEnum::Yes(block, share) => {
                // Verify sigma1.
                ensure!(
                    block.check_sigma1(&pk_set.public_key()),
                    ConsensusError::InvalidVoteProof(block.proof.clone())
                );

                // Verify sig share.
                let pk_share = pk_set.public_key_share(committee.id(self.author));
                ensure!(
                    pk_share.verify(&share, block.digest()),
                    ConsensusError::InvalidSignatureShare(self.author)
                );

                Ok(())
            },
            VoteEnum::No(sig, share) => {
                // Verify threshold signature formed out of n-f `No` PreVotes.
                let digest = digest!(
                    self.epoch.to_le_bytes(),
                    self.view.to_le_bytes(),
                    self.leader.0,
                    "NULL"
                );
                ensure!(
                    pk_set.public_key().verify(&sig, digest),
                    ConsensusError::InvalidThresholdSignature(self.author)
                );

                // Verify sig share.
                let digest = digest!(
                    self.epoch.to_le_bytes(),
                    self.view.to_le_bytes(),
                    self.leader.0,
                    "UNLOCK"
                );
                let pk_share = pk_set.public_key_share(committee.id(self.author));
                ensure!(
                    pk_share.verify(&share, digest),
                    ConsensusError::InvalidSignatureShare(self.author)
                );

                Ok(())
            },
        }
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        digest!(
            self.epoch.to_le_bytes(),
            self.view.to_le_bytes(),
            self.leader.0,
            "VOTE"
        )
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Vote(author {}, epoch {}, view {}, leader {}, body {})", 
            self.author,
            self.epoch,
            self.view, 
            self.leader,
            match self.body {
                VoteEnum::Yes(_, _) => "YES",
                VoteEnum::No(_, _) => "NO",
            }
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Halt {
    pub block: Block,
    pub is_optimistic: bool,
}

impl Halt {
    pub fn verify(
        &self, 
        committee: &Committee, 
        pk_set: &PublicKeySet,
        halt_mark: EpochNumber, 
        epochs_halted: &HashSet<EpochNumber>
    ) -> ConsensusResult<()> {
        // If halt from optimistic path, check leader.
        if self.is_optimistic {
            let leader = committee
            .get_public_key(self.block.epoch as usize % committee.size())
            .unwrap();

            ensure!(
                leader == self.block.author,
                ConsensusError::InvalidOptimisticHalt
            )
        }

        // Verify block.
        self.block.verify(committee, halt_mark, epochs_halted)?;
        ensure!(
            self.block.check_sigma1(&pk_set.public_key()) &&
            if !self.is_optimistic {self.block.check_sigma2(&pk_set.public_key())} else {true},
            ConsensusError::InvalidSignatureShare(self.block.author)
        );

        Ok(())
    }
}