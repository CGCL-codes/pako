use crate::config::{Committee, EpochNumber, ViewNumber};
use crate::error::{ConsensusError, ConsensusResult};
use crypto::{Digest, Signature, SignatureService, Hash, PublicKey};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, BTreeMap};
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

// Two types of proof associated with block
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Proof {
    // Relates to input for PBPhase1 (see PBPhase defined below).
    Pi(Vec<(bool, ViewNumber, threshold_crypto::Signature)>),

    // Relates to input for PBPhase2.
    // sigma1(left) for PB1 output and sigma2(right) for PB2 output.
    Sigma(Option<threshold_crypto::Signature>, Option<threshold_crypto::Signature>),
}

// Two PB phase under SPB.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum PBPhase {
    Phase1,
    Phase2,
}

impl fmt::Display for PBPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Phase1 => write!(f, "PBPhase1"),
            Self::Phase2 => write!(f, "PBPhase2"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ConsensusMessage {
    Val(Block),
    Echo(Echo),
    Finish(Finish),
    Done(Done),
    Halt(Block),
    RandomnessShare(RandomnessShare),
    RandomCoin(RandomCoin),
    PreVote(PreVote),
    Vote(Vote),
}

impl fmt::Display for ConsensusMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, 
            "ConsensusMessage {{ {} }}",
            match &self {
                ConsensusMessage::Val(_) => "VAL",
                ConsensusMessage::Echo(_) => "ECHO",
                ConsensusMessage::Finish(_) => "FINISH",
                ConsensusMessage::Done(_) => "DONE",
                ConsensusMessage::Halt(_) => "HALT",
                ConsensusMessage::RandomnessShare(_) => "RANDOMNESS_SHARE",
                ConsensusMessage::RandomCoin(_) => "RANDOM_COIN",
                ConsensusMessage::PreVote(_) => "PREVOTE",
                ConsensusMessage::Vote(_) => "VOTE",
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

    // According to proof, we can tell which PBPhase this block is currently in.
    pub proof: Proof,
}

impl Block {
    pub async fn new(
        payload: Vec<Digest>, 
        author: PublicKey,
        epoch: EpochNumber,
        view: ViewNumber,
        proof: Proof,
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
        // Use the digest of block used to be sent during PBPhase1.
        let mut mocked = self.clone(); 
        mocked.proof = Proof::Pi(Vec::new());
        self.signature.verify(&mocked.digest(), &self.author)?;

        Ok(())
    }

    pub fn check_sigma1(&self, pk: &threshold_crypto::PublicKey) -> bool {
        if let Proof::Sigma(Some(sigma1), _) = &self.proof {
            // To verify sigma1 we should use digest of block of PBPhase1's state.
            let mut mocked = self.clone();
            mocked.proof = Proof::Pi(Vec::new());
            return pk.verify(&sigma1, mocked.digest())
        }
        false
    }

    pub fn check_sigma2(&self, pk: &threshold_crypto::PublicKey) -> bool {
        if let Proof::Sigma(_, Some(sigma2)) = &self.proof {
            return pk.verify(&sigma2, self.digest())
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
            Proof::Pi(_) => &[0],
            Proof::Sigma(_, _) => &[1],
        });
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B(author {}, epoch {}, view {}, PBPhase {}, payload_len {}",
            self.digest(),
            self.author,
            self.epoch,
            self.view,
            match self.proof {
                Proof::Pi(_) => "1",
                Proof::Sigma(_, _) => "2",
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
pub struct Echo {
    // Block info.
    pub block_digest: Digest,
    pub block_author: PublicKey,
    pub phase: PBPhase,

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
        phase: PBPhase, 
        epoch: EpochNumber,
        view: ViewNumber,
        author: PublicKey,
        mut signature_service: SignatureService
    ) -> Self {
        let signature_share = signature_service.request_tss_signature(block_digest.clone()).await.unwrap();
        Self {
            block_digest,
            block_author,
            phase,
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
        leader: PublicKey, 
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
            self.block_author == leader,
            ConsensusError::WrongLeader {
                digest: self.block_digest.clone(),
                leader: self.block_author,
                author: leader,
                epoch: self.epoch,
                view: self.view,
            }
        );

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
            "Echo(author {}, block_author {}, epoch {}, view {}, PBPhase {})", 
            self.author,
            self.block_author,
            self.epoch,
            self.view,
            self.phase,
        )
    }
}

impl Hash for Echo {
    fn digest(&self) -> Digest {
        // Echo is distinguished by <block_author, epoch, view, phase, ECHO>,
        digest!(
            self.block_author.0,
            self.epoch.to_le_bytes(),
            self.view.to_le_bytes(),
            match self.phase {
                PBPhase::Phase1 => &[0],
                PBPhase::Phase2 => &[1],
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

#[derive(Serialize, Deserialize, Clone)]
pub struct Done {
    pub epoch: EpochNumber,
    pub view: ViewNumber,
    pub author: PublicKey,
}

impl Done {
    pub fn verify(
        &self,
        halt_mark: EpochNumber, 
        epochs_halted: &HashSet<EpochNumber>
    ) -> ConsensusResult<()> {
        // Check for epoch.
        ensure!(
            self.epoch > halt_mark && !epochs_halted.contains(&self.epoch),
            ConsensusError::MessageWithHaltedEpoch(self.epoch, halt_mark+1)
        );
        Ok(())
    }
}

impl Hash for Done {
    fn digest(&self) -> Digest {
        // Done is distinguished by <epoch, view, Done>,
        digest!(
            self.epoch.to_le_bytes(),
            self.view.to_le_bytes(),
            "DONE"
        )
    }
}

impl fmt::Debug for Done {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Done (author {}, epoch {}, view {})", self.author, self.epoch, self.view)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RandomnessShare {
    pub epoch: EpochNumber, // eopch
    pub view: ViewNumber, // view
    pub author: PublicKey,
    pub signature_share: SignatureShare,
}

impl RandomnessShare {
    pub async fn new(
        epoch: EpochNumber,
        view: ViewNumber,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let digest = digest!(epoch.to_le_bytes(), view.to_le_bytes(), "RANDOMNESS_SHARE");
        let signature_share = signature_service.request_tss_signature(digest).await.unwrap();
        Self {
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
        let share = pk_set.public_key_share(committee.id(self.author));
        // Check the signature.
        ensure!(
            share.verify(&self.signature_share, &self.digest()),
            ConsensusError::InvalidSignatureShare(self.author)
        );

        Ok(())
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
        write!(f, "RandomnessShare (author {}, epoch {}, view {})", self.author, self.epoch, self.view)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct RandomCoin {
    pub epoch: EpochNumber, // epoch
    pub view: ViewNumber, // view
    pub leader: PublicKey,  // elected leader of the view
    pub shares: Vec<RandomnessShare>,
}

impl RandomCoin {
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

        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for share in self.shares.iter() {
            let name = share.author;
            ensure!(!used.contains(&name), ConsensusError::AuthorityReuseinCoin(name));
            let voting_rights = committee.stake(&name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(name));
            used.insert(name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.random_coin_threshold(),
            ConsensusError::RandomCoinRequiresQuorum
        );

        let mut sigs = BTreeMap::new();
        // Check the random shares.
        for share in &self.shares {
            share.verify(committee, pk_set, halt_mark, epochs_halted)?;
            sigs.insert(committee.id(share.author), share.signature_share.clone());
        }
        if let Ok(sig) = pk_set.combine_signatures(sigs.iter()) {
            let id = usize::from_be_bytes((&sig.to_bytes()[0..8]).try_into().unwrap()) % committee.size();
            let mut keys: Vec<_> = committee.authorities.keys().cloned().collect();
            keys.sort();
            let leader = keys[id];
            ensure!(leader == self.leader, ConsensusError::RandomCoinWithWrongLeader);
        } else {
            ensure!(true, ConsensusError::RandomCoinWithWrongShares);
        }

        Ok(())
    }
}

impl fmt::Debug for RandomCoin {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "RandomCoin(epoch {}, view {}, leader {})", self.epoch, self.view, self.leader)
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
        committee: 
        &Committee, 
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
        write!(f, "PreVote (author {}, epoch {}, view {}, leader {}, body {})", 
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
        write!(f, "Vote (author {}, epoch {}, view {}, leader {}, body {})", 
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
