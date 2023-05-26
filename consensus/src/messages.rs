use crate::Consensus;
use crate::config::Committee;
use crate::error::{ConsensusError, ConsensusResult};
use crypto::{Digest, Signature, SignatureService, Hash, PublicKey};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, BTreeMap};
use std::convert::TryInto;
use std::{fmt, hash};
use threshold_crypto::{SignatureShare, PublicKeySet, PublicKeyShare};

pub type SeqNumber = u128;
pub type ViewNumber = u8;

// Two types of proof associated with block
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Proof {
    // Relates to input for Phase1 (see PBPhase defined below).
    Pi(Vec<(bool, ViewNumber, threshold_crypto::Signature)>),

    // Relates to input for Phase2.
    // sigma1(left) for PB1 output and sigma2(right) for PB2 output.
    Sigma(Option<threshold_crypto::Signature>, Option<threshold_crypto::Signature>),
}

// Two PB phase under SPB.
#[derive(Serialize, Deserialize, Clone)]
pub enum PBPhase {
    Phase1,
    Phase2,
}

impl AsRef<[u8]> for PBPhase {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Phase1 => &[0],
            Self::Phase2 => &[1],
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ConsensusMessage {
    Propose(Block),
    Val(Block),
    Echo(Echo),
    Lock(Lock),
    Finish(Finish),
    Done(Done),
    Halt(Block),    // Need to compare leader of round <epoch, view> with the block leader.
    RandomnessShare(RandomnessShare),
    RandomCoin(RandomCoin),
    PreVote(PreVote),
    Vote(Vote),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Block {
    pub payload: Vec<Digest>,
    pub author: PublicKey,
    pub signature: Signature,
    pub epoch: SeqNumber,
    pub view: ViewNumber,

    // According to proof, we can tell which PBPhase this block is currently in.
    pub proof: Proof,
}

impl Block {
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
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

    pub fn check_sigma1(&self, external_publickey: &PublicKeyShare) -> ConsensusResult<()> {

    }

    pub fn check_sigma2(&self, external_publickey: &PublicKeyShare) ->  ConsensusResult<()> {

    }
}

impl Hash for Block {
    // Form a complete digest of the block,
    // denote as <ID, R, l, 1 or 2> in original paper,
    // where ID is the identifier of current MVBA instance, here we
    // use epoch. R equals view number, l corresponds to the leader
    // of the SPB instance, 1 or 2 indicates PB phase 1 or 2.
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.view.to_le_bytes());

        for x in &self.payload {
            hasher.update(x);
        }

        match self.proof {
            Proof::Pi(_) => hasher.update(&[0]),
            Proof::Sigma(_, _) => hasher.update(&[1]),
        };

        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B(author {}, epoch {}, view {}, payload_len {}",
            self.digest(),
            self.author,
            self.epoch,
            self.view,
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
    pub phase: PBPhase,

    // Echo author.
    pub author: PublicKey,

    // Signature share against block digest.
    pub signature_share: SignatureShare,
}

impl Echo {
    pub async fn new(block_digest: Digest, 
        phase: PBPhase, 
        author: PublicKey,
        mut signature_service: SignatureService
    ) -> Self {
        let signature_share = signature_service.request_tss_signature(block_digest.clone()).await.unwrap();
        Self {
            block_digest,
            phase,
            author,
            signature_share,
        }
    }
    pub fn verify(&self, committee: &Committee, pk_set: &PublicKeySet) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        let tss_pk = pk_set.public_key_share(committee.id(self.author));
        // Check the signature.
        ensure!(
            tss_pk.verify(&self.signature_share, &self.digest()),
            ConsensusError::InvalidThresholdSignature(self.author)
        )
    }
}

impl fmt::Debug for Echo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        // write!(
        //     f, 
        //     "Echo(author {}, block_author {}, epoch {}, view {}, phase {})", 
        //     self.author,
        //     self.block_author,
        //     self.epoch,
        //     self.view,
        //     self.phase,
        // )
        todo!()
    }
}

impl Hash for Echo {
    fn digest(&self) -> Digest {
        // Echo is distinguished by <epoch, view, phase, ECHO>,
        // which can be implemented by <block_digest, ECHO>.
        let mut hasher = Sha512::new();
        hasher.update(self.block_digest);
        hasher.update("ECHO");

        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Lock {
    // Block digest with PB phase.
    pub digest: Digest,
    pub phase: PBPhase,

    // Threshold signature combined by PB leader.
    pub signature: threshold_crypto::Signature,
}

impl fmt::Debug for Lock{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        todo!()
    }
}

impl Hash for Lock {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        todo!()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Finish {
    pub block: Block,
    pub author: PublicKey,
}

impl Hash for Finish {
    fn digest(&self) -> Digest {
        // Finish is distinguished by <epoch, view, FINISH>,
        let mut hasher = Sha512::new();
        hasher.update(self.block.epoch.to_le_bytes());
        hasher.update(self.block.view.to_le_bytes());
        hasher.update("FINISH");

        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Done {
    pub block_digest: Digest,
    pub author: PublicKey,
}

impl Hash for Done {
    fn digest(&self) -> Digest {
        // Finish is distinguished by <epoch, view, Done>,
        // which can be implemented by <block_digest, Done>.
        let mut hasher = Sha512::new();
        hasher.update(self.block_digest);
        hasher.update("FINISH");

        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RandomnessShare {
    pub epoch: SeqNumber, // eopch
    pub view: ViewNumber, // view
    pub author: PublicKey,
    pub signature_share: SignatureShare,
}

impl RandomnessShare {
    pub async fn new(
        epoch: SeqNumber,
        view: ViewNumber,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(epoch.to_le_bytes());
        hasher.update(view.to_le_bytes());
        let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
        let signature_share = signature_service.request_tss_signature(digest).await.unwrap();
        Self {
            epoch,
            view,
            author,
            signature_share,
        }
    }

    pub fn verify(&self, committee: &Committee, pk_set: &PublicKeySet) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        let tss_pk = pk_set.public_key_share(committee.id(self.author));
        // Check the signature.
        ensure!(
            tss_pk.verify(&self.signature_share, &self.digest()),
            ConsensusError::InvalidThresholdSignature(self.author)
        );

        Ok(())
    }
}

impl Hash for RandomnessShare {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.view.to_le_bytes());
        hasher.update("RANDOMNESS_SHARE");
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for RandomnessShare {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "RandomnessShare (author {}, view {}, sig share {:?})", self.author, self.view, self.signature_share)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct RandomCoin {
    pub epoch: SeqNumber, // epoch
    pub view: ViewNumber, // view
    pub leader: PublicKey,  // elected leader of the view
    pub shares: Vec<RandomnessShare>,
}

impl RandomCoin {
    pub fn verify(&self, committee: &Committee,  pk_set: &PublicKeySet) -> ConsensusResult<()> {
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
            share.verify(committee, pk_set)?;
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
        write!(f, "RandomCoin(view {}, leader {})", self.view, self.leader)
    }
}

impl Hash for RandomCoin {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.view.to_le_bytes());
        hasher.update("RANDOM_COIN");
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum PreVote {
    Yes(Block),
    No(SignatureShare),
}

#[derive(Serialize, Deserialize, Clone)]
pub enum Vote {
    Yes(Block, SignatureShare),
    No(threshold_crypto::Signature, SignatureShare),
}
