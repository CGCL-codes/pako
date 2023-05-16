use crate::config::Committee;
use crate::error::{ConsensusError, ConsensusResult};
use crypto::{Digest, Signature, SignatureService, Hash, PublicKey};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, BTreeMap};
use std::convert::TryInto;
use std::fmt;
use threshold_crypto::Signature as ThreshldSig;
use threshold_crypto::{SignatureShare, PublicKeySet};

pub type SeqNumber = u64;
pub type ViewNumber = u8;

pub enum Phase {
    Phase1,
    Phase2
}

pub struct Proof(bool, ViewNumber, ThreshldSig);

pub struct Block {
    pub payload: Vec<Digest>,
    pub author: PublicKey,
    pub epoch: SeqNumber,
    pub view: ViewNumber,
    pub phase: Phase,
    pub signature: Signature,
    pub proof: Option<Proof>,
}

impl Block {
    pub fn verify(&self, committee: &Committee, pk_set: &PublicKeySet) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        Ok(())
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.view.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B(author {}, view {}, epoch {}, payload_len {}",
            self.digest(),
            self.author,
            self.view,
            self.epoch,
            self.payload.iter().map(|x| x.size()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}", self.view)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RandomnessShare {
    pub view: ViewNumber, // view
    pub author: PublicKey,
    pub signature_share: SignatureShare,
}

impl RandomnessShare {
    pub async fn new(
        view: ViewNumber,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(view.to_le_bytes());
        let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
        let signature_share = signature_service.request_tss_signature(digest).await.unwrap();
        Self {
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
        hasher.update(self.view.to_le_bytes());
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