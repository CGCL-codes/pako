use crate::SeqNumber;

pub struct Block {
    pub payload: Vec<Digest>,
    pub author: PublicKey,
    pub view: SeqNumber,
    pub signature: Signature,
    pub proof: Proof,
}