pub enum ConsensusMessage {
    SPB(Block),
    Finish(Finish),
    RandomnessShare(RandomnessShare),
    RandomCoin(RandomCoin),
    PreVote(PreVote),
    Vote(Vote),
}

pub struct Consensus;