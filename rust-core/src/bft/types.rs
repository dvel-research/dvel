use crate::event::{Hash, PublicKey, ZERO_HASH};
use sha2::{Digest, Sha256};

#[cfg(feature = "bft")]
use serde::{Deserialize, Serialize};

pub type NodeId = [u8; 32];

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct ValidatorInfo {
    pub pubkey: PublicKey,
    pub node_id: NodeId,
    pub address: String,
    pub power: u64,
    pub tls_cert: Option<Vec<u8>>,
}

pub fn node_id_from_pubkey(pubkey: &PublicKey) -> NodeId {
    let mut h = Sha256::new();
    h.update(pubkey);
    h.finalize().into()
}

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteType {
    Prevote,
    Precommit,
}

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct Vote {
    pub height: u64,
    pub round: u64,
    pub vote_type: VoteType,
    pub block_hash: Hash,
    pub validator_id: NodeId,
}

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct SignedVote {
    pub vote: Vote,
    pub signature: String,
}

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct BlockHeader {
    pub height: u64,
    pub round: u64,
    pub prev_block_hash: Hash,
    pub tx_root: Hash,
    pub proposer_id: NodeId,
    pub timestamp_ms: u64,
}

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Vec<u8>>,
}

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct Proposal {
    pub height: u64,
    pub round: u64,
    pub block: Block,
    pub proposer_id: NodeId,
    pub signature: String,
}

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub enum Message {
    Hello {
        node_id: NodeId,
        pubkey: PublicKey,
        signature: String,
    },
    Tx { tx: Vec<u8> },
    Proposal(Proposal),
    Vote(SignedVote),
}

pub fn tx_hash(tx: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(tx);
    h.finalize().into()
}

pub fn merkle_root_hashes(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() {
        return ZERO_HASH;
    }
    let mut level: Vec<Hash> = hashes.to_vec();
    while level.len() > 1 {
        let mut next: Vec<Hash> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let a = level[i];
            let b = if i + 1 < level.len() { level[i + 1] } else { level[i] };
            let mut h = Sha256::new();
            h.update(a);
            h.update(b);
            next.push(h.finalize().into());
            i += 2;
        }
        level = next;
    }
    level[0]
}

pub fn header_bytes(h: &BlockHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 8 + 32 + 32 + 32 + 8);
    out.extend_from_slice(&h.height.to_le_bytes());
    out.extend_from_slice(&h.round.to_le_bytes());
    out.extend_from_slice(&h.prev_block_hash);
    out.extend_from_slice(&h.tx_root);
    out.extend_from_slice(&h.proposer_id);
    out.extend_from_slice(&h.timestamp_ms.to_le_bytes());
    out
}

pub fn block_hash(header: &BlockHeader) -> Hash {
    let mut h = Sha256::new();
    h.update(header_bytes(header));
    h.finalize().into()
}

pub fn vote_bytes(v: &Vote) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 8 + 1 + 32 + 32);
    out.extend_from_slice(&v.height.to_le_bytes());
    out.extend_from_slice(&v.round.to_le_bytes());
    out.push(match v.vote_type {
        VoteType::Prevote => 1,
        VoteType::Precommit => 2,
    });
    out.extend_from_slice(&v.block_hash);
    out.extend_from_slice(&v.validator_id);
    out
}

pub fn proposal_bytes(p: &Proposal) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 8 + 32 + 32);
    out.extend_from_slice(&p.height.to_le_bytes());
    out.extend_from_slice(&p.round.to_le_bytes());
    out.extend_from_slice(&block_hash(&p.block.header));
    out.extend_from_slice(&p.proposer_id);
    out
}
