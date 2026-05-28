use crate::event::Hash;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MmrNode {
    pub hash: Hash,
    pub left: Option<usize>,
    pub right: Option<usize>,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Mmr {
    pub nodes: Vec<MmrNode>,
    pub leaves: Vec<usize>, // Store node index in `nodes` for each leaf
    pub parents: Vec<Option<usize>>, // parents[node_idx] = Some(parent_idx)
    pub peaks: Vec<(usize, usize)>, // (node_index, tree_height)
    pub leaf_count: u64,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MmrProof {
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub siblings: Vec<(Hash, bool)>, // (Hash, is_right_sibling)
    pub peaks: Vec<Hash>,            // Active peak hashes in order
}

pub fn merge_hashes(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    out
}

impl Default for Mmr {
    fn default() -> Self {
        Self::new()
    }
}

impl Mmr {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            leaves: Vec::new(),
            parents: Vec::new(),
            peaks: Vec::new(),
            leaf_count: 0,
        }
    }

    pub fn append(&mut self, leaf_hash: Hash) {
        let leaf_idx = self.nodes.len();
        self.nodes.push(MmrNode {
            hash: leaf_hash,
            left: None,
            right: None,
        });
        self.leaves.push(leaf_idx);

        if self.parents.len() <= leaf_idx {
            self.parents.resize(leaf_idx + 1, None);
        }

        let mut carry = (leaf_idx, 0); // (node_index, height)

        loop {
            if let Some(&(last_idx, _)) = self.peaks.last().filter(|&&(_, h)| h == carry.1) {
                self.peaks.pop();

                let left_child = last_idx;
                let right_child = carry.0;

                let parent_hash =
                    merge_hashes(&self.nodes[left_child].hash, &self.nodes[right_child].hash);
                let parent_idx = self.nodes.len();

                self.nodes.push(MmrNode {
                    hash: parent_hash,
                    left: Some(left_child),
                    right: Some(right_child),
                });

                if self.parents.len() <= parent_idx {
                    self.parents.resize(parent_idx + 1, None);
                }
                self.parents[left_child] = Some(parent_idx);
                self.parents[right_child] = Some(parent_idx);

                carry = (parent_idx, carry.1 + 1);
                continue;
            }

            self.peaks.push(carry);
            break;
        }

        self.leaf_count += 1;
    }

    pub fn get_root(&self) -> Option<Hash> {
        if self.peaks.is_empty() {
            return None;
        }
        let mut active_peaks: Vec<Hash> = self
            .peaks
            .iter()
            .map(|&(idx, _)| self.nodes[idx].hash)
            .collect();
        let mut root = active_peaks.pop().unwrap();
        while let Some(peak) = active_peaks.pop() {
            root = merge_hashes(&peak, &root);
        }
        Some(root)
    }

    pub fn gen_proof(&self, leaf_index: u64) -> Option<MmrProof> {
        if leaf_index >= self.leaf_count {
            return None;
        }

        let leaf_node_idx = self.leaves[leaf_index as usize];
        let mut siblings = Vec::new();
        let mut curr = leaf_node_idx;

        while let Some(parent_idx) = self.parents.get(curr).copied().flatten() {
            let parent_node = &self.nodes[parent_idx];
            let left_idx = parent_node.left.unwrap();
            let right_idx = parent_node.right.unwrap();

            if left_idx == curr {
                siblings.push((self.nodes[right_idx].hash, true)); // Right sibling
            } else {
                siblings.push((self.nodes[left_idx].hash, false)); // Left sibling
            }
            curr = parent_idx;
        }

        let peaks: Vec<Hash> = self
            .peaks
            .iter()
            .map(|&(idx, _)| self.nodes[idx].hash)
            .collect();

        Some(MmrProof {
            leaf_index,
            leaf_count: self.leaf_count,
            siblings,
            peaks,
        })
    }
}

impl MmrProof {
    pub fn verify(&self, trusted_root: &Hash, leaf_hash: &Hash) -> bool {
        let mut curr = *leaf_hash;
        for &(sibling_hash, is_right) in &self.siblings {
            if is_right {
                curr = merge_hashes(&curr, &sibling_hash);
            } else {
                curr = merge_hashes(&sibling_hash, &curr);
            }
        }

        if !self.peaks.contains(&curr) {
            return false;
        }

        let mut active_peaks = self.peaks.clone();
        let mut root = match active_peaks.pop() {
            Some(r) => r,
            None => return false,
        };
        while let Some(peak) = active_peaks.pop() {
            root = merge_hashes(&peak, &root);
        }

        root == *trusted_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hash(val: u8) -> Hash {
        let mut h = [0u8; 32];
        h[0] = val;
        h
    }

    #[test]
    fn mmr_single_leaf() {
        let mut mmr = Mmr::new();
        let leaf = dummy_hash(1);
        mmr.append(leaf);
        assert_eq!(mmr.leaf_count, 1);
        assert_eq!(mmr.get_root(), Some(leaf));

        let proof = mmr.gen_proof(0).unwrap();
        assert_eq!(proof.siblings.len(), 0);
        assert!(proof.verify(&mmr.get_root().unwrap(), &leaf));
    }

    #[test]
    fn mmr_multi_leaf_round_trip() {
        let mut mmr = Mmr::new();
        let num_leaves = 100;
        let mut leaf_hashes = Vec::new();

        for i in 0..num_leaves {
            let h = dummy_hash(i as u8);
            mmr.append(h);
            leaf_hashes.push(h);
        }

        assert_eq!(mmr.leaf_count, num_leaves as u64);
        let root = mmr.get_root().unwrap();

        for (i, leaf_hash) in leaf_hashes.iter().enumerate() {
            let proof = mmr.gen_proof(i as u64).expect("proof");
            assert!(proof.verify(&root, leaf_hash));

            // Fails with corrupted leaf hash
            let bad_leaf = dummy_hash(255);
            assert!(!proof.verify(&root, &bad_leaf));

            // Fails with corrupted root
            let bad_root = dummy_hash(254);
            assert!(!proof.verify(&bad_root, leaf_hash));
        }
    }
}
