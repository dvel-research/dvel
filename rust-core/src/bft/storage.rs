use crate::bft::slashing::SlashingState;
use crate::bft::types::Block;
use crate::event::Hash;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedSnapshot {
    pub height: u64,
    pub tip_hash: Hash,
    pub blocks: Vec<Block>,
    pub slashing_state: Option<SlashingState>,
}

pub struct SnapshotStore {
    path: PathBuf,
}

impl SnapshotStore {
    pub fn new<P: AsRef<Path>>(data_dir: P) -> Result<Self, String> {
        fs::create_dir_all(&data_dir).map_err(|e| format!("{}", e))?;
        Ok(Self {
            path: data_dir.as_ref().join("bft_snapshot.json"),
        })
    }

    pub fn load(&self) -> Result<Option<PersistedSnapshot>, String> {
        if !self.path.exists() {
            return Ok(None);
        }
        let data = fs::read(&self.path).map_err(|e| format!("{}", e))?;
        let snap = serde_json::from_slice::<PersistedSnapshot>(&data)
            .map_err(|e| format!("{}", e))?;
        Ok(Some(snap))
    }

    pub fn save(&self, snapshot: &PersistedSnapshot) -> Result<(), String> {
        let data = serde_json::to_vec_pretty(snapshot).map_err(|e| format!("{}", e))?;
        let tmp_path = self.path.with_extension("json.tmp");
        fs::write(&tmp_path, data).map_err(|e| format!("{}", e))?;
        fs::rename(&tmp_path, &self.path).map_err(|e| format!("{}", e))?;
        Ok(())
    }
}
