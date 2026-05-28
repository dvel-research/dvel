use crate::event::{Hash, PublicKey, Signature};
use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::{ExpandedSecretKey, PublicKey as DalekPublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MANIFEST_MAGIC: &str = "dvel-manifest-v1";

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    InvalidManifest(String),
    SignatureMissing,
    SignatureInvalid,
    HashMismatch { index: usize },
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::Io(err)
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "io error: {}", e),
            StorageError::InvalidManifest(msg) => write!(f, "invalid manifest: {}", msg),
            StorageError::SignatureMissing => write!(f, "signature missing"),
            StorageError::SignatureInvalid => write!(f, "signature invalid"),
            StorageError::HashMismatch { index } => {
                write!(f, "chunk {} hash mismatch", index)
            }
        }
    }
}

impl std::error::Error for StorageError {}

#[derive(Debug, Clone)]
pub struct ChunkMeta {
    pub hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub version: u8,
    pub file_name: String,
    pub total_size: u64,
    pub chunk_size: u64,
    pub chunks: Vec<ChunkMeta>,
    pub signer: Option<PublicKey>,
    pub signature: Option<Signature>,
}

impl Manifest {
    fn canonical_string(&self) -> String {
        let mut out = String::new();
        out.push_str(MANIFEST_MAGIC);
        out.push('\n');
        out.push_str(&format!("file_name:{}\n", self.file_name));
        out.push_str(&format!("total_size:{}\n", self.total_size));
        out.push_str(&format!("chunk_size:{}\n", self.chunk_size));
        out.push_str(&format!("chunks:{}\n", self.chunks.len()));
        for c in &self.chunks {
            out.push_str("h:");
            out.push_str(&hex::encode(c.hash));
            out.push('\n');
        }
        out
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_string().into_bytes()
    }

    /// Hash of the canonical (unsigned) manifest bytes.
    pub fn hash(&self) -> Hash {
        sha256_bytes(&self.canonical_bytes())
    }

    /// Merkle root over chunk hashes (lexicographically sorted, pairwise SHA256 fold).
    pub fn chunk_merkle_root(&self) -> Option<Hash> {
        merkle_root(&self.chunks.iter().map(|c| c.hash).collect::<Vec<_>>())
    }

    pub fn to_string_with_signature(&self) -> String {
        let mut out = self.canonical_string();
        if let Some(signer) = &self.signer {
            out.push_str("signer:");
            out.push_str(&hex::encode(signer));
            out.push('\n');
        }
        if let Some(sig) = &self.signature {
            out.push_str("signature:");
            out.push_str(&hex::encode(sig));
            out.push('\n');
        }
        out
    }
}

fn chunk_filename(file_name: &str, index: usize) -> String {
    format!("{}.chunk.{:08}", file_name, index)
}

pub fn manifest_path(dir: &Path, file_name: &str) -> PathBuf {
    dir.join(format!("{}.manifest", file_name))
}

pub fn chunk_path(dir: &Path, file_name: &str, index: usize) -> PathBuf {
    dir.join(chunk_filename(file_name, index))
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    out
}

fn merkle_root(leaves: &[Hash]) -> Option<Hash> {
    if leaves.is_empty() {
        return None;
    }
    let mut level: Vec<Hash> = {
        let mut v = leaves.to_vec();
        v.sort();
        v
    };
    while level.len() > 1 {
        let mut next: Vec<Hash> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let a = level[i];
            let b = if i + 1 < level.len() {
                level[i + 1]
            } else {
                level[i]
            };
            let mut hasher = Sha256::new();
            hasher.update(a);
            hasher.update(b);
            let h: Hash = hasher.finalize().into();
            next.push(h);
            i += 2;
        }
        level = next;
    }
    level.first().copied()
}

fn hex_to_array<const N: usize>(hex_str: &str) -> Result<[u8; N], StorageError> {
    let bytes =
        hex::decode(hex_str).map_err(|_| StorageError::InvalidManifest("bad hex".into()))?;
    if bytes.len() != N {
        return Err(StorageError::InvalidManifest("length mismatch".into()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn chunk_file_to_dir(
    input: &Path,
    out_dir: &Path,
    chunk_size: usize,
) -> Result<Manifest, StorageError> {
    if chunk_size == 0 {
        return Err(StorageError::InvalidManifest(
            "chunk_size must be > 0".into(),
        ));
    }
    fs::create_dir_all(out_dir)?;
    let file_name = input
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| StorageError::InvalidManifest("invalid file name".into()))?
        .to_string();

    let mut f = File::open(input)?;
    let mut buf = vec![0u8; chunk_size];
    let mut chunks = Vec::new();
    let mut idx: usize = 0;
    let mut total: u64 = 0;

    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let data = &buf[..n];
        total = total.saturating_add(n as u64);
        let hash = sha256_bytes(data);
        let chunk_path = chunk_path(out_dir, &file_name, idx);
        let mut out = File::create(chunk_path)?;
        out.write_all(data)?;
        chunks.push(ChunkMeta { hash });
        idx += 1;
    }

    Ok(Manifest {
        version: 1,
        file_name,
        total_size: total,
        chunk_size: chunk_size as u64,
        chunks,
        signer: None,
        signature: None,
    })
}

pub fn write_manifest(manifest: &Manifest, path: &Path) -> Result<(), StorageError> {
    fs::write(path, manifest.to_string_with_signature())?;
    Ok(())
}

pub fn read_manifest(path: &Path) -> Result<Manifest, StorageError> {
    let text = fs::read_to_string(path)?;
    let mut file_name: Option<String> = None;
    let mut total_size: Option<u64> = None;
    let mut chunk_size: Option<u64> = None;
    let mut chunks: Vec<ChunkMeta> = Vec::new();
    let mut signer: Option<PublicKey> = None;
    let mut signature: Option<Signature> = None;
    let mut declared_chunks: Option<usize> = None;

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if line == MANIFEST_MAGIC {
            continue;
        }
        if let Some(rest) = line.strip_prefix("file_name:") {
            file_name = Some(rest.to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix("total_size:") {
            total_size = rest.parse::<u64>().ok();
            continue;
        }
        if let Some(rest) = line.strip_prefix("chunk_size:") {
            chunk_size = rest.parse::<u64>().ok();
            continue;
        }
        if let Some(rest) = line.strip_prefix("chunks:") {
            declared_chunks = rest.parse::<usize>().ok();
            continue;
        }
        if let Some(rest) = line.strip_prefix("h:") {
            let hash = hex_to_array::<32>(rest)?;
            chunks.push(ChunkMeta { hash });
            continue;
        }
        if let Some(rest) = line.strip_prefix("signer:") {
            signer = Some(hex_to_array::<32>(rest)?);
            continue;
        }
        if let Some(rest) = line.strip_prefix("signature:") {
            signature = Some(hex_to_array::<64>(rest)?);
            continue;
        }
        return Err(StorageError::InvalidManifest("unknown line".into()));
    }

    let fname =
        file_name.ok_or_else(|| StorageError::InvalidManifest("missing file_name".into()))?;
    let ts =
        total_size.ok_or_else(|| StorageError::InvalidManifest("missing total_size".into()))?;
    let cs =
        chunk_size.ok_or_else(|| StorageError::InvalidManifest("missing chunk_size".into()))?;

    if let Some(n) = declared_chunks
        && n != chunks.len()
    {
        return Err(StorageError::InvalidManifest("chunk count mismatch".into()));
    }

    Ok(Manifest {
        version: 1,
        file_name: fname,
        total_size: ts,
        chunk_size: cs,
        chunks,
        signer,
        signature,
    })
}

pub fn sign_manifest_inplace(
    manifest: &mut Manifest,
    secret_key: &[u8; 32],
) -> Result<(), StorageError> {
    let sk = SecretKey::from_bytes(secret_key).map_err(|_| StorageError::SignatureInvalid)?;
    let pk: DalekPublicKey = (&sk).into();
    let esk = ExpandedSecretKey::from(&sk);
    let sig = esk.sign(&manifest.canonical_bytes(), &pk);

    manifest.signer = Some(pk.to_bytes());
    manifest.signature = Some(sig.to_bytes());
    Ok(())
}

pub fn verify_manifest_signature(manifest: &Manifest) -> Result<(), StorageError> {
    let signer = manifest.signer.ok_or(StorageError::SignatureMissing)?;
    let sig_bytes = manifest.signature.ok_or(StorageError::SignatureMissing)?;

    let pk = DalekPublicKey::from_bytes(&signer).map_err(|_| StorageError::SignatureInvalid)?;
    let sig = DalekSignature::from_bytes(&sig_bytes).map_err(|_| StorageError::SignatureInvalid)?;
    pk.verify_strict(&manifest.canonical_bytes(), &sig)
        .map_err(|_| StorageError::SignatureInvalid)
}

pub fn verify_chunks(manifest: &Manifest, chunk_dir: &Path) -> Result<(), StorageError> {
    let mut total: u64 = 0;
    for (idx, meta) in manifest.chunks.iter().enumerate() {
        let p = chunk_path(chunk_dir, &manifest.file_name, idx);
        let data = fs::read(&p)?;
        let hash = sha256_bytes(&data);
        total = total.saturating_add(data.len() as u64);
        if hash != meta.hash {
            return Err(StorageError::HashMismatch { index: idx });
        }
    }
    if total != manifest.total_size {
        return Err(StorageError::InvalidManifest("total_size mismatch".into()));
    }
    Ok(())
}

pub fn reassemble(
    manifest: &Manifest,
    chunk_dir: &Path,
    output: &Path,
) -> Result<(), StorageError> {
    let mut out = File::create(output)?;
    for idx in 0..manifest.chunks.len() {
        let p = chunk_path(chunk_dir, &manifest.file_name, idx);
        let mut f = File::open(&p)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        let hash = sha256_bytes(&buf);
        if hash != manifest.chunks[idx].hash {
            return Err(StorageError::HashMismatch { index: idx });
        }
        out.write_all(&buf)?;
    }
    Ok(())
}

pub fn manifest_hash_from_file(manifest_path: &Path) -> Result<Hash, StorageError> {
    let m = read_manifest(manifest_path)?;
    Ok(m.hash())
}

pub fn chunk_merkle_root_from_file(manifest_path: &Path) -> Result<Option<Hash>, StorageError> {
    let m = read_manifest(manifest_path)?;
    Ok(m.chunk_merkle_root())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn chunk_sign_verify_round_trip() -> Result<(), StorageError> {
        let dir = tempdir().unwrap();
        let input_path = dir.path().join("sample.bin");
        let data = sample_bytes(32 * 1024 + 123);
        fs::write(&input_path, &data)?;

        let mut manifest = chunk_file_to_dir(&input_path, dir.path(), 1024)?;
        let secret = [7u8; 32];
        sign_manifest_inplace(&mut manifest, &secret)?;

        let mpath = manifest_path(dir.path(), &manifest.file_name);
        write_manifest(&manifest, &mpath)?;

        let loaded = read_manifest(&mpath)?;
        verify_manifest_signature(&loaded)?;
        verify_chunks(&loaded, dir.path())?;

        let out_path = dir.path().join("rebuilt.bin");
        reassemble(&loaded, dir.path(), &out_path)?;
        let rebuilt = fs::read(out_path)?;
        assert_eq!(rebuilt, data);
        Ok(())
    }

    #[test]
    fn manifest_and_chunk_roots_match_helpers() -> Result<(), StorageError> {
        let dir = tempdir().unwrap();
        let input_path = dir.path().join("sample.bin");
        fs::write(&input_path, sample_bytes(10_000))?;

        let manifest = chunk_file_to_dir(&input_path, dir.path(), 2048)?;
        let mpath = manifest_path(dir.path(), &manifest.file_name);
        write_manifest(&manifest, &mpath)?;

        // manifest hash via struct vs file helper
        let h_struct = manifest.hash();
        let h_file = manifest_hash_from_file(&mpath)?;
        assert_eq!(h_struct, h_file);

        // chunk Merkle root (present because there are chunks)
        let c_struct = manifest.chunk_merkle_root().expect("root");
        let c_file = chunk_merkle_root_from_file(&mpath)?.expect("root file");
        assert_eq!(c_struct, c_file);

        // corrupt manifest should change hash
        fs::write(&mpath, "corrupt")?;
        match manifest_hash_from_file(&mpath) {
            Err(StorageError::InvalidManifest(_)) => {}
            other => panic!("expected invalid manifest, got {:?}", other),
        }
        Ok(())
    }

    #[test]
    fn detect_corrupt_chunk() -> Result<(), StorageError> {
        let dir = tempdir().unwrap();
        let input_path = dir.path().join("sample.bin");
        fs::write(&input_path, sample_bytes(4096))?;

        let manifest = chunk_file_to_dir(&input_path, dir.path(), 512)?;
        let first_chunk = chunk_path(dir.path(), &manifest.file_name, 0);
        let mut c0 = fs::read(&first_chunk)?;
        c0[0] ^= 0xFF;
        fs::write(&first_chunk, &c0)?;

        match verify_chunks(&manifest, dir.path()) {
            Err(StorageError::HashMismatch { index }) => assert_eq!(index, 0),
            _ => panic!("expected HashMismatch on chunk 0"),
        }
        Ok(())
    }
}
