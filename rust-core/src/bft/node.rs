use crate::bft::config::GenesisConfig;
use crate::bft::slashing::SlashingState;
use crate::bft::storage::{PersistedSnapshot, SnapshotStore};
use crate::bft::types::{
    block_hash, merkle_root_hashes, node_id_from_pubkey, proposal_bytes, tx_hash, vote_bytes,
    Block, BlockHeader, Message, NodeId, Proposal, SignedVote, ValidatorInfo, Vote, VoteType,
};
use crate::event::{Event, Hash, PublicKey, ZERO_HASH};
use crate::ledger::Ledger;
use crate::validation::{validate_event, ValidationContext};
use ed25519_dalek::{Keypair, PublicKey as DalekPublicKey, Signature, Signer, Verifier};
use hex::{decode as hex_decode, encode as hex_encode};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustls::{
    Certificate, ClientConfig, ClientConnection, PrivateKey, RootCertStore, ServerConfig,
    ServerConnection, ServerName, StreamOwned,
};
use rustls::server::AllowAnyAuthenticatedClient;

pub struct NodeConfig {
    pub listen_addr: String,
    pub client_addr: String,
    pub data_dir: Option<String>,
}

pub struct TlsIdentity {
    pub cert_chain: Vec<Certificate>,
    pub key: PrivateKey,
}

#[derive(Clone, Debug)]
pub struct NodeSnapshot {
    pub height: u64,
    pub tip_hash: Hash,
    pub blocks_by_height: HashMap<u64, Block>,
    pub blocks_by_hash: HashMap<Hash, Block>,
    pub tx_index: HashMap<Hash, (Hash, u64)>,
    pub slashing_state: Option<SlashingState>,
}

impl NodeSnapshot {
    pub fn new() -> Self {
        Self {
            height: 0,
            tip_hash: ZERO_HASH,
            blocks_by_height: HashMap::new(),
            blocks_by_hash: HashMap::new(),
            tx_index: HashMap::new(),
            slashing_state: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Propose,
    Prevote,
    Precommit,
}

struct RoundState {
    proposal: Option<Proposal>,
    prevotes: HashMap<Hash, HashSet<NodeId>>,
    precommits: HashMap<Hash, HashSet<NodeId>>,
    proposed: bool,
}

impl RoundState {
    fn new() -> Self {
        Self {
            proposal: None,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            proposed: false,
        }
    }
}

struct ValidatorSet {
    validators: Vec<ValidatorInfo>,
    by_id: HashMap<NodeId, ValidatorInfo>,
    quorum_power: u64,
}

impl ValidatorSet {
    fn new(validators: Vec<ValidatorInfo>) -> Self {
        let mut by_id = HashMap::new();
        for v in &validators {
            by_id.insert(v.node_id, v.clone());
        }
        let f = (validators.len().saturating_sub(1)) / 3;
        let quorum = ((2 * f) + 1) as u64;
        Self {
            validators,
            by_id,
            quorum_power: quorum,
        }
    }

    fn proposer_for(&self, height: u64, round: u64) -> &ValidatorInfo {
        let idx = ((height + round) as usize) % self.validators.len();
        &self.validators[idx]
    }

    fn has_validator(&self, node_id: &NodeId) -> bool {
        self.by_id.contains_key(node_id)
    }

    fn pubkey_for(&self, node_id: &NodeId) -> Option<PublicKey> {
        self.by_id.get(node_id).map(|v| v.pubkey)
    }

    fn quorum_met(&self, votes: &HashSet<NodeId>) -> bool {
        let mut power = 0u64;
        for id in votes {
            if let Some(v) = self.by_id.get(id) {
                power = power.saturating_add(v.power);
            }
        }
        power >= self.quorum_power
    }
}

pub enum NodeCommand {
    SubmitTx(Vec<u8>),
    Shutdown,
}

pub struct Node {
    genesis: GenesisConfig,
    validators: ValidatorSet,
    keypair: Arc<Keypair>,
    node_id: NodeId,
    ledger: Ledger,
    vctx_by_author: HashMap<PublicKey, ValidationContext>,
    mempool: VecDeque<Vec<u8>>,
    mempool_bytes: usize,
    height: u64,
    round: u64,
    step: Step,
    round_start: Instant,
    locked: Option<Hash>,
    round_state: RoundState,
    snapshot: Arc<RwLock<NodeSnapshot>>,
    net: Network,
    store: Option<SnapshotStore>,
    slashing_state: SlashingState,
}

struct TlsConfig {
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
}

enum PeerStream {
    Plain(TcpStream),
    TlsServer(StreamOwned<ServerConnection, TcpStream>),
    TlsClient(StreamOwned<ClientConnection, TcpStream>),
}

impl Read for PeerStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            PeerStream::Plain(stream) => stream.read(buf),
            PeerStream::TlsServer(stream) => stream.read(buf),
            PeerStream::TlsClient(stream) => stream.read(buf),
        }
    }
}

impl Write for PeerStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            PeerStream::Plain(stream) => stream.write(buf),
            PeerStream::TlsServer(stream) => stream.write(buf),
            PeerStream::TlsClient(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            PeerStream::Plain(stream) => stream.flush(),
            PeerStream::TlsServer(stream) => stream.flush(),
            PeerStream::TlsClient(stream) => stream.flush(),
        }
    }
}

impl PeerStream {
    fn set_read_timeout(&mut self, dur: Duration) {
        match self {
            PeerStream::Plain(stream) => {
                let _ = stream.set_read_timeout(Some(dur));
            }
            PeerStream::TlsServer(stream) => {
                let _ = stream.get_ref().set_read_timeout(Some(dur));
            }
            PeerStream::TlsClient(stream) => {
                let _ = stream.get_ref().set_read_timeout(Some(dur));
            }
        }
    }
}


impl Node {
    pub fn new(
        genesis: GenesisConfig,
        keypair: Arc<Keypair>,
        cfg: NodeConfig,
        snapshot: Arc<RwLock<NodeSnapshot>>,
        net: Network,
    ) -> Result<Self, String> {
        let validators = ValidatorSet::new(genesis.validator_infos()?);
        let node_id = node_id_from_pubkey(&keypair.public.to_bytes());
        if !validators.has_validator(&node_id) {
            return Err("node key not found in validator set".into());
        }

        let store = match cfg.data_dir {
            Some(dir) => Some(SnapshotStore::new(dir)?),
            None => None,
        };

        // Initialize slashing state with validator stakes
        let validator_infos = genesis.validator_infos()?;
        let mut initial_stakes = HashMap::new();
        for v in &validator_infos {
            initial_stakes.insert(v.node_id, v.stake);
        }
        let slashing_state = SlashingState::new(initial_stakes);

        let mut node = Self {
            genesis,
            validators,
            keypair,
            node_id,
            ledger: Ledger::new(),
            vctx_by_author: HashMap::new(),
            mempool: VecDeque::new(),
            mempool_bytes: 0,
            height: 1,
            round: 0,
            step: Step::Propose,
            round_start: Instant::now(),
            locked: None,
            round_state: RoundState::new(),
            snapshot,
            net,
            store,
            slashing_state: slashing_state.clone(),
        };

        // Initialize slashing_state in snapshot
        if let Ok(mut snap) = node.snapshot.write() {
            snap.slashing_state = Some(slashing_state);
        }

        node.restore_from_store()?;

        Ok(node)
    }

    pub fn run(mut self, rx_net: mpsc::Receiver<Message>, rx_cmd: mpsc::Receiver<NodeCommand>) {
        let mut shutdown = false;
        loop {
            while let Ok(msg) = rx_net.try_recv() {
                self.handle_message(msg);
            }
            while let Ok(cmd) = rx_cmd.try_recv() {
                match cmd {
                    NodeCommand::SubmitTx(tx) => self.submit_tx(tx, true),
                    NodeCommand::Shutdown => {
                        shutdown = true;
                    }
                }
            }

            if shutdown {
                self.net.shutdown();
                break;
            }

            self.maybe_propose();
            self.check_timeouts();
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn submit_tx(&mut self, tx: Vec<u8>, broadcast: bool) {
        if tx.is_empty() {
            return;
        }
        self.mempool_bytes = self.mempool_bytes.saturating_add(tx.len());
        self.mempool.push_back(tx.clone());
        if broadcast {
            self.net.broadcast(Message::Tx { tx });
        }
    }

    fn maybe_propose(&mut self) {
        if self.step != Step::Propose || self.round_state.proposed {
            return;
        }
        let proposer = self.validators.proposer_for(self.height, self.round);
        if proposer.node_id != self.node_id {
            return;
        }
        let block = self.build_block();
        let proposal = self.sign_proposal(block);
        self.round_state.proposed = true;
        self.round_state.proposal = Some(proposal.clone());
        self.net.broadcast(Message::Proposal(proposal.clone()));
        self.handle_proposal(proposal);
    }

    fn build_block(&mut self) -> Block {
        let max_bytes = self.genesis.consensus.max_block_bytes as usize;
        let max_events = self.genesis.consensus.max_events as usize;
        let prev_hash = self
            .snapshot
            .read()
            .map(|s| s.tip_hash)
            .unwrap_or(ZERO_HASH);

        let mut txs = Vec::new();
        let mut total = 0usize;
        for tx in self.mempool.iter() {
            if txs.len() >= max_events {
                break;
            }
            if total + tx.len() > max_bytes {
                break;
            }
            total += tx.len();
            txs.push(tx.clone());
        }

        let tx_hashes: Vec<Hash> = txs.iter().map(|t| tx_hash(t)).collect();
        let tx_root = merkle_root_hashes(&tx_hashes);
        let header = BlockHeader {
            height: self.height,
            round: self.round,
            prev_block_hash: prev_hash,
            tx_root,
            proposer_id: self.node_id,
            timestamp_ms: now_ms(),
        };

        Block { header, txs }
    }

    fn sign_proposal(&self, block: Block) -> Proposal {
        let proposer_id = self.node_id;
        let mut proposal = Proposal {
            height: self.height,
            round: self.round,
            block,
            proposer_id,
            signature: String::new(),
        };
        let sig = self.keypair.sign(&proposal_bytes(&proposal));
        proposal.signature = sig_to_hex(&sig);
        proposal
    }

    fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::Tx { tx } => self.submit_tx(tx, false),
            Message::Proposal(p) => self.handle_proposal(p),
            Message::Vote(v) => self.handle_vote(v),
            Message::Hello { .. } => {}
        }
    }

    fn handle_proposal(&mut self, proposal: Proposal) {
        if proposal.height != self.height || proposal.round != self.round {
            return;
        }

        if !self.verify_proposal(&proposal) {
            return;
        }

        if !self.validate_block(&proposal.block) {
            self.broadcast_vote(VoteType::Prevote, ZERO_HASH);
            self.step = Step::Prevote;
            return;
        }

        self.round_state.proposal = Some(proposal.clone());

        let bh = block_hash(&proposal.block.header);
        if let Some(locked) = self.locked {
            if locked != bh {
                self.broadcast_vote(VoteType::Prevote, ZERO_HASH);
                self.step = Step::Prevote;
                return;
            }
        }

        self.broadcast_vote(VoteType::Prevote, bh);
        self.step = Step::Prevote;
    }

    fn handle_vote(&mut self, signed: SignedVote) {
        if !self.verify_vote(&signed) {
            return;
        }
        let v = &signed.vote;
        if v.height != self.height || v.round != self.round {
            return;
        }

        // Reject votes from jailed validators
        if self.slashing_state.is_jailed(&v.validator_id, self.height) {
            return;
        }

        // Check for double-signing and apply slashing if detected
        if let Some(evidence) = self.slashing_state.record_vote(
            &signed,
            &self.genesis.consensus.slashing,
            self.height,
        ) {
            eprintln!(
                "SLASHING DETECTED: Double-sign by validator {:?} at height {} round {}",
                v.validator_id, v.height, v.round
            );
            
            match self.slashing_state.slash(
                evidence.clone(),
                &self.genesis.consensus.slashing,
                self.height,
            ) {
                Ok(record) => {
                    eprintln!(
                        "Validator slashed: {} stake removed, jailed until height {}",
                        record.slashed_amount, record.jail_until_height
                    );
                    // Update snapshot with slashing state
                    if let Ok(mut snap) = self.snapshot.write() {
                        snap.slashing_state = Some(self.slashing_state.clone());
                    }
                }
                Err(e) => {
                    eprintln!("Slashing failed: {}", e);
                }
            }
        }

        let vote_set = match v.vote_type {
            VoteType::Prevote => &mut self.round_state.prevotes,
            VoteType::Precommit => &mut self.round_state.precommits,
        };

        let entry = vote_set.entry(v.block_hash).or_insert_with(HashSet::new);
        entry.insert(v.validator_id);

        if self.validators.quorum_met(entry) {
            match v.vote_type {
                VoteType::Prevote => {
                    if v.block_hash != ZERO_HASH {
                        self.locked = Some(v.block_hash);
                        self.broadcast_vote(VoteType::Precommit, v.block_hash);
                        self.step = Step::Precommit;
                    }
                }
                VoteType::Precommit => {
                    if v.block_hash != ZERO_HASH {
                        if let Some(block) = self.round_state.proposal.clone().map(|p| p.block) {
                            let bh = block_hash(&block.header);
                            if bh == v.block_hash {
                                if let Err(e) = self.commit_block(block) {
                                    eprintln!("fatal: commit failed: {}", e);
                                    std::process::exit(1);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn commit_block(&mut self, block: Block) -> Result<(), String> {
        self.apply_block(&block)?;
        let bh = block_hash(&block.header);

        let mut persisted: Option<PersistedSnapshot> = None;
        {
            let mut snap = self.snapshot.write().map_err(|_| "snapshot lock".to_string())?;
            snap.height = block.header.height;
            snap.tip_hash = bh;
            snap.blocks_by_height.insert(block.header.height, block.clone());
            snap.blocks_by_hash.insert(bh, block.clone());
            for tx in &block.txs {
                let th = tx_hash(tx);
                snap.tx_index.insert(th, (bh, block.header.height));
            }
            if self.store.is_some() {
                persisted = Some(snapshot_to_persisted(&snap));
            }
        }

        self.height = block.header.height.saturating_add(1);
        self.round = 0;
        self.step = Step::Propose;
        self.round_start = Instant::now();
        self.locked = None;
        self.round_state = RoundState::new();
        self.prune_mempool(&block.txs);
        if let (Some(store), Some(persisted)) = (&self.store, persisted) {
            if let Err(e) = store.save(&persisted) {
                eprintln!("snapshot save failed: {}", e);
            }
        }
        Ok(())
    }

    fn prune_mempool(&mut self, committed: &[Vec<u8>]) {
        if committed.is_empty() {
            return;
        }
        let committed_hashes: HashSet<Hash> =
            committed.iter().map(|t| tx_hash(t)).collect();
        let mut new_pool = VecDeque::new();
        let mut bytes = 0usize;
        while let Some(tx) = self.mempool.pop_front() {
            if !committed_hashes.contains(&tx_hash(&tx)) {
                bytes = bytes.saturating_add(tx.len());
                new_pool.push_back(tx);
            }
        }
        self.mempool = new_pool;
        self.mempool_bytes = bytes;
    }

    fn apply_block(&mut self, block: &Block) -> Result<(), String> {
        let mut vctx = self.vctx_by_author.clone();
        let mut known = self.ledger.hashes_set();

        for tx in &block.txs {
            let ev = decode_event(tx)?;
            let ctx = vctx.entry(ev.author).or_insert_with(ValidationContext::new);
            validate_event(&ev, ctx).map_err(|e| format!("{:?}", e))?;

            let h = Ledger::hash_event(&ev);
            if known.contains(&h) {
                return Err("duplicate event hash in block".into());
            }
            if ev.prev_hash != ZERO_HASH && !known.contains(&ev.prev_hash) {
                return Err("missing parent in block".into());
            }
            known.insert(h);
        }

        // Apply to ledger for real
        for tx in &block.txs {
            let ev = decode_event(tx)?;
            let ctx = self
                .vctx_by_author
                .entry(ev.author)
                .or_insert_with(ValidationContext::new);
            validate_event(&ev, ctx).map_err(|e| format!("{:?}", e))?;
            self.ledger
                .try_add_event(ev)
                .map_err(|e| format!("{:?}", e))?;
        }

        Ok(())
    }

    fn validate_block(&self, block: &Block) -> bool {
        if block.header.height != self.height || block.header.round != self.round {
            return false;
        }
        let tip = self
            .snapshot
            .read()
            .map(|s| s.tip_hash)
            .unwrap_or(ZERO_HASH);
        if block.header.prev_block_hash != tip {
            return false;
        }
        let tx_hashes: Vec<Hash> = block.txs.iter().map(|t| tx_hash(t)).collect();
        let tx_root = merkle_root_hashes(&tx_hashes);
        if tx_root != block.header.tx_root {
            return false;
        }

        let max_bytes = self.genesis.consensus.max_block_bytes as usize;
        let max_events = self.genesis.consensus.max_events as usize;
        let bytes: usize = block.txs.iter().map(|t| t.len()).sum();
        if bytes > max_bytes || block.txs.len() > max_events {
            return false;
        }
        true
    }

    fn verify_proposal(&self, proposal: &Proposal) -> bool {
        let proposer = self.validators.proposer_for(proposal.height, proposal.round);
        if proposer.node_id != proposal.proposer_id {
            return false;
        }
        let pk = match DalekPublicKey::from_bytes(&proposer.pubkey) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let Some(sig) = sig_from_hex(&proposal.signature) else {
            return false;
        };
        pk.verify(&proposal_bytes(proposal), &sig).is_ok()
    }

    fn verify_vote(&self, signed: &SignedVote) -> bool {
        let v = &signed.vote;
        let Some(pk_bytes) = self.validators.pubkey_for(&v.validator_id) else {
            return false;
        };
        let pk = match DalekPublicKey::from_bytes(&pk_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let Some(sig) = sig_from_hex(&signed.signature) else {
            return false;
        };
        pk.verify(&vote_bytes(v), &sig).is_ok()
    }

    fn broadcast_vote(&mut self, vote_type: VoteType, block_hash: Hash) {
        let vote = Vote {
            height: self.height,
            round: self.round,
            vote_type,
            block_hash,
            validator_id: self.node_id,
        };
        let sig = self.keypair.sign(&vote_bytes(&vote));
        let signed = SignedVote {
            vote,
            signature: sig_to_hex(&sig),
        };
        self.handle_vote(signed.clone());
        self.net.broadcast(Message::Vote(signed));
    }

    fn check_timeouts(&mut self) {
        let elapsed = self.round_start.elapsed();
        let cfg = &self.genesis.consensus;
        let base = match self.step {
            Step::Propose => cfg.propose_timeout_ms,
            Step::Prevote => cfg.prevote_timeout_ms,
            Step::Precommit => cfg.precommit_timeout_ms,
        };

        let backoff = timeout_backoff(base, cfg, self.round);
        if elapsed > backoff {
            match self.step {
                Step::Propose => {
                    if self.round_state.proposal.is_none() {
                        self.broadcast_vote(VoteType::Prevote, ZERO_HASH);
                    }
                    self.step = Step::Prevote;
                    self.round_start = Instant::now();
                }
                Step::Prevote => {
                    self.broadcast_vote(VoteType::Precommit, ZERO_HASH);
                    self.step = Step::Precommit;
                    self.round_start = Instant::now();
                }
                Step::Precommit => {
                    self.round = self.round.saturating_add(1);
                    self.step = Step::Propose;
                    self.round_state = RoundState::new();
                    self.round_start = Instant::now();
                }
            }
        }
    }

    fn restore_from_store(&mut self) -> Result<(), String> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let Some(persisted) = store.load()? else {
            return Ok(());
        };

        let mut blocks = persisted.blocks;
        blocks.sort_by_key(|b| b.header.height);
        if blocks.is_empty() && persisted.height > 0 {
            return Err("snapshot has height but no blocks".into());
        }

        let mut snap = NodeSnapshot::new();
        let mut expected_prev = ZERO_HASH;
        let mut expected_height = 1u64;
        for block in &blocks {
            if block.header.height != expected_height {
                return Err("snapshot block height mismatch".into());
            }
            if block.header.prev_block_hash != expected_prev {
                return Err("snapshot block linkage mismatch".into());
            }
            self.apply_block(block)?;
            let bh = block_hash(&block.header);
            snap.blocks_by_height.insert(block.header.height, block.clone());
            snap.blocks_by_hash.insert(bh, block.clone());
            for tx in &block.txs {
                let th = tx_hash(tx);
                snap.tx_index.insert(th, (bh, block.header.height));
            }
            expected_prev = bh;
            expected_height = expected_height.saturating_add(1);
        }

        if let Some(last) = blocks.last() {
            snap.height = last.header.height;
            snap.tip_hash = block_hash(&last.header);
            if persisted.height != snap.height || persisted.tip_hash != snap.tip_hash {
                eprintln!("warning: snapshot metadata mismatch; recomputed from blocks");
            }
        } else {
            snap.height = persisted.height;
            snap.tip_hash = persisted.tip_hash;
        }

        // Restore slashing state from persisted snapshot
        snap.slashing_state = persisted.slashing_state.clone();
        if let Some(ref restored_slashing) = snap.slashing_state {
            self.slashing_state = restored_slashing.clone();
        }

        let next_height = snap.height.saturating_add(1);
        {
            let mut current = self
                .snapshot
                .write()
                .map_err(|_| "snapshot lock".to_string())?;
            *current = snap;
        }

        self.height = next_height;
        self.round = 0;
        self.step = Step::Propose;
        self.round_start = Instant::now();
        self.locked = None;
        self.round_state = RoundState::new();
        Ok(())
    }
}

pub struct Network {
    peers: Arc<Mutex<HashMap<NodeId, mpsc::Sender<Message>>>>,
    allowlist: HashMap<NodeId, PublicKey>,
    self_id: NodeId,
    keypair: Arc<Keypair>,
    tx_net: mpsc::Sender<Message>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    tls: Option<Arc<TlsConfig>>,
}

impl Network {
    pub fn start(
        listen_addr: String,
        validators: &[ValidatorInfo],
        keypair: Arc<Keypair>,
        tx_net: mpsc::Sender<Message>,
        tls_identity: Option<TlsIdentity>,
    ) -> Result<Network, String> {
        let self_id = node_id_from_pubkey(&keypair.public.to_bytes());
        let allowlist = validators
            .iter()
            .map(|v| (v.node_id, v.pubkey))
            .collect::<HashMap<_, _>>();

        let tls = match tls_identity {
            Some(identity) => Some(Arc::new(build_tls_config(identity, validators)?)),
            None => None,
        };
        let peers = Arc::new(Mutex::new(HashMap::new()));
        let peers_clone = Arc::clone(&peers);
        let allowlist_clone = allowlist.clone();
        let kp_clone = Arc::clone(&keypair);
        let tx_net_in = tx_net.clone();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_in = Arc::clone(&shutdown);
        let tls_in = tls.clone();

        thread::spawn(move || {
            use std::io::ErrorKind;
            let listener = TcpListener::bind(listen_addr).expect("bind listen");
            listener
                .set_nonblocking(true)
                .expect("set nonblocking");
            loop {
                if shutdown_in.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        let mut peer_stream = match make_server_stream(stream, tls_in.as_deref()) {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        if let Some(peer_id) =
                            handshake_accept(&mut peer_stream, &allowlist_clone, &kp_clone)
                        {
                            peer_stream.set_read_timeout(Duration::from_millis(50));
                            let sender = spawn_peer(peer_stream, tx_net_in.clone(), Arc::clone(&shutdown_in));
                            let mut map = peers_clone.lock().unwrap();
                            map.insert(peer_id, sender);
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Network {
            peers,
            allowlist,
            self_id,
            keypair,
            tx_net,
            shutdown,
            tls,
        })
    }

    pub fn connect_peers(&self, validators: &[ValidatorInfo]) {
        for v in validators {
            if v.node_id == self.self_id {
                continue;
            }
            let addr = v.address.clone();
            let allowlist = self.allowlist.clone();
            let peers = Arc::clone(&self.peers);
            let kp = Arc::clone(&self.keypair);
            let tx_net = self.tx_net.clone();
            let shutdown = Arc::clone(&self.shutdown);
            let tls = self.tls.clone();
            thread::spawn(move || loop {
                if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let mut peer_stream = match make_client_stream(&addr, tls.as_deref()) {
                    Ok(s) => s,
                    Err(_) => {
                        thread::sleep(Duration::from_millis(500));
                        continue;
                    }
                };
                if let Some(peer_id) = handshake_connect(&mut peer_stream, &allowlist, &kp) {
                    peer_stream.set_read_timeout(Duration::from_millis(50));
                    let sender = spawn_peer(peer_stream, tx_net.clone(), Arc::clone(&shutdown));
                    let mut map = peers.lock().unwrap();
                    map.insert(peer_id, sender);
                    break;
                }
                thread::sleep(Duration::from_millis(500));
            });
        }
    }

    pub fn broadcast(&self, msg: Message) {
        let peers = self.peers.lock().unwrap();
        for (_, peer) in peers.iter() {
            let _ = peer.send(msg.clone());
        }
    }

    pub fn shutdown(&self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut peers = self.peers.lock().unwrap();
        peers.clear();
    }
}

fn spawn_peer(
    mut stream: PeerStream,
    tx_net: mpsc::Sender<Message>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> mpsc::Sender<Message> {
    let (tx_out, rx_out) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        loop {
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            loop {
                match rx_out.try_recv() {
                    Ok(msg) => {
                        if write_message(&mut stream, &msg).is_err() {
                            return;
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => break,
                }
            }

            match read_into_buffer(&mut stream, &mut buf) {
                Ok(()) => {
                    loop {
                        let msg = match try_decode_message(&mut buf) {
                            Ok(Some(msg)) => msg,
                            Ok(None) => break,
                            Err(_) => return,
                        };
                        let _ = tx_net.send(msg);
                    }
                }
                Err(_) => return,
            }

            thread::sleep(Duration::from_millis(5));
        }
    });
    tx_out
}

fn read_into_buffer(stream: &mut PeerStream, buf: &mut Vec<u8>) -> Result<(), String> {
    let mut tmp = [0u8; 4096];
    match stream.read(&mut tmp) {
        Ok(0) => Err("connection closed".into()),
        Ok(n) => {
            buf.extend_from_slice(&tmp[..n]);
            Ok(())
        }
        Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
            Ok(())
        }
        Err(err) => Err(format!("{}", err)),
    }
}

fn try_decode_message(buf: &mut Vec<u8>) -> Result<Option<Message>, String> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len == 0 || len > 8_000_000 {
        return Err("invalid message length".into());
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let data = buf[4..4 + len].to_vec();
    buf.drain(0..4 + len);
    let msg = serde_json::from_slice(&data).map_err(|e| format!("{}", e))?;
    Ok(Some(msg))
}

fn build_tls_config(identity: TlsIdentity, validators: &[ValidatorInfo]) -> Result<TlsConfig, String> {
    let mut roots = RootCertStore::empty();
    for v in validators {
        let cert = v
            .tls_cert
            .as_ref()
            .ok_or("tls enabled but validator missing tls_cert_hex")?;
        roots
            .add(&Certificate(cert.clone()))
            .map_err(|_| "invalid tls_cert_hex".to_string())?;
    }

    let client = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots.clone())
        .with_client_auth_cert(identity.cert_chain.clone(), identity.key.clone())
        .map_err(|_| "invalid tls key or certificate".to_string())?;

    let server = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(AllowAnyAuthenticatedClient::new(roots)))
        .with_single_cert(identity.cert_chain, identity.key)
        .map_err(|_| "invalid tls key or certificate".to_string())?;

    Ok(TlsConfig {
        server: Arc::new(server),
        client: Arc::new(client),
    })
}

fn make_server_stream(stream: TcpStream, tls: Option<&TlsConfig>) -> Result<PeerStream, String> {
    if let Some(tls) = tls {
        let conn = ServerConnection::new(Arc::clone(&tls.server))
            .map_err(|_| "tls server config error".to_string())?;
        Ok(PeerStream::TlsServer(StreamOwned::new(conn, stream)))
    } else {
        Ok(PeerStream::Plain(stream))
    }
}

fn make_client_stream(addr: &str, tls: Option<&TlsConfig>) -> Result<PeerStream, String> {
    let stream = TcpStream::connect(addr).map_err(|e| format!("{}", e))?;
    if let Some(tls) = tls {
        let server_name = server_name_from_addr(addr)?;
        let conn = ClientConnection::new(Arc::clone(&tls.client), server_name)
            .map_err(|_| "tls client config error".to_string())?;
        Ok(PeerStream::TlsClient(StreamOwned::new(conn, stream)))
    } else {
        Ok(PeerStream::Plain(stream))
    }
}

fn server_name_from_addr(addr: &str) -> Result<ServerName, String> {
    let host = host_from_addr(addr).ok_or("invalid address")?;
    ServerName::try_from(host).map_err(|_| "invalid server name".to_string())
}

fn host_from_addr(addr: &str) -> Option<&str> {
    if let Some(rest) = addr.strip_prefix('[') {
        let end = rest.find(']')?;
        return Some(&rest[..end]);
    }
    addr.split(':').next()
}

fn handshake_accept<S: Read + Write>(
    stream: &mut S,
    allowlist: &HashMap<NodeId, PublicKey>,
    keypair: &Arc<Keypair>,
) -> Option<NodeId> {
    let hello = read_message(stream).ok()??;
    let Message::Hello {
        node_id,
        pubkey,
        signature,
    } = hello else {
        return None;
    };
    let expected = allowlist.get(&node_id)?;
    if expected != &pubkey {
        return None;
    }
    let pk = DalekPublicKey::from_bytes(&pubkey).ok()?;
    let sig = sig_from_hex(&signature)?;
    let hello = hello_bytes(&node_id);
    if pk.verify(&hello, &sig).is_err() {
        return None;
    }

    let my_id = node_id_from_pubkey(&keypair.public.to_bytes());
    let hello = hello_bytes(&my_id);
    let my_sig = keypair.sign(&hello);
    let response = Message::Hello {
        node_id: my_id,
        pubkey: keypair.public.to_bytes(),
        signature: sig_to_hex(&my_sig),
    };
    let _ = write_message(stream, &response);
    Some(node_id)
}

fn handshake_connect<S: Read + Write>(
    stream: &mut S,
    allowlist: &HashMap<NodeId, PublicKey>,
    keypair: &Arc<Keypair>,
) -> Option<NodeId> {
    let my_id = node_id_from_pubkey(&keypair.public.to_bytes());
    let hello = hello_bytes(&my_id);
    let sig = keypair.sign(&hello);
    let hello = Message::Hello {
        node_id: my_id,
        pubkey: keypair.public.to_bytes(),
        signature: sig_to_hex(&sig),
    };
    let _ = write_message(stream, &hello);
    let reply = read_message(stream).ok()??;
    let Message::Hello {
        node_id,
        pubkey,
        signature,
    } = reply else {
        return None;
    };
    let expected = allowlist.get(&node_id)?;
    if expected != &pubkey {
        return None;
    }
    let pk = DalekPublicKey::from_bytes(&pubkey).ok()?;
    let sig = sig_from_hex(&signature)?;
    let hello = hello_bytes(&node_id);
    if pk.verify(&hello, &sig).is_err() {
        return None;
    }
    Some(node_id)
}

fn hello_bytes(node_id: &NodeId) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(b"DVEL");
    out.extend_from_slice(node_id);
    out
}

fn sig_to_hex(sig: &Signature) -> String {
    hex_encode(sig.to_bytes())
}

fn sig_from_hex(sig_hex: &str) -> Option<Signature> {
    let bytes = hex_decode(sig_hex).ok()?;
    if bytes.len() != 64 {
        return None;
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Signature::from_bytes(&arr).ok()
}

fn snapshot_to_persisted(snapshot: &NodeSnapshot) -> PersistedSnapshot {
    let mut heights: Vec<u64> = snapshot.blocks_by_height.keys().cloned().collect();
    heights.sort_unstable();
    let mut blocks = Vec::with_capacity(heights.len());
    for h in heights {
        if let Some(block) = snapshot.blocks_by_height.get(&h) {
            blocks.push(block.clone());
        }
    }
    PersistedSnapshot {
        height: snapshot.height,
        tip_hash: snapshot.tip_hash,
        blocks,
        slashing_state: snapshot.slashing_state.clone(),
    }
}

fn write_message<W: Write>(stream: &mut W, msg: &Message) -> Result<(), String> {
    let data = serde_json::to_vec(msg).map_err(|e| format!("{}", e))?;
    let len = data.len() as u32;
    stream
        .write_all(&len.to_le_bytes())
        .map_err(|e| format!("{}", e))?;
    stream
        .write_all(&data)
        .map_err(|e| format!("{}", e))?;
    Ok(())
}

fn read_message<R: Read>(stream: &mut R) -> Result<Option<Message>, String> {
    use std::io::ErrorKind;
    let mut len_buf = [0u8; 4];
    if let Err(err) = stream.read_exact(&mut len_buf) {
        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
            return Ok(None);
        }
        return Err(format!("{}", err));
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > 8_000_000 {
        return Err("invalid message length".into());
    }
    let mut data = vec![0u8; len];
    stream
        .read_exact(&mut data)
        .map_err(|e| format!("{}", e))?;
    let msg = serde_json::from_slice(&data).map_err(|e| format!("{}", e))?;
    Ok(Some(msg))
}

fn decode_event(tx: &[u8]) -> Result<Event, String> {
    if tx.len() != 1 + 32 + 32 + 8 + 32 + 64 {
        return Err("invalid tx length".into());
    }
    let version = tx[0];
    let mut offset = 1;
    let prev_hash = read_hash(tx, &mut offset);
    let author = read_pubkey(tx, &mut offset);
    let timestamp = read_u64(tx, &mut offset);
    let payload_hash = read_hash(tx, &mut offset);
    let signature = read_sig(tx, &mut offset);
    Ok(Event::from_raw(
        version,
        prev_hash,
        author,
        timestamp,
        payload_hash,
        signature,
    ))
}

fn read_hash(buf: &[u8], offset: &mut usize) -> Hash {
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf[*offset..*offset + 32]);
    *offset += 32;
    out
}

fn read_pubkey(buf: &[u8], offset: &mut usize) -> PublicKey {
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf[*offset..*offset + 32]);
    *offset += 32;
    out
}

fn read_sig(buf: &[u8], offset: &mut usize) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&buf[*offset..*offset + 64]);
    *offset += 64;
    out
}

fn read_u64(buf: &[u8], offset: &mut usize) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&buf[*offset..*offset + 8]);
    *offset += 8;
    u64::from_le_bytes(out)
}

fn now_ms() -> u64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    dur.as_millis() as u64
}

fn timeout_backoff(
    base_ms: u64,
    cfg: &crate::bft::config::ConsensusConfig,
    round: u64,
) -> Duration {
    let mut base = base_ms as u128;
    let num = cfg.timeout_backoff_num as u128;
    let den = cfg.timeout_backoff_den.max(1) as u128;
    let mut i = 0;
    while i < round {
        base = base.saturating_mul(num) / den;
        i += 1;
    }
    let capped = base.min(cfg.timeout_cap_ms as u128);
    Duration::from_millis(capped as u64)
}
