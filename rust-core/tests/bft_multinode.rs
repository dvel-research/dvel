#![cfg(feature = "bft")]

use dvel_core::bft::config::{
    ClientConfig, ConsensusConfig, GenesisConfig, TransportConfig, ValidatorConfig,
};
use dvel_core::bft::node::{Network, Node, NodeCommand, NodeConfig, NodeSnapshot};
use dvel_core::bft::types::block_hash;
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::{mpsc, Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

struct TestNode {
    snapshot: Arc<RwLock<NodeSnapshot>>,
    tx_cmd: mpsc::Sender<NodeCommand>,
    handle: thread::JoinHandle<()>,
}

fn consensus_fast() -> ConsensusConfig {
    ConsensusConfig {
        propose_timeout_ms: 150,
        prevote_timeout_ms: 150,
        precommit_timeout_ms: 150,
        target_block_ms: 200,
        timeout_cap_ms: 2_000,
        ..ConsensusConfig::default()
    }
}

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephem")
        .local_addr()
        .expect("local addr")
        .port()
}

fn secret_from_seed(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn keypair_from_secret(secret: [u8; 32]) -> Keypair {
    let secret = SecretKey::from_bytes(&secret).expect("secret key");
    let public: PublicKey = (&secret).into();
    Keypair { secret, public }
}

fn genesis_from_secrets(secrets: &[[u8; 32]], addrs: &[String]) -> GenesisConfig {
    let mut validators = Vec::with_capacity(secrets.len());
    for (secret, addr) in secrets.iter().zip(addrs.iter()) {
        let secret = SecretKey::from_bytes(secret).expect("secret key");
        let public: PublicKey = (&secret).into();
        validators.push(ValidatorConfig {
            pubkey_hex: hex::encode(public.to_bytes()),
            address: addr.clone(),
            power: 1,
            stake: 1_000_000,
            tls_cert_hex: None,
        });
    }

    GenesisConfig {
        chain_id: "bft-test".to_string(),
        validators,
        consensus: consensus_fast(),
        client: ClientConfig {
            listen_addr: "127.0.0.1:0".to_string(),
        },
        transport: TransportConfig::default(),
    }
}

fn start_node(genesis: GenesisConfig, keypair: Keypair, listen_addr: String) -> TestNode {
    let snapshot = Arc::new(RwLock::new(NodeSnapshot::new()));
    let (tx_net, rx_net) = mpsc::channel();
    let (tx_cmd, rx_cmd) = mpsc::channel();

    let validators = genesis.validator_infos().expect("validators");
    let keypair = Arc::new(keypair);
    let net = Network::start(
        listen_addr.clone(),
        &validators,
        Arc::clone(&keypair),
        tx_net,
        None,
    )
    .expect("network start");
    net.connect_peers(&validators);

    let node = Node::new(
        genesis,
        Arc::clone(&keypair),
        NodeConfig {
            listen_addr,
            client_addr: "127.0.0.1:0".to_string(),
            data_dir: None,
        },
        Arc::clone(&snapshot),
        net,
    )
    .expect("node init");

    let handle = thread::spawn(move || node.run(rx_net, rx_cmd));
    TestNode {
        snapshot,
        tx_cmd,
        handle,
    }
}

fn wait_for_quorum_block(nodes: &[TestNode], height: u64, timeout: Duration) -> u64 {
    let start = Instant::now();
    loop {
        let mut counts: HashMap<[u8; 32], (usize, u64)> = HashMap::new();
        for node in nodes {
            let snap = node.snapshot.read().expect("snapshot lock");
            if let Some(block) = snap.blocks_by_height.get(&height) {
                let hash = block_hash(&block.header);
                let entry = counts.entry(hash).or_insert((0, block.header.round));
                entry.0 += 1;
            }
        }

        for (_, (count, round)) in &counts {
            if *count >= 3 {
                return *round;
            }
        }

        if start.elapsed() > timeout {
            panic!("timeout waiting for quorum block at height {}", height);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn shutdown_nodes(nodes: Vec<TestNode>) {
    for node in nodes {
        let _ = node.tx_cmd.send(NodeCommand::Shutdown);
        let _ = node.handle.join();
    }
}

#[test]
fn bft_finality_quorum_4_nodes() {
    let secrets: Vec<[u8; 32]> = (1u8..=4).map(secret_from_seed).collect();
    let addrs: Vec<String> = (0..4)
        .map(|_| format!("127.0.0.1:{}", pick_port()))
        .collect();
    let genesis = genesis_from_secrets(&secrets, &addrs);

    let mut nodes = Vec::new();
    for (secret, addr) in secrets.iter().zip(addrs.iter()) {
        let keypair = keypair_from_secret(*secret);
        nodes.push(start_node(genesis.clone(), keypair, addr.clone()));
    }

    let _round = wait_for_quorum_block(&nodes, 1, Duration::from_secs(5));

    shutdown_nodes(nodes);
}

#[test]
fn bft_timeouts_skip_missing_proposer() {
    let secrets: Vec<[u8; 32]> = (10u8..=13).map(secret_from_seed).collect();
    let addrs: Vec<String> = (0..4)
        .map(|_| format!("127.0.0.1:{}", pick_port()))
        .collect();
    let genesis = genesis_from_secrets(&secrets, &addrs);

    // Skip validator index 1 so the round-0 proposer is offline.
    let mut nodes = Vec::new();
    for (idx, (secret, addr)) in secrets.iter().zip(addrs.iter()).enumerate() {
        if idx == 1 {
            continue;
        }
        let keypair = keypair_from_secret(*secret);
        nodes.push(start_node(genesis.clone(), keypair, addr.clone()));
    }

    let round = wait_for_quorum_block(&nodes, 1, Duration::from_secs(6));
    assert!(
        round >= 1,
        "expected round advance when initial proposer is offline"
    );

    shutdown_nodes(nodes);
}
