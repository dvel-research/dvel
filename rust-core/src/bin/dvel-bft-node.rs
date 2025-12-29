#[cfg(not(feature = "bft"))]
fn main() {
    eprintln!("Build with --features bft to enable the BFT node.");
}

#[cfg(feature = "bft")]
fn main() {
    use dvel_core::bft::config::GenesisConfig;
    use dvel_core::bft::http::start_http_server;
    use dvel_core::bft::node::{Network, Node, NodeConfig, NodeSnapshot};
    use dvel_core::bft::types::node_id_from_pubkey;
    use ed25519_dalek::{Keypair, PublicKey, SecretKey};
    use std::env;
    use std::fs;
    use std::sync::{mpsc, Arc, RwLock};

    let mut genesis_path: Option<String> = None;
    let mut key_hex: Option<String> = None;
    let mut key_file: Option<String> = None;
    let mut listen_override: Option<String> = None;
    let mut client_override: Option<String> = None;
    let mut data_dir_override: Option<String> = None;
    let mut tls_cert_path: Option<String> = None;
    let mut tls_key_path: Option<String> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--genesis" => genesis_path = args.next(),
            "--key-hex" => key_hex = args.next(),
            "--key-file" => key_file = args.next(),
            "--listen" => listen_override = args.next(),
            "--client" => client_override = args.next(),
            "--data-dir" => data_dir_override = args.next(),
            "--tls-cert" => tls_cert_path = args.next(),
            "--tls-key" => tls_key_path = args.next(),
            _ => {
                eprintln!("unknown arg {}", arg);
                return;
            }
        }
    }

    let genesis_path = genesis_path.expect("missing --genesis");
    let genesis_bytes = fs::read_to_string(&genesis_path).expect("read genesis");
    let genesis: GenesisConfig =
        serde_json::from_str(&genesis_bytes).expect("parse genesis json");

    let secret_hex = if let Some(h) = key_hex {
        h
    } else if let Some(path) = key_file {
        fs::read_to_string(path).expect("read key file").trim().to_string()
    } else {
        panic!("missing --key-hex or --key-file");
    };

    let secret_bytes = hex::decode(secret_hex.trim()).expect("bad secret hex");
    if secret_bytes.len() != 32 {
        panic!("secret key must be 32 bytes hex");
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&secret_bytes);
    let secret = SecretKey::from_bytes(&sk).expect("secret key");
    let public: PublicKey = (&secret).into();
    let keypair = Arc::new(Keypair { secret, public });

    let validators = genesis.validator_infos().expect("validator list");
    let node_id = node_id_from_pubkey(&keypair.public.to_bytes());
    let mut listen_addr = None;
    for v in &validators {
        if v.node_id == node_id {
            listen_addr = Some(v.address.clone());
            break;
        }
    }
    let listen_addr = listen_override.or(listen_addr).expect("listen address");
    let client_addr = client_override.unwrap_or(genesis.client.listen_addr.clone());
    let data_dir = data_dir_override.unwrap_or_else(|| {
        let node_id_hex = hex::encode(node_id);
        format!("data/{}", node_id_hex)
    });
    let tls_identity = if genesis.transport.tls_enabled {
        let cert_path = tls_cert_path.expect("missing --tls-cert");
        let key_path = tls_key_path.expect("missing --tls-key");
        Some(load_tls_identity(&cert_path, &key_path).expect("load tls identity"))
    } else {
        None
    };

    let snapshot = Arc::new(RwLock::new(NodeSnapshot::new()));
    let (tx_net, rx_net) = mpsc::channel();
    let (tx_cmd, rx_cmd) = mpsc::channel();

    let net = Network::start(
        listen_addr.clone(),
        &validators,
        Arc::clone(&keypair),
        tx_net,
        tls_identity,
    )
    .expect("network start");
    net.connect_peers(&validators);

    start_http_server(client_addr.clone(), Arc::clone(&snapshot), tx_cmd.clone());

    let node = Node::new(
        genesis,
        Arc::clone(&keypair),
        NodeConfig {
            listen_addr,
            client_addr: client_addr.clone(),
            data_dir: Some(data_dir),
        },
        snapshot,
        net,
    )
    .expect("node init");

    node.run(rx_net, rx_cmd);
}

#[cfg(feature = "bft")]
fn load_tls_identity(
    cert_path: &str,
    key_path: &str,
) -> Result<dvel_core::bft::node::TlsIdentity, String> {
    use rustls::{Certificate, PrivateKey};
    use std::fs::File;
    use std::io::BufReader;

    let cert_file = File::open(cert_path).map_err(|e| format!("{}", e))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader).map_err(|e| format!("{}", e))?;
    if certs.is_empty() {
        return Err("no certs found in tls cert file".into());
    }

    let key_file = File::open(key_path).map_err(|e| format!("{}", e))?;
    let mut key_reader = BufReader::new(key_file);
    let keys =
        rustls_pemfile::pkcs8_private_keys(&mut key_reader).map_err(|e| format!("{}", e))?;
    if keys.is_empty() {
        return Err("no pkcs8 private key found".into());
    }

    Ok(dvel_core::bft::node::TlsIdentity {
        cert_chain: certs.into_iter().map(Certificate).collect(),
        key: PrivateKey(keys[0].clone()),
    })
}
