#!/usr/bin/env python3

import os
import sys
import json
import time
import socket
import shutil
import signal
import datetime
import ipaddress
import subprocess
import urllib.request
import urllib.error

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
except ImportError:
    print("[orchestrator] 'cryptography' library is missing. Installing it dynamically...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "cryptography"], check=True)
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
        print("[orchestrator] 'cryptography' library installed successfully!")
    except Exception as e:
        print(f"[orchestrator] ERROR: Failed to install 'cryptography' library. Please run: pip install cryptography")
        sys.exit(1)

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPTS_DIR, ".."))
DATA_DIR = os.path.join(ROOT_DIR, "data")
STATE_FILE = os.path.join(DATA_DIR, "cluster_state.json")
GENESIS_FILE = os.path.join(DATA_DIR, "genesis.json")

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_CYAN = "\033[36m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_RED = "\033[31m"
C_BLUE = "\033[34m"
C_MAGENTA = "\033[35m"
BG_BLUE = "\033[44m"

def print_banner():
    banner = f"""
{C_CYAN}{C_BOLD}======================================================================
     ____ _     _ _____ _       ____ _             _
    |  _ \ \   / / ____| |     / ___| | _   _  ___| |_ ___ _ __
    | | | \ \ / /|  _| | |    | |   | | | | |/ __| __/ _ \ '__|
    | |_| |\ V / | |___| |___ | |___| | |_| |\__ \ ||  __/ |
    |____/  \_/  |_____|_____| \____|_|\__,_||___/\__\___|_|
{C_RESET}
    Deterministic Event Ledger - 4-Node mTLS BFT Cluster Orchestrator
{C_CYAN}{C_BOLD}======================================================================{C_RESET}"""
    print(banner)

def get_binary_path():

    ext = ".exe" if sys.platform == "win32" else ""
    return os.path.join(ROOT_DIR, "rust-core", "target", "release", f"dvel-bft-node{ext}")

def check_binary():

    binary_path = get_binary_path()
    if not os.path.exists(binary_path):
        print(f"{C_YELLOW}[orchestrator] Binary not found at {binary_path}. Compiling now...{C_RESET}")
        compile_binary()
    return binary_path

def compile_binary():

    print(f"{C_CYAN}[orchestrator] Running cargo build --release --features bft,parallel ...{C_RESET}")
    rust_dir = os.path.join(ROOT_DIR, "rust-core")
    try:
        subprocess.run(["cargo", "build", "--release", "--features", "bft,parallel"], cwd=rust_dir, check=True)
        print(f"{C_GREEN}[orchestrator] Compilation successful!{C_RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{C_RED}[orchestrator] ERROR: Compilation failed! ({e}){C_RESET}")
        sys.exit(1)

def sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()

def generate_node_keys(ip_address, host_name):

    ed25519_key = ed25519.Ed25519PrivateKey.generate()
    ed25519_pub = ed25519_key.public_key()
    
    seed_hex = ed25519_key.private_bytes_raw().hex()
    pub_hex = ed25519_pub.public_bytes_raw().hex()
    

    node_id_bytes = sha256(ed25519_pub.public_bytes_raw())
    node_id_hex = node_id_bytes.hex()
    

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, host_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        rsa_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow() - datetime.timedelta(days=1)
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=825)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
        ]), critical=False
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.IPv4Address(ip_address))
        ]), critical=False
    ).sign(rsa_key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    rsa_key_pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    cert_hex = cert.public_bytes(serialization.Encoding.DER).hex()
    
    return {
        "node_id": node_id_hex,
        "seed_hex": seed_hex,
        "pub_hex": pub_hex,
        "cert_pem": cert_pem.decode("ascii"),
        "key_pem": rsa_key_pem.decode("ascii"),
        "cert_hex": cert_hex
    }

def build_cluster_configs(num_nodes=4, enable_tls=True):

    print(f"{C_CYAN}[orchestrator] Generating keys and certificates for {num_nodes} nodes...{C_RESET}")
    
    nodes_config = []
    validators_genesis = []
    
    for i in range(num_nodes):
        ip = "127.0.0.1"
        gossip_port = 9001 + i
        client_port = 7001 + i
        host = f"node{i}"
        
        keys = generate_node_keys(ip, host)
        
        node_conf = {
            "node_index": i,
            "node_id": keys["node_id"],
            "seed_hex": keys["seed_hex"],
            "pub_hex": keys["pub_hex"],
            "address": f"{ip}:{gossip_port}",
            "client_address": f"{ip}:{client_port}",
            "cert_pem": keys["cert_pem"],
            "key_pem": keys["key_pem"],
            "cert_hex": keys["cert_hex"]
        }
        nodes_config.append(node_conf)
        
        val_genesis = {
            "pubkey_hex": keys["pub_hex"],
            "address": f"{ip}:{gossip_port}",
            "power": 10,
            "stake": 1000000,
            "tls_cert_hex": keys["cert_hex"] if enable_tls else None
        }
        validators_genesis.append(val_genesis)
        
    genesis = {
        "chain_id": "dvel-bft-local-net",
        "validators": validators_genesis,
        "consensus": {
            "max_block_bytes": 1048576,
            "max_events": 5000,
            "target_block_ms": 2000,
            "propose_timeout_ms": 500,
            "prevote_timeout_ms": 400,
            "precommit_timeout_ms": 400,
            "timeout_backoff_num": 3,
            "timeout_backoff_den": 2,
            "timeout_cap_ms": 5000,
            "slashing": {
                "enabled": True,
                "double_sign_percent": 5,
                "invalid_proposal_percent": 1,
                "jail_duration_blocks": 100
            }
        },
        "client": {
            "listen_addr": "127.0.0.1:7001"
        },
        "transport": {
            "tls_enabled": enable_tls
        }
    }
    
    return nodes_config, genesis

def start_cluster(num_nodes=4, enable_tls=True):
    print_banner()
    

    binary_path = check_binary()
    

    if os.path.exists(STATE_FILE):
        print(f"{C_RED}[orchestrator] ERROR: A local cluster is already running. Run stop mode first.{C_RESET}")
        return
        

    if os.path.exists(DATA_DIR):
        print(f"{C_YELLOW}[orchestrator] Cleaning existing data folder...{C_RESET}")
        try:

            shutil.rmtree(DATA_DIR)
        except Exception as e:
            print(f"{C_YELLOW}[orchestrator] Warning during cleanup: {e}{C_RESET}")
            
    os.makedirs(DATA_DIR, exist_ok=True)
    

    nodes_config, genesis = build_cluster_configs(num_nodes, enable_tls)
    

    with open(GENESIS_FILE, "w") as f:
        json.dump(genesis, f, indent=2)
    print(f"{C_GREEN}[orchestrator] Wrote genesis.json to {GENESIS_FILE}{C_RESET}")
    

    running_state = {
        "binary": binary_path,
        "tls_enabled": enable_tls,
        "nodes": []
    }
    
    for conf in nodes_config:
        idx = conf["node_index"]
        node_dir = os.path.join(DATA_DIR, f"node_{idx}")
        os.makedirs(node_dir, exist_ok=True)
        

        cert_path = os.path.join(node_dir, "node.crt")
        key_path = os.path.join(node_dir, "node.key")
        with open(cert_path, "w") as f:
            f.write(conf["cert_pem"])
        with open(key_path, "w") as f:
            f.write(conf["key_pem"])
            

        seed_path = os.path.join(node_dir, "node.seed")
        with open(seed_path, "w") as f:
            f.write(conf["seed_hex"])
            

        args = [
            binary_path,
            "--genesis", GENESIS_FILE,
            "--key-hex", conf["seed_hex"],
            "--listen", conf["address"],
            "--client", conf["client_address"],
            "--data-dir", node_dir
        ]
        
        if enable_tls:
            args.extend([
                "--tls-cert", cert_path,
                "--tls-key", key_path
            ])
            

        stdout_log_path = os.path.join(node_dir, "stdout.log")
        log_file = open(stdout_log_path, "w")
        
        print(f"{C_YELLOW}[orchestrator] Starting Node {idx} ({conf['node_id'][:8]}) at gossip={conf['address']} client={conf['client_address']}...{C_RESET}")
        
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_CONSOLE
            
        proc = subprocess.Popen(
            args,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            cwd=ROOT_DIR,
            creationflags=creationflags
        )
        
        running_state["nodes"].append({
            "index": idx,
            "node_id": conf["node_id"],
            "pid": proc.pid,
            "address": conf["address"],
            "client_address": conf["client_address"],
            "log_path": stdout_log_path
        })
        

    with open(STATE_FILE, "w") as f:
        json.dump(running_state, f, indent=2)
        
    print(f"\n{C_GREEN}{C_BOLD}[orchestrator] SUCCESS: 4-Node local cluster spawned successfully!{C_RESET}")
    print(f"[orchestrator] Logs and snapshot DB are saved under: {DATA_DIR}")
    print(f"[orchestrator] Keeping orchestrator running to maintain node lifetimes. Press Ctrl+C to stop cluster.\n")
    
    try:
        while True:
            time.sleep(1.5)
            heights = []
            for node in running_state["nodes"]:
                idx = node["index"]
                url = f"http://{node['client_address']}/tip"
                try:
                    with urllib.request.urlopen(url, timeout=0.5) as r:
                        data = json.loads(r.read().decode("utf-8"))
                        heights.append(f"Node {idx}: Height={data['height']}")
                except Exception:
                    heights.append(f"Node {idx}: {C_RED}OFFLINE{C_RESET}")
            
            print(f"\r[live consensus] {' | '.join(heights)}", end="", flush=True)
            
    except KeyboardInterrupt:
        print(f"\n\n{C_YELLOW}[orchestrator] KeyboardInterrupt received. Stopping cluster gracefully...{C_RESET}")
        stop_cluster(clean=False)

def start_host_cluster(ip):

    print_banner()
    ip_clean = ip.replace(".", "_")
    host_dir = os.path.join(ROOT_DIR, "dist", f"host_{ip_clean}")
    
    if not os.path.exists(host_dir):
        print(f"{C_RED}[orchestrator] ERROR: No host configuration found at {host_dir}.{C_RESET}")
        print(f"[orchestrator] Please run: python scripts/run_local_cluster.py export <IPs> first.")
        return

    if os.path.exists(STATE_FILE):
        print(f"{C_RED}[orchestrator] ERROR: A local cluster is already running. Run stop mode first.{C_RESET}")
        return

    if os.path.exists(DATA_DIR):
        print(f"{C_YELLOW}[orchestrator] Cleaning existing data folder...{C_RESET}")
        try:
            shutil.rmtree(DATA_DIR)
        except Exception as e:
            print(f"{C_YELLOW}[orchestrator] Warning during cleanup: {e}{C_RESET}")
            
    os.makedirs(DATA_DIR, exist_ok=True)

    binary_path = check_binary()

    validators = []
    for item in os.listdir(host_dir):
        if item.startswith("validator_") and os.path.isdir(os.path.join(host_dir, item)):
            try:
                idx = int(item.split("_")[1])
                validators.append((idx, os.path.join(host_dir, item)))
            except ValueError:
                pass
                
    validators.sort()
    
    if not validators:
        print(f"{C_RED}[orchestrator] ERROR: No validator subdirectories found in {host_dir}.{C_RESET}")
        return

    print(f"{C_CYAN}[orchestrator] Spawning {len(validators)} local nodes for host {ip}...{C_RESET}")
    
    host_genesis_path = os.path.join(host_dir, "genesis.json")
    with open(host_genesis_path, "r") as f:
        genesis = json.load(f)
        
    running_state = {
        "binary": binary_path,
        "tls_enabled": genesis.get("transport", {}).get("tls_enabled", True),
        "nodes": []
    }
    

    for port_offset, (idx, val_dir) in enumerate(validators):

        with open(os.path.join(val_dir, "node.seed"), "r") as f:
            seed_hex = f.read().strip()
            
        gossip_port = 19001 + port_offset
        client_port = 17001 + port_offset
        
        gossip_address = f"{ip}:{gossip_port}"
        client_address = f"{ip}:{client_port}"
        
        cert_path = os.path.join(val_dir, "node.crt")
        key_path = os.path.join(val_dir, "node.key")
        

        node_data_dir = os.path.join(DATA_DIR, f"node_{idx}")
        os.makedirs(node_data_dir, exist_ok=True)
        

        args = [
            binary_path,
            "--genesis", host_genesis_path,
            "--key-hex", seed_hex,
            "--listen", gossip_address,
            "--client", client_address,
            "--data-dir", node_data_dir
        ]
        
        if running_state["tls_enabled"]:
            args.extend([
                "--tls-cert", cert_path,
                "--tls-key", key_path
            ])
            

        stdout_log_path = os.path.join(node_data_dir, "stdout.log")
        log_file = open(stdout_log_path, "w")
        
        node_id_short = "unknown"
        for val in genesis["validators"]:
            if val["address"] == gossip_address:
                node_id_short = val["pubkey_hex"][:8]
                break
        
        print(f"{C_YELLOW}[orchestrator] Starting Node {idx} ({node_id_short}) at gossip={gossip_address} client={client_address}...{C_RESET}")
        
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_CONSOLE
            
        proc = subprocess.Popen(
            args,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            cwd=ROOT_DIR,
            creationflags=creationflags
        )
        
        running_state["nodes"].append({
            "index": idx,
            "node_id": node_id_short,
            "pid": proc.pid,
            "address": gossip_address,
            "client_address": client_address,
            "log_path": stdout_log_path
        })
        

    with open(STATE_FILE, "w") as f:
        json.dump(running_state, f, indent=2)
        
    print(f"\n{C_GREEN}{C_BOLD}[orchestrator] SUCCESS: {len(validators)} local nodes for host {ip} spawned successfully!{C_RESET}")
    print(f"[orchestrator] Logs and snapshot DB are saved under: {DATA_DIR}")
    print(f"[orchestrator] Keeping orchestrator running to maintain node lifetimes. Press Ctrl+C to stop cluster.\n")
    
    try:
        while True:
            time.sleep(1.5)
            heights = []
            for node in running_state["nodes"]:
                idx = node["index"]
                url = f"http://{node['client_address']}/tip"
                try:
                    with urllib.request.urlopen(url, timeout=0.5) as r:
                        data = json.loads(r.read().decode("utf-8"))
                        heights.append(f"Node {idx}: Height={data['height']}")
                except Exception:
                    heights.append(f"Node {idx}: {C_RED}OFFLINE{C_RESET}")
            
            print(f"\r[live consensus] {' | '.join(heights)}", end="", flush=True)
            
    except KeyboardInterrupt:
        print(f"\n\n{C_YELLOW}[orchestrator] KeyboardInterrupt received. Stopping cluster gracefully...{C_RESET}")
        stop_cluster(clean=False)

def stop_cluster(clean=False):
    print_banner()
    if not os.path.exists(STATE_FILE):
        print(f"{C_YELLOW}[orchestrator] No running cluster state found in {STATE_FILE}.{C_RESET}")
        if clean and os.path.exists(DATA_DIR):
            shutil.rmtree(DATA_DIR)
            print(f"{C_GREEN}[orchestrator] Cleaned {DATA_DIR}{C_RESET}")
        return
        
    with open(STATE_FILE, "r") as f:
        state = json.load(f)
        
    print(f"{C_CYAN}[orchestrator] Stopping all background node processes...{C_RESET}")
    for node in state["nodes"]:
        pid = node["pid"]
        idx = node["index"]
        print(f"[orchestrator] Terminating Node {idx} (PID: {pid})...")
        
        if sys.platform == "win32":

            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
                
    time.sleep(1)
    

    try:
        os.remove(STATE_FILE)
    except OSError:
        pass
        
    print(f"{C_GREEN}[orchestrator] Cluster stopped successfully!{C_RESET}")
    
    if clean:
        try:
            shutil.rmtree(DATA_DIR)
            print(f"{C_GREEN}[orchestrator] Cleaned all cluster data!{C_RESET}")
        except Exception as e:
            print(f"{C_YELLOW}[orchestrator] Warning: Failed to fully clean data folder ({e}){C_RESET}")

def print_status():
    print_banner()
    if not os.path.exists(STATE_FILE):
        print(f"{C_RED}[orchestrator] Status: OFFLINE. No local cluster is running.{C_RESET}")
        return
        
    with open(STATE_FILE, "r") as f:
        state = json.load(f)
        
    print(f"{C_BOLD}Local Cluster Status: {C_GREEN}RUNNING{C_RESET}")
    print(f"Data Directory: {DATA_DIR}")
    print(f"TLS Transport: {'mTLS Enabled (RSA-2048)' if state['tls_enabled'] else 'Insecure/Plaintext'}")
    print("-" * 80)
    print(f"{C_BOLD}{'NODE':<6} {'PID':<8} {'NODE ID':<36} {'GOSSIP ADDR':<18} {'CLIENT API':<18} {'STATUS':<10}{C_RESET}")
    
    all_online = True
    for node in state["nodes"]:
        pid = node["pid"]
        idx = node["index"]
        

        is_running = False
        if sys.platform == "win32":

            tasks = subprocess.check_output(f'tasklist /FI "PID eq {pid}"', shell=True).decode("ascii", errors="ignore")
            is_running = str(pid) in tasks
        else:
            try:
                os.kill(pid, 0)
                is_running = True
            except OSError:
                is_running = False
                
        status_str = f"{C_GREEN}ONLINE{C_RESET}" if is_running else f"{C_RED}DEAD{C_RESET}"
        if not is_running:
            all_online = False
            
        print(f"Node {idx:<3} {pid:<8} {node['node_id'][:32]:<36} {node['address']:<18} {node['client_address']:<18} {status_str:<10}")
        
    print("-" * 80)
    

    if all_online:
        print(f"\n{C_CYAN}[orchestrator] Querying live HTTP client APIs for consensus heights...{C_RESET}")
        print(f"{C_BOLD}{'NODE':<10} {'HEIGHT':<10} {'TIP BLOCK HASH':<66}{C_RESET}")
        for node in state["nodes"]:
            idx = node["index"]
            url = f"http://{node['client_address']}/tip"
            try:
                with urllib.request.urlopen(url, timeout=0.8) as r:
                    data = json.loads(r.read().decode("utf-8"))
                    print(f"Node {idx:<5} {data['height']:<10} {data['hash']:<66}")
            except Exception as e:
                print(f"Node {idx:<5} {C_RED}UNREACHABLE{C_RESET} ({e})")

def build_valid_transaction(prev_hash_hex, author_seed_hex, timestamp, payload_bytes):

    prev_hash = bytes.fromhex(prev_hash_hex)
    if len(prev_hash) != 32:
        raise ValueError("prev_hash must be 32 bytes")
        
    sk_bytes = bytes.fromhex(author_seed_hex)
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(sk_bytes)
    vk = sk.public_key()
    author_pub = vk.public_bytes_raw()
    
    payload_hash = sha256(payload_bytes)
    

    version = 1
    ts_bytes = timestamp.to_bytes(8, byteorder="little")
    
    canonical = bytearray()
    canonical.append(version)
    canonical.extend(prev_hash)
    canonical.extend(author_pub)
    canonical.extend(ts_bytes)
    canonical.extend(payload_hash)
    

    sig = sk.sign(bytes(canonical))
    

    tx = bytearray(canonical)
    tx.extend(sig)
    
    return bytes(tx)

def start_interactive_console():

    if not os.path.exists(STATE_FILE):
        print(f"{C_RED}[orchestrator] ERROR: No cluster is running. Please boot one first.{C_RESET}")
        return
        
    with open(STATE_FILE, "r") as f:
        state = json.load(f)
        

    client_sk = ed25519.Ed25519PrivateKey.generate()
    client_seed = client_sk.private_bytes_raw().hex()
    client_pub = client_sk.public_key().public_bytes_raw().hex()
    
    last_tx_hash = "00" * 32
    
    while True:
        os.system("cls" if sys.platform == "win32" else "clear")
        print_banner()
        print(f"{C_CYAN}{C_BOLD}INTERACTIVE CONSENSUS CONSOLE DASHBOARD (Client Identity: {client_pub[:16]}...){C_RESET}")
        print(f"Data Dir: {DATA_DIR} | TLS: {state['tls_enabled']}")
        print("=" * 80)
        

        print(f"{C_BOLD}{'NODE':<6} {'PID':<8} {'GOSSIP ADDR':<18} {'CLIENT API':<18} {'HEIGHT':<8} {'TIP HASH':<20} {'STATUS':<10}{C_RESET}")
        
        nodes_online = []
        for node in state["nodes"]:
            idx = node["index"]
            pid = node["pid"]
            

            is_running = False
            if sys.platform == "win32":
                tasks = subprocess.check_output(f'tasklist /FI "PID eq {pid}"', shell=True).decode("ascii", errors="ignore")
                is_running = str(pid) in tasks
            else:
                try:
                    os.kill(pid, 0)
                    is_running = True
                except OSError:
                    is_running = False
            
            height = "n/a"
            tip_hash = "n/a"
            status_str = f"{C_GREEN}ONLINE{C_RESET}" if is_running else f"{C_RED}DEAD{C_RESET}"
            
            if is_running:
                nodes_online.append(node)

                url = f"http://{node['client_address']}/tip"
                try:
                    with urllib.request.urlopen(url, timeout=0.5) as r:
                        data = json.loads(r.read().decode("utf-8"))
                        height = str(data["height"])
                        tip_hash = data["hash"]
                except Exception:
                    status_str = f"{C_YELLOW}UNREACHABLE{C_RESET}"
                    
            print(f"Node {idx:<3} {pid:<8} {node['address']:<18} {node['client_address']:<18} {height:<8} {tip_hash[:18]:<20} {status_str:<10}")
            
        print("=" * 80)
        print(f"{C_BOLD}CONSOLE COMMANDS:{C_RESET}")
        print(f"  [{C_GREEN}1{C_RESET}] Refresh Dashboard (Scan Heights & Rounds)")
        print(f"  [{C_GREEN}2{C_RESET}] Broadcast Signed Transaction Event (POST /tx)")
        print(f"  [{C_GREEN}3{C_RESET}] Audit Block Header & Merkle Root (GET /block/<height>)")
        print(f"  [{C_GREEN}4{C_RESET}] Inspect Transaction Event Status (GET /tx/<hash>)")
        print(f"  [{C_GREEN}5{C_RESET}] Export Cluster to Production (Cloud/Docker)")
        print(f"  [{C_GREEN}q{C_RESET}] Quit Console")
        print("=" * 80)
        
        choice = input(f"{C_BOLD}Select choice: {C_RESET}").strip()
        
        if choice == "1":
            print("[console] Scanning...")
            time.sleep(0.5)
            
        elif choice == "2":
            if not nodes_online:
                print(f"{C_RED}No nodes are online to receive transaction!{C_RESET}")
                time.sleep(2)
                continue
                
            print(f"\n{C_CYAN}[console] Broadcaster signed transaction event{C_RESET}")
            payload_str = input(f"Enter transaction custom string payload: ").strip()
            if not payload_str:
                payload_str = f"Console Mock Transaction Event at {time.time()}"
                

            node = nodes_online[0]
            

            prev_hash = "00" * 32
            try:
                with urllib.request.urlopen(f"http://{node['client_address']}/tip", timeout=0.8) as r:
                    tip_data = json.loads(r.read().decode("utf-8"))

                    prev_hash = last_tx_hash
            except Exception:
                pass
                

            timestamp = int(time.time())
            tx_bytes = build_valid_transaction(
                prev_hash_hex=prev_hash,
                author_seed_hex=client_seed,
                timestamp=timestamp,
                payload_bytes=payload_str.encode("utf-8")
            )
            
            tx_hex = tx_bytes.hex()
            

            url = f"http://{node['client_address']}/tx"
            req_data = json.dumps({"tx_hex": tx_hex}).encode("utf-8")
            
            print(f"[console] Sending 169-byte biner transaction (hex: {tx_hex[:24]}...) to Node {node['index']}...")
            
            try:
                req = urllib.request.Request(url, data=req_data, headers={'Content-Type': 'application/json'})
                with urllib.request.urlopen(req, timeout=1.0) as r:
                    resp = json.loads(r.read().decode("utf-8"))
                    tx_h = resp["tx_hash"]
                    last_tx_hash = tx_h
                    print(f"{C_GREEN}[console] Broadcast Success! Tx Hash: {tx_h}{C_RESET}")
                    print(f"[console] Waiting 2 seconds for BFT Consensus round consensus commit...")
                    time.sleep(2.5)
            except Exception as e:
                print(f"{C_RED}[console] Failed to submit transaction: {e}{C_RESET}")
                time.sleep(2)
                
        elif choice == "3":
            h_str = input("Enter block height to audit: ").strip()
            if not h_str.isdigit():
                print(f"{C_RED}Invalid height!{C_RESET}")
                time.sleep(1.5)
                continue
                
            h = int(h_str)
            if not nodes_online:
                print(f"{C_RED}No nodes online.{C_RESET}")
                time.sleep(1.5)
                continue
                

            node = nodes_online[0]
            url = f"http://{node['client_address']}/block/{h}"
            try:
                with urllib.request.urlopen(url, timeout=1.0) as r:
                    block = json.loads(r.read().decode("utf-8"))
                    print(f"\n{C_CYAN}{C_BOLD}--- BLOCK AUDIT AT HEIGHT {h} ---{C_RESET}")
                    print(f"Block Hash:        {block['block_hash']}")
                    print(f"Previous Block:    {block['prev_block_hash']}")
                    print(f"Proposer Node ID:  {block['proposer_id']}")
                    print(f"Transaction Root:  {block['tx_root']}")
                    print(f"Timestamp MS:      {block['timestamp_ms']} ({datetime.datetime.fromtimestamp(block['timestamp_ms']/1000.0)})")
                    print(f"Consensus Round:   {block['round']}")
                    print(f"Tx Hashes Count:   {len(block['tx_hashes'])}")
                    for idx, th in enumerate(block['tx_hashes']):
                        print(f"  Tx [{idx}]: {th}")
                    print("-" * 80)
                    input("\nPress Enter to return to console...")
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    print(f"{C_YELLOW}[console] Block not found at height {h} (consensus not reached or empty block).{C_RESET}")
                else:
                    print(f"{C_RED}[console] Error fetching block: {e}{C_RESET}")
                time.sleep(2)
            except Exception as e:
                print(f"{C_RED}[console] Connection error: {e}{C_RESET}")
                time.sleep(2)
                
        elif choice == "4":
            tx_h = input("Enter transaction hash to check status: ").strip()
            if not tx_h:
                continue
            if not nodes_online:
                print(f"{C_RED}No nodes online.{C_RESET}")
                time.sleep(1.5)
                continue
                
            node = nodes_online[0]
            url = f"http://{node['client_address']}/tx/{tx_h}"
            try:
                with urllib.request.urlopen(url, timeout=1.0) as r:
                    status = json.loads(r.read().decode("utf-8"))
                    print(f"\n{C_CYAN}{C_BOLD}--- TRANSACTION STATUS ---{C_RESET}")
                    print(f"Tx Hash:     {tx_h}")
                    print(f"Status:      {C_GREEN}{status['status'].upper()}{C_RESET}")
                    print(f"Block Height: {status['height']}")
                    print(f"Block Hash:  {status['block_hash']}")
                    print("-" * 80)
                    input("\nPress Enter to return...")
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    print(f"{C_YELLOW}[console] Transaction not found/uncommitted yet.{C_RESET}")
                else:
                    print(f"{C_RED}[console] Error fetching status: {e}{C_RESET}")
                time.sleep(2)
            except Exception as e:
                print(f"{C_RED}[console] Connection error: {e}{C_RESET}")
                time.sleep(2)
                
        elif choice == "5":
            export_cluster_production()
            
        elif choice.lower() == "q":
            break

def export_cluster_production(ips_list=None):

    print_banner()
    print(f"{C_CYAN}[exporter] Production Cloud Exporter Configurator{C_RESET}")
    print("This will create a deployment pack under `dist/` directory.")
    
    if ips_list is not None:
        ips = ips_list
    else:
        ips_input = input("Enter comma-separated public IPs of validators (e.g. 192.168.1.10,192.168.1.11,192.168.1.12,192.168.1.13): ").strip()
        if not ips_input:
            print(f"{C_RED}ERROR: IP list cannot be empty.{C_RESET}")
            time.sleep(2)
            return
        ips = [ip.strip() for ip in ips_input.split(",") if ip.strip()]
    num_nodes = len(ips)
    if num_nodes < 4:
        print(f"{C_YELLOW}Warning: Consensuses under 4 nodes ($3f+1$ with $f>=1$) are not BFT Byzantine Fault Tolerant. Proceeding...{C_RESET}")
        
    dist_dir = os.path.join(ROOT_DIR, "dist")
    if os.path.exists(dist_dir):
        shutil.rmtree(dist_dir)
    os.makedirs(dist_dir, exist_ok=True)
    

    nodes_config = []
    validators_genesis = []
    
    print(f"[exporter] Deriving cryptographic certificates for IPs: {ips}...")
    
    ip_gossip_ports = {}
    ip_client_ports = {}
    
    for i, ip in enumerate(ips):

        gossip_port = ip_gossip_ports.get(ip, 19001)
        client_port = ip_client_ports.get(ip, 17001)
        

        ip_gossip_ports[ip] = gossip_port + 1
        ip_client_ports[ip] = client_port + 1
        
        host = f"validator-{i}"
        
        keys = generate_node_keys(ip, host)
        
        node_conf = {
            "node_index": i,
            "node_id": keys["node_id"],
            "seed_hex": keys["seed_hex"],
            "pub_hex": keys["pub_hex"],
            "ip": ip,
            "address": f"{ip}:{gossip_port}",
            "client_address": f"{ip}:{client_port}",
            "cert_pem": keys["cert_pem"],
            "key_pem": keys["key_pem"],
            "cert_hex": keys["cert_hex"]
        }
        nodes_config.append(node_conf)
        
        val_genesis = {
            "pubkey_hex": keys["pub_hex"],
            "address": f"{ip}:{gossip_port}",
            "power": 10,
            "stake": 1000000,
            "tls_cert_hex": keys["cert_hex"]
        }
        validators_genesis.append(val_genesis)
        

    genesis = {
        "chain_id": "dvel-bft-prod-net",
        "validators": validators_genesis,
        "consensus": {
            "max_block_bytes": 1048576,
            "max_events": 5000,
            "target_block_ms": 2000,
            "propose_timeout_ms": 3000,
            "prevote_timeout_ms": 2000,
            "precommit_timeout_ms": 2000,
            "timeout_backoff_num": 3,
            "timeout_backoff_den": 2,
            "timeout_cap_ms": 30000,
            "slashing": {
                "enabled": True,
                "double_sign_percent": 5,
                "invalid_proposal_percent": 1,
                "jail_duration_blocks": 1000
            }
        },
        "client": {
            "listen_addr": "0.0.0.0:7001"
        },
        "transport": {
            "tls_enabled": True
        }
    }
    
    prod_genesis_path = os.path.join(dist_dir, "genesis.json")
    with open(prod_genesis_path, "w") as f:
        json.dump(genesis, f, indent=2)
        

    def dump_yaml(data, indent=0):
        lines = []
        spacing = "  " * indent
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{spacing}{k}:")
                    lines.append(dump_yaml(v, indent + 1))
                else:
                    if isinstance(v, str):
                        lines.append(f"{spacing}{k}: \"{v}\"")
                    elif v is None:
                        lines.append(f"{spacing}{k}: null")
                    else:
                        lines.append(f"{spacing}{k}: {str(v).lower()}")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    pass
                else:
                    lines.append(f"{spacing}- \"{item}\"")
        return "\n".join(lines)
        

    host_groups = {}
    for conf in nodes_config:
        ip = conf["ip"]
        if ip not in host_groups:
            host_groups[ip] = []
        host_groups[ip].append(conf)
        
    for ip, group in host_groups.items():

        ip_clean = ip.replace(".", "_")
        host_dir = os.path.join(dist_dir, f"host_{ip_clean}")
        os.makedirs(host_dir, exist_ok=True)
        

        shutil.copy(prod_genesis_path, os.path.join(host_dir, "genesis.json"))
        

        for conf in group:
            idx = conf["node_index"]
            val_dir = os.path.join(host_dir, f"validator_{idx}")
            os.makedirs(val_dir, exist_ok=True)
            

            shutil.copy(prod_genesis_path, os.path.join(val_dir, "genesis.json"))
            

            with open(os.path.join(val_dir, "node.crt"), "w") as f:
                f.write(conf["cert_pem"])
            with open(os.path.join(val_dir, "node.key"), "w") as f:
                f.write(conf["key_pem"])
            with open(os.path.join(val_dir, "node.seed"), "w") as f:
                f.write(conf["seed_hex"])
                

        compose = {
            "version": "3.8",
            "services": {}
        }
        
        for conf in group:
            idx = conf["node_index"]
            service_name = f"dvel-validator-{idx}"
            

            gossip_port = conf["address"].split(":")[1]
            client_port = conf["client_address"].split(":")[1]
            
            compose["services"][service_name] = {
                "image": "dvel-bft-node:latest",
                "container_name": service_name,
                "network_mode": "host",
                "restart": "always",
                "volumes": [
                    f"./validator_{idx}/genesis.json:/etc/dvel/genesis.json:ro",
                    f"./validator_{idx}/node.crt:/etc/dvel/node.crt:ro",
                    f"./validator_{idx}/node.key:/etc/dvel/node.key:ro",
                    f"dvel-data-{idx}:/var/lib/dvel"
                ],
                "command": [
                    "--genesis", "/etc/dvel/genesis.json",
                    "--key-hex", conf["seed_hex"],
                    "--listen", f"0.0.0.0:{gossip_port}",
                    "--client", f"0.0.0.0:{client_port}",
                    "--data-dir", "/var/lib/dvel",
                    "--tls-cert", "/etc/dvel/node.crt",
                    "--tls-key", "/etc/dvel/node.key"
                ]
            }
            
        compose["volumes"] = {f"dvel-data-{conf['node_index']}": None for conf in group}
        
        compose_path = os.path.join(host_dir, "docker-compose.yml")
        with open(compose_path, "w") as f:
            f.write(f"# DVEL Multi-Node mTLS Production Cluster for host {ip}\n")
            f.write("# Run: docker-compose up -d on this host machine\n\n")
            f.write(dump_yaml(compose))
            
    print(f"\n{C_GREEN}{C_BOLD}[exporter] SUCCESS: Cloud deployment package generated under: {dist_dir}{C_RESET}")
    print(f"[exporter] Grouped configurations by host IPs: {list(host_groups.keys())}")
    print(f"[exporter] Generates host-specific docker-compose.yml files.")
    if ips_list is None:
        input("\nPress Enter to return...")

def main():
    if len(sys.argv) < 2:
        print_banner()
        print("Usage:")
        print("  python scripts/run_local_cluster.py start      - Build and start local 4-node mTLS BFT cluster")
        print("  python scripts/run_local_cluster.py start-host [IP] - Start subset of validator nodes for a specific IP")
        print("  python scripts/run_local_cluster.py stop       - Gracefully terminate background nodes")
        print("  python scripts/run_local_cluster.py status     - Query cluster state and block heights")
        print("  python scripts/run_local_cluster.py console    - Cinematic CLI interactive control dashboard")
        print("  python scripts/run_local_cluster.py export [IPs] - Generate production multi-validator config")
        print("  python scripts/run_local_cluster.py clean      - Stop cluster and wipe all database state")
        sys.exit(0)
        
    mode = sys.argv[1].lower()
    
    if mode == "start":
        start_cluster()
    elif mode == "start-host":
        if len(sys.argv) < 3:
            print(f"{C_RED}ERROR: Please specify the host IP to start (e.g. 192.168.1.9){C_RESET}")
            sys.exit(1)
        start_host_cluster(sys.argv[2])
    elif mode == "stop":
        stop_cluster(clean=False)
    elif mode == "status":
        print_status()
    elif mode == "console":
        start_interactive_console()
    elif mode == "export":
        ips_list = None
        if len(sys.argv) >= 3:
            ips_list = [ip.strip() for ip in sys.argv[2].split(",") if ip.strip()]
        export_cluster_production(ips_list)
    elif mode == "clean":
        stop_cluster(clean=True)
    else:
        print(f"Unknown mode: {mode}")

if __name__ == "__main__":
    main()
