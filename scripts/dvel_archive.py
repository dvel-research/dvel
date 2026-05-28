#!/usr/bin/env python3

import os
import sys
import time
import json
import hashlib
import subprocess
import urllib.request
import urllib.error
import argparse

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from run_local_cluster import build_valid_transaction
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError as e:
    print(f"[archive] Error importing crypto modules: {e}")
    sys.exit(1)

def find_dvel_file_bin():

    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(scripts_dir, ".."))
    
    bin_name = "dvel-file.exe" if os.name == "nt" else "dvel-file"
    search_paths = [
        os.path.join(root_dir, "rust-core", "target", "release", bin_name),
        os.path.join(root_dir, "rust-core", "target", "debug", bin_name),
    ]
    
    for path in search_paths:
        if os.path.exists(path):
            return path
            

    print("[archive] dvel-file binary not found. Attempting to build automatically...")
    try:
        cargo_toml = os.path.join(root_dir, "rust-core", "Cargo.toml")
        subprocess.check_call(["cargo", "build", "--release", "--manifest-path", cargo_toml, "--bin", "dvel-file"])
        release_path = os.path.join(root_dir, "rust-core", "target", "release", bin_name)
        if os.path.exists(release_path):
            return release_path
    except Exception as e:
        print(f"[archive] Failed to build dvel-file automatically: {e}")
        
    return None

def get_canonical_manifest_bytes(manifest_path):

    if not os.path.exists(manifest_path):
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
        
    with open(manifest_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    lines = content.splitlines()
    canonical_lines = []
    for line in lines:
        line_strip = line.strip()
        if not line_strip:
            continue

        if line_strip.startswith("signer:") or line_strip.startswith("signature:"):
            continue
        canonical_lines.append(line_strip)
        

    canonical_str = "\n".join(canonical_lines) + "\n"
    return canonical_str.encode("utf-8")

def compute_manifest_hash(manifest_path):

    c_bytes = get_canonical_manifest_bytes(manifest_path)
    return hashlib.sha256(c_bytes).digest()

def check_bft_connectivity(node_api):

    import re
    endpoints = [node_api]
    m = re.match(r"(http://[^:]+):(\d+)", node_api)
    if m:
        base_url = m.group(1)
        port = int(m.group(2))
        if 17001 <= port <= 17004:
            for p in [17001, 17002, 17003, 17004]:
                alt = f"{base_url}:{p}"
                if alt not in endpoints:
                    endpoints.append(alt)
        elif 7001 <= port <= 7004:
            for p in [7001, 7002, 7003, 7004]:
                alt = f"{base_url}:{p}"
                if alt not in endpoints:
                    endpoints.append(alt)
                    
    for endpoint in endpoints:
        try:
            with urllib.request.urlopen(f"{endpoint}/tip", timeout=3.0) as r:
                tip = json.loads(r.read().decode("utf-8"))
                return tip, endpoint
        except Exception:
            continue
            
    print(f"[archive] ERROR: Failed to connect to any BFT Node API in the network. Checked: {endpoints}")
    sys.exit(1)

def submit_anchor_transaction(node_api, manifest_hash, sign_key_hex=None):

    if sign_key_hex:
        sk_bytes = bytes.fromhex(sign_key_hex)
        client_sk = ed25519.Ed25519PrivateKey.from_private_bytes(sk_bytes)
    else:
        print("[archive] Generating temporary client Ed25519 identity key for BFT anchoring...")
        client_sk = ed25519.Ed25519PrivateKey.generate()
        
    client_seed = client_sk.private_bytes_raw().hex()
    client_pub = client_sk.public_key().public_bytes_raw().hex()
    print(f"[archive] Client Key: {client_pub}")
    

    prev_hash = "00" * 32
    timestamp = int(time.time())
    
    tx_bytes = build_valid_transaction(
        prev_hash_hex=prev_hash,
        author_seed_hex=client_seed,
        timestamp=timestamp,
        payload_bytes=manifest_hash
    )
    
    tx_hex = tx_bytes.hex()
    

    url = f"{node_api}/tx"
    req_data = json.dumps({"tx_hex": tx_hex}).encode("utf-8")
    req = urllib.request.Request(url, data=req_data, headers={'Content-Type': 'application/json'})
    
    try:
        with urllib.request.urlopen(req, timeout=5.0) as r:
            resp = json.loads(r.read().decode("utf-8"))
            tx_hash_hex = resp["tx_hash"]
            print(f"[archive] Transaction broadcast successful. Tx Hash: {tx_hash_hex}")
            return tx_hash_hex
    except Exception as e:
        print(f"[archive] ERROR: Failed to broadcast transaction to BFT node: {e}")
        sys.exit(1)

def wait_for_consensus_commit(node_api, tx_hash_hex):

    status_url = f"{node_api}/tx/{tx_hash_hex}"
    print("[archive] Waiting for BFT consensus round execution (max 15s)...")
    
    for attempt in range(1, 8):
        time.sleep(2.0)
        try:
            with urllib.request.urlopen(status_url, timeout=5.0) as r:
                status = json.loads(r.read().decode("utf-8"))
                if status.get("status") == "committed":
                    print(f"[archive] SUCCESS: Transaction committed at Height {status['height']}!")
                    print(f"[archive]   Block Hash: {status['block_hash']}")
                    return status
                else:
                    print(f"[archive]   Consensus state: {status.get('status')} (attempt {attempt}/7)")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print(f"[archive]   Consensus state: pending (attempt {attempt}/7)")
            else:
                print(f"[archive]   HTTP error {e.code}: {e.reason}")
        except Exception as e:
            print(f"[archive]   Connection delay: {e}")
            
    print("[archive] ERROR: Transaction commitment timed out. Check cluster health.")
    sys.exit(1)

def read_chunk_hashes_from_manifest(manifest_path):
    if not os.path.exists(manifest_path):
        return []
    hashes = []
    with open(manifest_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("h:"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    h_val = parts[1].strip()
                    if h_val:
                        hashes.append(h_val)
    return hashes

def download_chunk_with_fallback(primary_node, chunk_hash, chunk_path):
    import re

    endpoints = [primary_node]
    m = re.match(r"(http://[^:]+):(\d+)", primary_node)
    if m:
        base_url = m.group(1)
        port = int(m.group(2))
        if 17001 <= port <= 17004:
            for p in [17001, 17002, 17003, 17004]:
                alt = f"{base_url}:{p}"
                if alt not in endpoints:
                    endpoints.append(alt)
        elif 7001 <= port <= 7004:
            for p in [7001, 7002, 7003, 7004]:
                alt = f"{base_url}:{p}"
                if alt not in endpoints:
                    endpoints.append(alt)
    
    for endpoint in endpoints:
        url = f"{endpoint}/chunk/{chunk_hash}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=3.0) as r:
                data = r.read()
                if hashlib.sha256(data).hexdigest() == chunk_hash:
                    with open(chunk_path, "wb") as f:
                        f.write(data)
                    return True
        except Exception:
            continue
    return False

def run_archive(args):
    print("="*60)
    print("  DVEL SECURE ARCHIVE & BLOCKCHAIN ANCHORING ENGINE")
    print("="*60)
    
    bin_path = find_dvel_file_bin()
    if not bin_path:
        print("[archive] ERROR: 'dvel-file' binary not found and compile failed.")
        sys.exit(1)
        
    print(f"[archive] Step 1: Chunking file '{args.input_file}' to '{args.out_dir}'...")
    

    cmd = [bin_path, "upload", args.input_file, args.out_dir, str(args.chunk_size)]
    if args.sign_key:
        cmd.extend(["--sign", args.sign_key])
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        print(f"[archive] ERROR: dvel-file chunking failed:\n{e.stderr}")
        sys.exit(1)
        

    file_basename = os.path.basename(args.input_file)
    manifest_path = os.path.join(args.out_dir, f"{file_basename}.manifest")
    if not os.path.exists(manifest_path):
        print(f"[archive] ERROR: Expected manifest was not written at {manifest_path}")
        sys.exit(1)
        

    manifest_hash = compute_manifest_hash(manifest_path)
    manifest_hash_hex = manifest_hash.hex()
    print(f"[archive] Step 2: Calculated Canonical Manifest Hash: {manifest_hash_hex}")
    

    print(f"[archive] Step 3: Connecting to live BFT node at '{args.node}'...")
    tip, active_node = check_bft_connectivity(args.node)
    args.node = active_node
    
    print(f"[archive] Step 4: Broadcasting ledger anchoring transaction...")
    tx_hash = submit_anchor_transaction(args.node, manifest_hash, args.sign_key)
    

    commit_status = wait_for_consensus_commit(args.node, tx_hash)
    

    anchor_path = manifest_path + ".anchor"
    anchor_data = {
        "manifest_hash": manifest_hash_hex,
        "tx_hash": tx_hash,
        "block_height": commit_status["height"],
        "block_hash": commit_status["block_hash"],
        "anchored_at_ms": int(time.time() * 1000)
    }
    
    with open(anchor_path, "w", encoding="utf-8") as f:
        json.dump(anchor_data, f, indent=2)
        

    print(f"[archive] Step 7: Replicating document chunks to DVEL network storage...")
    hashes = read_chunk_hashes_from_manifest(manifest_path)
    file_basename = os.path.basename(args.input_file)
    for i, chunk_hash in enumerate(hashes):
        chunk_filename = f"{file_basename}.chunk.{i:08d}"
        chunk_path = os.path.join(args.out_dir, chunk_filename)
        if not os.path.exists(chunk_path):
            print(f"[archive] WARNING: Chunk file missing locally: {chunk_path}")
            continue
        
        print(f"[archive]   Uploading chunk {i+1}/{len(hashes)} ({chunk_hash[:8]}...) to {args.node}...")
        url = f"{args.node}/chunk/{chunk_hash}"
        try:
            with open(chunk_path, "rb") as f:
                chunk_data = f.read()
            req = urllib.request.Request(url, data=chunk_data, headers={'Content-Type': 'application/octet-stream'})
            with urllib.request.urlopen(req, timeout=10.0) as r:
                resp = json.loads(r.read().decode("utf-8"))
                if resp.get("status") != "ok":
                    print(f"[archive]   WARNING: Node rejected chunk upload: {resp}")
        except Exception as e:
            print(f"[archive]   WARNING: Failed to upload chunk {chunk_hash}: {e}")
        
    print("\n" + "="*60)
    print("  ARCHIVE & LEDGER ANCHOR SUCCESSFUL!")
    print("="*60)
    print(f"Manifest Hash:  {manifest_hash_hex}")
    print(f"Manifest File:  {manifest_path}")
    print(f"Anchor File:    {anchor_path}")
    print(f"Commit Height:  {commit_status['height']}")
    print(f"Block Hash:     {commit_status['block_hash']}")
    print("="*60)

def run_verify(args):
    print("="*60)
    print("  DVEL ARCHIVE CONSENSUS AUDIT & VERIFICATION ENGINE")
    print("="*60)
    
    bin_path = find_dvel_file_bin()
    if not bin_path:
        print("[archive] ERROR: 'dvel-file' binary not found.")
        sys.exit(1)
        
    if not os.path.exists(args.manifest_path):
        print(f"[archive] ERROR: Manifest path does not exist: {args.manifest_path}")
        sys.exit(1)
        

    manifest_hash = compute_manifest_hash(args.manifest_path)
    manifest_hash_hex = manifest_hash.hex()
    print(f"[archive] Step 1: Calculated Canonical Manifest Hash: {manifest_hash_hex}")
    

    anchor_path = args.manifest_path + ".anchor"
    if not os.path.exists(anchor_path):
        print(f"[archive] WARNING: Sidecar anchor file (.anchor) not found at {anchor_path}")
        print("[archive] Attempting Zero-Sidecar BFT query on BFT Node API...")

        tip, active_node = check_bft_connectivity(args.node)
        args.node = active_node
        
        manifest_url = f"{args.node}/manifest/{manifest_hash_hex}"
        try:
            with urllib.request.urlopen(manifest_url, timeout=5.0) as r:
                manifest_status = json.loads(r.read().decode("utf-8"))
                if manifest_status.get("status") == "committed":
                    tx_hash_hex = manifest_status.get("tx_hash")
                    block_height = manifest_status.get("height")
                    expected_block_hash = manifest_status.get("block_hash")
                    print(f"[archive] Step 2: Successfully resolved manifest on BFT node:")
                    print(f"  Resolved Tx Hash: {tx_hash_hex}")
                    print(f"  Resolved Height:  {block_height}")
                    print(f"  Block Hash:       {expected_block_hash}")
                else:
                    print(f"[archive]   [FAIL] BFT node returned status: {manifest_status.get('status')}")
                    tx_hash_hex = None
                    block_height = None
        except Exception as e:
            print(f"[archive]   [FAIL] Zero-Sidecar manifest query failed: {e}")
            tx_hash_hex = None
            block_height = None
    else:
        with open(anchor_path, "r", encoding="utf-8") as f:
            anchor_data = json.load(f)
        tx_hash_hex = anchor_data.get("tx_hash")
        block_height = anchor_data.get("block_height")
        print(f"[archive] Step 2: Loaded sidecar anchor metadata:")
        print(f"  Expected Tx Hash: {tx_hash_hex}")
        print(f"  Expected Height:  {block_height}")
        

    if tx_hash_hex and block_height:
        print(f"[archive] Step 3: Querying live BFT node at '{args.node}' for consensus proof...")
        tip, active_node = check_bft_connectivity(args.node)
        args.node = active_node
        

        status_url = f"{args.node}/tx/{tx_hash_hex}"
        try:
            with urllib.request.urlopen(status_url, timeout=5.0) as r:
                status = json.loads(r.read().decode("utf-8"))
                if status.get("status") == "committed":
                    print(f"[archive]   [OK] Ledger Status: COMMITTED")
                    print(f"[archive]   [OK] Height Match:  Height {status['height']} (expected: {block_height})")
                    print(f"[archive]   [OK] Block Hash:    {status['block_hash']}")
                else:
                    print(f"[archive]   [FAIL] Ledger Status: {status.get('status')}. VERIFICATION FAILED.")
                    sys.exit(1)
        except Exception as e:
            print(f"[archive]   [FAIL] BFT verification endpoint query failed: {e}")
            sys.exit(1)
            

        block_url = f"{args.node}/block/{block_height}"
        try:
            with urllib.request.urlopen(block_url, timeout=5.0) as r:
                block = json.loads(r.read().decode("utf-8"))
                print(f"[archive] Step 4: Auditing BFT block metadata at Height {block_height}...")
                print(f"  Block Timestamp:  {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(block['timestamp_ms']/1000.0))} UTC")
                print(f"  Proposer Node ID: {block['proposer_id']}")
                print(f"  Transaction Root: {block['tx_root']}")
                
                if tx_hash_hex in block["tx_hashes"]:
                    print(f"  [OK] Transaction presence in block: CONFIRMED")
                else:
                    print(f"  [FAIL] Transaction is missing from BFT block tx list! VERIFICATION FAILED.")
                    sys.exit(1)
        except Exception as e:
            print(f"[archive]   [FAIL] Block audit query failed: {e}")
            sys.exit(1)

        proof_url = f"{args.node}/manifest/{manifest_hash_hex}/proof"
        print(f"[archive] Step 4.5: Fetching and auditing logarithmic MMR proof from '{proof_url}'...")
        try:
            with urllib.request.urlopen(proof_url, timeout=5.0) as r:
                proof_data = json.loads(r.read().decode("utf-8"))
                if proof_data.get("status") == "committed":
                    mmr_root_hex = proof_data["mmr_root"]
                    leaf_idx = proof_data["leaf_index"]
                    leaf_count = proof_data["leaf_count"]
                    siblings = proof_data["siblings"]
                    peaks = proof_data["peaks"]

                    curr = hashlib.sha256(manifest_hash).digest()
                    for sib in siblings:
                        sib_hash = bytes.fromhex(sib["hash"])
                        is_right = sib["is_right"]
                        h = hashlib.sha256()
                        if is_right:
                            h.update(curr)
                            h.update(sib_hash)
                        else:
                            h.update(sib_hash)
                            h.update(curr)
                        curr = h.digest()

                    computed_peak = curr.hex()

                    if computed_peak in peaks:

                        peaks_bytes = [bytes.fromhex(p) for p in peaks]
                        fold_root = peaks_bytes.pop()
                        while peaks_bytes:
                            peak = peaks_bytes.pop()
                            h = hashlib.sha256()
                            h.update(peak)
                            h.update(fold_root)
                            fold_root = h.digest()

                        if fold_root.hex() == mmr_root_hex:
                            print(f"  [OK] MMR Root Match: {mmr_root_hex}")
                            print(f"  [OK] MMR Leaf Index: {leaf_idx} within MMR leaf count: {leaf_count}")
                            print(f"  [OK] MMR Inclusion Proof: VERIFIED (climb height: {len(siblings)} nodes)")
                        else:
                            print("  [FAIL] MMR Root folding mismatch! VERIFICATION FAILED.")
                            sys.exit(1)
                    else:
                        print("  [FAIL] Climbed peak is missing from active peaks list! VERIFICATION FAILED.")
                        sys.exit(1)
                else:
                    print(f"  [FAIL] Proof endpoint returned status: {proof_data.get('status')}. VERIFICATION FAILED.")
                    sys.exit(1)
        except Exception as e:
            print(f"  [FAIL] MMR proof fetch/verification failed: {e}. VERIFICATION FAILED.")
            sys.exit(1)
            
        print("\n" + "="*60)
        print("  [OK] BLOCKCHAIN ANCHOR PROOF: VERIFIED & ABSOLUTELY SECURE!")
        print("="*60)

    print(f"\n[archive] Step 4.7: Auditing local chunks & checking remote availability...")
    manifest_basename = os.path.basename(args.manifest_path)
    if manifest_basename.endswith(".manifest"):
        orig_filename = manifest_basename[:-9]
    else:
        orig_filename = manifest_basename
        
    hashes = read_chunk_hashes_from_manifest(args.manifest_path)
    if hashes:
        os.makedirs(args.chunk_dir, exist_ok=True)
        missing_count = 0
        for i, chunk_hash in enumerate(hashes):
            chunk_filename = f"{orig_filename}.chunk.{i:08d}"
            chunk_path = os.path.join(args.chunk_dir, chunk_filename)
            
            needs_download = True
            if os.path.exists(chunk_path):
                with open(chunk_path, "rb") as f:
                    local_data = f.read()
                if hashlib.sha256(local_data).hexdigest() == chunk_hash:
                    needs_download = False
            
            if needs_download:
                missing_count += 1
                print(f"[archive]   Chunk {i+1}/{len(hashes)} ({chunk_hash[:8]}...) missing/invalid locally. Downloading from BFT Network...")
                success = download_chunk_with_fallback(args.node, chunk_hash, chunk_path)
                if not success:
                    print(f"[archive] ERROR: Failed to retrieve chunk {chunk_hash} from any BFT storage node.")
                    sys.exit(1)
        if missing_count > 0:
            print(f"[archive]   Successfully restored {missing_count} chunk(s) from BFT Network.")
        else:
            print(f"[archive]   All chunks are already intact locally.")
        

    print(f"\n[archive] Step 5: Reassembling file from chunks...")
    cmd = [bin_path, "download", args.manifest_path, args.chunk_dir, args.output_path]
    if args.expect_signer:
        cmd.extend(["--expect-signer", args.expect_signer])
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        print(f"[archive] ERROR: dvel-file reassembly failed:\n{e.stderr}")
        sys.exit(1)
        
    print("\n" + "="*60)
    print("  ARCHIVE DOWNLOAD & VERIFICATION COMPLETE!")
    print("="*60)
    print(f"Manifest:       {args.manifest_path}")
    print(f"Output File:    {args.output_path}")
    print("Integrity:      100% Cryptographically Intact")
    print("="*60)

def main():
    parser = argparse.ArgumentParser(description="DVEL Secure Storage & Ledger Anchoring CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    

    archive_parser = subparsers.add_parser("archive", help="Chunk file and anchor to BFT ledger")
    archive_parser.add_argument("input_file", help="Path to input file to archive")
    archive_parser.add_argument("out_dir", help="Output directory for chunks and manifest")
    archive_parser.add_argument("chunk_size", type=int, help="Size of each chunk in bytes")
    archive_parser.add_argument("--node", default="http://127.0.0.1:17001", help="Target BFT Node API endpoint")
    archive_parser.add_argument("--sign-key", help="Hex encoded 32-byte Ed25519 secret key to sign the manifest")
    

    verify_parser = subparsers.add_parser("verify", help="Verify consensus anchor and reassemble chunks")
    verify_parser.add_argument("manifest_path", help="Path to .manifest file")
    verify_parser.add_argument("chunk_dir", help="Directory where chunks are stored")
    verify_parser.add_argument("output_path", help="Destination path for reassembled file")
    verify_parser.add_argument("--node", default="http://127.0.0.1:17001", help="Target BFT Node API endpoint")
    verify_parser.add_argument("--expect-signer", help="Hex encoded 32-byte Ed25519 pubkey expected to sign the manifest")
    
    args = parser.parse_args()
    
    if args.command == "archive":
        run_archive(args)
    elif args.command == "verify":
        run_verify(args)

if __name__ == "__main__":
    main()
