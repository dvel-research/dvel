import os
import sys
import time
import json
import urllib.request
import urllib.error

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from run_local_cluster import build_valid_transaction, sha256
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

def main():
    print("=== DVEL Transaction Submission and Consensus Verification ===")
    

    client_sk = ed25519.Ed25519PrivateKey.generate()
    client_seed = client_sk.private_bytes_raw().hex()
    client_pub = client_sk.public_key().public_bytes_raw().hex()
    print(f"Client Public Key: {client_pub}")
    

    node_api = "http://127.0.0.1:17001"
    if len(sys.argv) > 1:
        node_api = sys.argv[1]
    
    print(f"Connecting to DVEL Node API: {node_api}")
    try:
        with urllib.request.urlopen(f"{node_api}/tip", timeout=5.0) as r:
            tip = json.loads(r.read().decode("utf-8"))
            print(f"Connected to Node 0. Current Tip Height: {tip['height']}, Hash: {tip['hash']}")
    except Exception as e:
        print(f"Failed to connect to Node 0 at {node_api}: {e}")
        sys.exit(1)
        

    prev_hash = "00" * 32
    timestamp = int(time.time())
    payload = b"Verification transaction payload - hello BFT consensus!"
    
    tx_bytes = build_valid_transaction(
        prev_hash_hex=prev_hash,
        author_seed_hex=client_seed,
        timestamp=timestamp,
        payload_bytes=payload
    )
    
    tx_hex = tx_bytes.hex()
    print(f"Generated 169-byte transaction hex: {tx_hex}")
    

    url = f"{node_api}/tx"
    req_data = json.dumps({"tx_hex": tx_hex}).encode("utf-8")
    req = urllib.request.Request(url, data=req_data, headers={'Content-Type': 'application/json'})
    
    try:
        with urllib.request.urlopen(req, timeout=10.0) as r:
            resp = json.loads(r.read().decode("utf-8"))
            tx_hash_hex = resp["tx_hash"]
            print(f"Successfully broadcast transaction. Returned Tx Hash: {tx_hash_hex}")
    except Exception as e:
        print(f"Failed to broadcast transaction: {e}")
        sys.exit(1)
        

    print("Waiting 4 seconds for BFT consensus round execution...")
    time.sleep(4.0)
    

    status_url = f"{node_api}/tx/{tx_hash_hex}"
    status = None
    block_height = None
    
    print("Querying transaction status...")
    for attempt in range(1, 6):
        try:
            with urllib.request.urlopen(status_url, timeout=10.0) as r:
                status = json.loads(r.read().decode("utf-8"))
                if status.get("status") == "committed":
                    print(f"\nTransaction Status Check (Attempt {attempt}):")
                    print(f"  Status: {status['status']}")
                    print(f"  Height: {status['height']}")
                    print(f"  Block Hash: {status['block_hash']}")
                    block_height = status['height']
                    break
                else:
                    print(f"Transaction status is {status.get('status')}. Waiting 2 seconds (Attempt {attempt}/5)...")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print(f"Transaction not committed yet (404). Waiting 2 seconds (Attempt {attempt}/5)...")
            else:
                print(f"HTTP Error {e.code}: {e.reason}. Waiting 2 seconds (Attempt {attempt}/5)...")
        except Exception as e:
            print(f"Connection issue or timeout: {e}. Waiting 2 seconds (Attempt {attempt}/5)...")
        
        if attempt < 5:
            time.sleep(2.0)
            
    if block_height is None:
        print("\nERROR: Failed to verify transaction commitment after multiple attempts.")
        sys.exit(1)
        

    block_url = f"{node_api}/block/{block_height}"
    try:
        with urllib.request.urlopen(block_url, timeout=10.0) as r:
            block = json.loads(r.read().decode("utf-8"))
            print(f"\nBlock Audit at Height {block_height}:")
            print(f"  Block Hash:        {block['block_hash']}")
            print(f"  Prev Block Hash:   {block['prev_block_hash']}")
            print(f"  Proposer Node ID:  {block['proposer_id']}")
            print(f"  Transaction Root:  {block['tx_root']}")
            print(f"  Transactions count: {len(block['tx_hashes'])}")
            print(f"  Included Tx Hash:  {block['tx_hashes'][0] if block['tx_hashes'] else 'NONE'}")
            
            if tx_hash_hex in block['tx_hashes']:
                print("\nSUCCESS: Transaction was successfully verified and committed by the BFT Consensus cluster!")
            else:
                print("\nERROR: Transaction is missing from the block transaction list.")
                sys.exit(1)
    except Exception as e:
        print(f"Failed to query block: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
