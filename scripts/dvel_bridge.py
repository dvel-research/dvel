#!/usr/bin/env python3

import os
import sys
import json
import time
import argparse
import subprocess
import urllib.request
import urllib.error

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("[bridge] 'pyserial' not installed. Attempting to install automatically...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyserial"])
        import serial
        import serial.tools.list_ports
        print("[bridge] 'pyserial' installed successfully!")
    except Exception as e:
        print("[bridge] Failed to install 'pyserial' automatically. Please run: pip install pyserial")
        sys.exit(1)

def find_esp32_port():

    ports = list(serial.tools.list_ports.comports())
    if not ports:
        return None
    
    keywords = ["cp210", "ch340", "usb", "serial", "silicon", "uart"]
    for port in ports:
        desc = port.description.lower()
        for kw in keywords:
            if kw in desc:
                print(f"[bridge] Auto-detected ESP32 on port: {port.device} ({port.description})")
                return port.device
                
    print(f"[bridge] No clear ESP32 keywords found. Selecting first port: {ports[0].device}")
    return ports[0].device

def find_sim_binary(root_dir):

    search_paths = [
        os.path.join(root_dir, "cpp-sim", "build", "Release", "sim_tft.exe"),
        os.path.join(root_dir, "cpp-sim", "build", "Debug", "sim_tft.exe"),
        os.path.join(root_dir, "cpp-sim", "build", "sim_tft.exe"),
        os.path.join(root_dir, "cpp-sim", "build", "sim_tft"),
    ]
    for path in search_paths:
        if os.path.exists(path):
            print(f"[bridge] Found DVEL simulator binary at: {path}")
            return path
    return None

def fetch_json(url, timeout=2.0):

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'DvelBridge/2.0'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception:
        return None

def run_simulator_mode(ser, root_dir):

    binary_path = find_sim_binary(root_dir)
    if not binary_path:
        print("[bridge] ERROR: 'sim_tft' simulator executable not found!")
        print("[bridge] Please compile the DVEL project or run in --live mode.")
        sys.exit(1)
        
    print(f"[bridge] Starting DVEL simulator process...")
    process = subprocess.Popen(
        [binary_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    try:
        while True:
            line = process.stdout.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
                
            try:
                data = json.loads(line)
                log_type = data.get("type", "unknown")
                if log_type == "tick_start":
                    print(f"\n[bridge] >>> TICK {data.get('tick')} START <<<")
                elif log_type == "link":
                    print(f"[bridge]   LINK: Node {data.get('node')} added event {data.get('hash')[:6]} from Author {data.get('author')}")
                elif log_type == "tip":
                    print(f"[bridge]   TIP: Node {data.get('node')} Preferred tip: {data.get('tip')[:6]} (Score: {data.get('score')}) | Merkle: {data.get('merkle')[:6]}")
                elif log_type == "weight":
                    print(f"[bridge]   WEIGHT: Node {data.get('node')} observes Peer {data.get('peer')} weight = {data.get('weight')/1000.0}")
                elif log_type == "tick_end":
                    print(f"[bridge] <<< TICK {data.get('tick')} END >>>")
                
                ser.write((line + "\n").encode("utf-8"))
                ser.flush()
            except json.JSONDecodeError:
                print(f"[sim stdout] {line}")
    finally:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()

def run_live_mode(ser, primary_node):

    print(f"[bridge] Initializing Live BFT mode pointing to primary node API: {primary_node}")
    

    primary_node = primary_node.rstrip('/')
    

    import urllib.parse
    parsed = urllib.parse.urlparse(primary_node)
    host_ip = parsed.hostname
    
    endpoints = [
        f"http://{host_ip}:17001",
        f"http://{host_ip}:17002",
        f"http://{host_ip}:17003",
        f"http://{host_ip}:17004"
    ]
    print(f"[bridge] Monitoring validator cluster health on endpoints: {endpoints}")
    

    proposer_map = {}
    
    def get_peer_index(proposer_id):
        if proposer_id not in proposer_map:
            proposer_map[proposer_id] = len(proposer_map) % 3
        return proposer_map[proposer_id]
        
    last_height = 0
    

    init_tip = fetch_json(f"{primary_node}/tip")
    if init_tip:
        last_height = init_tip["height"]
        print(f"[bridge] Connected! Starting from Height {last_height}")
    else:
        print(f"[bridge] WARNING: Could not contact primary node {primary_node}. Waiting for it to come online...")
        
    while True:
        try:

            tip = fetch_json(f"{primary_node}/tip")
            if not tip:
                print(f"[bridge] WARNING: Primary node {primary_node} is unreachable. Retrying in 1s...")

                weight_msg = {"type": "weight", "node": 0, "peer": 0, "weight": 0}
                ser.write((json.dumps(weight_msg) + "\n").encode("utf-8"))
                ser.flush()
                time.sleep(1.0)
                continue
                
            current_height = tip["height"]
            

            if current_height > last_height:
                for h in range(last_height + 1, current_height + 1):

                    block = fetch_json(f"{primary_node}/block/{h}")
                    if not block:
                        continue
                        
                    h_val = block["height"]
                    b_hash = block["block_hash"]
                    p_hash = block["prev_block_hash"]
                    prop_id = block["proposer_id"]
                    t_root = block["tx_root"]
                    
                    peer_idx = get_peer_index(prop_id)
                    

                    start_msg = {"type": "tick_start", "tick": h_val}
                    ser.write((json.dumps(start_msg) + "\n").encode("utf-8"))
                    ser.flush()
                    print(f"\n[bridge] >>> TICK {h_val} START <<<")
                    time.sleep(0.05)
                    

                    link_msg = {
                        "type": "link",
                        "hash": b_hash[:8],
                        "parent": p_hash[:8],
                        "author": peer_idx,
                        "node": peer_idx
                    }
                    ser.write((json.dumps(link_msg) + "\n").encode("utf-8"))
                    ser.flush()
                    print(f"[bridge]   LINK: Node {peer_idx} added block {b_hash[:6]} (prev: {p_hash[:6]})")
                    time.sleep(0.05)
                    

                    tip_msg = {
                        "type": "tip",
                        "tick": h_val,
                        "tip": b_hash[:8],
                        "score": h_val,
                        "merkle": t_root[:8]
                    }
                    ser.write((json.dumps(tip_msg) + "\n").encode("utf-8"))
                    ser.flush()
                    print(f"[bridge]   TIP: Preferred tip updated to {b_hash[:6]}")
                    time.sleep(0.05)
                    

                    end_msg = {"type": "tick_end"}
                    ser.write((json.dumps(end_msg) + "\n").encode("utf-8"))
                    ser.flush()
                    print(f"[bridge] <<< TICK {h_val} END >>>")
                    time.sleep(0.05)
                    
                last_height = current_height
                

            for idx in range(3):
                node_url = endpoints[idx]
                is_alive = fetch_json(f"{node_url}/tip", timeout=1.5) is not None
                weight_val = 1000 if is_alive else 0
                

                weight_msg = {
                    "type": "weight",
                    "node": 0,
                    "peer": idx,
                    "weight": weight_val
                }
                ser.write((json.dumps(weight_msg) + "\n").encode("utf-8"))
                ser.flush()
                
                if not is_alive:
                    print(f"[bridge]   ALERT: Validator {idx} ({node_url}) is OFFLINE! Weight slashed to 0.")
                    
            time.sleep(1.0)
            
        except Exception as e:
            print(f"[bridge] Error in live loop: {e}")
            time.sleep(1.0)

def main():
    parser = argparse.ArgumentParser(description="DVEL Telemetry Hardware Bridge")
    parser.add_argument("--port", help="ESP32 COM serial port (e.g. COM3 or /dev/ttyUSB0)")
    parser.add_argument("--live", action="store_true", help="Connect to a live BFT cluster instead of C++ simulator")
    parser.add_argument("--node", default="http://127.0.0.1:17001", help="Primary BFT client endpoint for live mode")
    args = parser.parse_args()
    
    print("="*60)
    print("      DVEL REAL-TIME TELEMETRY HARDWARE BRIDGE (v2.0.0)")
    print("="*60)
    
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(scripts_dir, ".."))
    
    port = args.port if args.port else find_esp32_port()
    if not port:
        print("[bridge] ERROR: No COM ports found! Is your ESP32 plugged in?")
        sys.exit(1)
        
    try:
        ser = serial.Serial(port, 115200, timeout=1)
        time.sleep(2)
        print(f"[bridge] Connected to ESP32 on {port} at 115200 baud.")
    except Exception as e:
        print(f"[bridge] ERROR: Failed to open serial port {port}: {e}")
        sys.exit(1)
        
    try:
        if args.live:
            run_live_mode(ser, args.node)
        else:
            run_simulator_mode(ser, root_dir)
    except KeyboardInterrupt:
        print("\n[bridge] Stopping bridge script gracefully...")
    finally:
        ser.close()
        print("[bridge] Disconnected. Bridge closed successfully.")

if __name__ == "__main__":
    main()
