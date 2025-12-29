use crate::bft::node::{NodeCommand, NodeSnapshot};
use crate::bft::types::{block_hash, tx_hash, BlockHeader};
use hex::{decode as hex_decode, encode as hex_encode};
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc, RwLock};
use std::thread;

#[derive(Deserialize)]
struct TxRequest {
    tx_hex: String,
}

pub fn start_http_server(
    listen_addr: String,
    snapshot: Arc<RwLock<NodeSnapshot>>,
    tx_cmd: mpsc::Sender<NodeCommand>,
) {
    thread::spawn(move || {
        let listener = TcpListener::bind(listen_addr).expect("bind http");
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let snap = Arc::clone(&snapshot);
                let tx_cmd = tx_cmd.clone();
                thread::spawn(move || handle_client(stream, snap, tx_cmd));
            }
        }
    });
}

fn handle_client(mut stream: TcpStream, snapshot: Arc<RwLock<NodeSnapshot>>, tx_cmd: mpsc::Sender<NodeCommand>) {
    let req = match read_request(&mut stream) {
        Ok(r) => r,
        Err(_) => return,
    };

    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/tx") => {
            let body = match serde_json::from_slice::<TxRequest>(&req.body) {
                Ok(b) => b,
                Err(_) => return write_json(&mut stream, 400, r#"{"error":"bad json"}"#),
            };
            let tx = match hex_decode(body.tx_hex) {
                Ok(t) => t,
                Err(_) => return write_json(&mut stream, 400, r#"{"error":"bad hex"}"#),
            };
            let th = tx_hash(&tx);
            let _ = tx_cmd.send(NodeCommand::SubmitTx(tx));
            let resp = format!(r#"{{"tx_hash":"{}"}}"#, hex_encode(th));
            write_json(&mut stream, 200, &resp);
        }
        ("GET", "/tip") => {
            let snap = snapshot.read().unwrap();
            let resp = format!(
                r#"{{"height":{},"hash":"{}"}}"#,
                snap.height,
                hex_encode(snap.tip_hash)
            );
            write_json(&mut stream, 200, &resp);
        }
        ("GET", path) if path.starts_with("/block/") => {
            let height = path.trim_start_matches("/block/");
            if let Ok(h) = height.parse::<u64>() {
                let snap = snapshot.read().unwrap();
                if let Some(block) = snap.blocks_by_height.get(&h) {
                    let header = &block.header;
                    let tx_hashes: Vec<String> =
                        block.txs.iter().map(|t| hex_encode(tx_hash(t))).collect();
                    let resp = block_json(header, &tx_hashes);
                    write_json(&mut stream, 200, &resp);
                } else {
                    write_json(&mut stream, 404, r#"{"error":"not found"}"#);
                }
            } else {
                write_json(&mut stream, 400, r#"{"error":"bad height"}"#);
            }
        }
        ("GET", path) if path.starts_with("/tx/") => {
            let hash_hex = path.trim_start_matches("/tx/");
            let Ok(hash_bytes) = hex_decode(hash_hex) else {
                return write_json(&mut stream, 400, r#"{"error":"bad hash"}"#);
            };
            if hash_bytes.len() != 32 {
                return write_json(&mut stream, 400, r#"{"error":"bad hash"}"#);
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&hash_bytes);
            let snap = snapshot.read().unwrap();
            if let Some((block_hash, height)) = snap.tx_index.get(&h) {
                let resp = format!(
                    r#"{{"status":"committed","height":{},"block_hash":"{}"}}"#,
                    height,
                    hex_encode(block_hash)
                );
                write_json(&mut stream, 200, &resp);
            } else {
                write_json(&mut stream, 404, r#"{"status":"unknown"}"#);
            }
        }
        _ => {
            write_json(&mut stream, 404, r#"{"error":"not found"}"#);
        }
    }
}

fn block_json(header: &BlockHeader, tx_hashes: &[String]) -> String {
    let block_hash = block_hash(header);
    let mut out = String::new();
    out.push_str("{");
    out.push_str(&format!("\"height\":{},", header.height));
    out.push_str(&format!("\"round\":{},", header.round));
    out.push_str(&format!("\"prev_block_hash\":\"{}\",", hex_encode(header.prev_block_hash)));
    out.push_str(&format!("\"tx_root\":\"{}\",", hex_encode(header.tx_root)));
    out.push_str(&format!("\"proposer_id\":\"{}\",", hex_encode(header.proposer_id)));
    out.push_str(&format!("\"timestamp_ms\":{},", header.timestamp_ms));
    out.push_str(&format!("\"block_hash\":\"{}\",", hex_encode(block_hash)));
    out.push_str("\"tx_hashes\":[");
    for (i, h) in tx_hashes.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(h);
        out.push('"');
    }
    out.push_str("]}");
    out
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<Request, String> {
    let mut buf = [0u8; 4096];
    let mut data = Vec::new();
    loop {
        let n = stream.read(&mut buf).map_err(|e| format!("{}", e))?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("bad request")?
        + 4;
    let header_bytes = &data[..header_end];
    let mut body = data[header_end..].to_vec();

    let req_str = String::from_utf8_lossy(header_bytes);
    let mut lines = req_str.split("\r\n");
    let line = lines.next().ok_or("bad request")?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("bad method")?.to_string();
    let path = parts.next().ok_or("bad path")?.to_string();

    let mut content_len = 0usize;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("Content-Length:") {
            content_len = rest.trim().parse::<usize>().unwrap_or(0);
        }
    }

    if content_len > body.len() {
        let mut remaining = content_len.saturating_sub(body.len());
        while remaining > 0 {
            let mut buf = vec![0u8; remaining.min(4096)];
            let n = stream.read(&mut buf).map_err(|e| format!("{}", e))?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&buf[..n]);
            remaining = remaining.saturating_sub(n);
        }
    }

    Ok(Request { method, path, body })
}

fn write_json(stream: &mut TcpStream, status: u16, body: &str) {
    let status_line = match status {
        200 => "HTTP/1.1 200 OK",
        400 => "HTTP/1.1 400 Bad Request",
        404 => "HTTP/1.1 404 Not Found",
        _ => "HTTP/1.1 500 Internal Server Error",
    };
    let resp = format!(
        "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status_line,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
}
