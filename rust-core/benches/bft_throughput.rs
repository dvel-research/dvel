// BFT Block Processing Throughput Benchmark
// Tests parallel signature verification performance

use dvel_core::event::{Event, Hash, PublicKey, ZERO_HASH};
use dvel_core::validation::{ValidationContext, compute_signature_with_secret, validate_event};
use std::time::Instant;

fn make_event_struct(
    author: PublicKey,
    secret: &[u8; 32],
    timestamp: u64,
    prev: Hash,
    payload: u8,
) -> Event {
    let mut payload_hash = [0u8; 32];
    payload_hash[0] = payload;

    let mut ev = Event {
        version: 1,
        prev_hash: prev,
        author,
        timestamp,
        payload_hash,
        signature: [0u8; 64],
    };

    ev.signature = compute_signature_with_secret(&ev, secret);
    ev
}

fn benchmark_block_processing(block_size: usize, num_blocks: usize) -> f64 {
    // Setup: 10 authors
    let num_authors = 10;
    let mut secrets = Vec::new();
    let mut pubkeys = Vec::new();

    for i in 0..num_authors {
        let mut secret = [0u8; 32];
        secret[0] = i as u8 + 1;

        // Derive pubkey manually
        use ed25519_dalek::{PublicKey as DalekPublic, SecretKey};
        let sk = SecretKey::from_bytes(&secret).unwrap();
        let pk: DalekPublic = (&sk).into();

        secrets.push(secret);
        pubkeys.push(pk.to_bytes());
    }

    // Generate blocks with event structs
    let mut blocks = Vec::new();
    let prev_tip = ZERO_HASH;

    for block_idx in 0..num_blocks {
        let mut events = Vec::new();

        for tx_idx in 0..block_size {
            let author_idx = (block_idx * block_size + tx_idx) % num_authors;
            let timestamp = 1000000 + (block_idx * block_size + tx_idx) as u64;
            let payload = ((block_idx + tx_idx) % 256) as u8;

            let ev = make_event_struct(
                pubkeys[author_idx],
                &secrets[author_idx],
                timestamp,
                prev_tip,
                payload,
            );

            events.push(ev);
        }

        blocks.push(events);
    }

    // Benchmark signature verification (the part that's parallelized)
    let start = Instant::now();
    let mut total_events = 0;

    for events in &blocks {
        // Simulate apply_block validation phase
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;

            let results: Result<Vec<_>, String> = events
                .par_iter()
                .map(|ev| {
                    let mut ctx = ValidationContext::new();
                    validate_event(ev, &mut ctx).map_err(|e| format!("{:?}", e))?;
                    Ok(())
                })
                .collect();

            if results.is_err() {
                panic!("Validation failed");
            }
        }

        #[cfg(not(feature = "parallel"))]
        {
            for ev in events {
                let mut ctx = ValidationContext::new();
                validate_event(ev, &mut ctx).unwrap();
            }
        }

        total_events += events.len();
    }

    total_events as f64 / start.elapsed().as_secs_f64()
}

fn main() {
    println!("========================================");
    println!("  BFT Block Processing Benchmark");
    println!("========================================");

    #[cfg(feature = "parallel")]
    println!("Mode: PARALLEL (rayon)");

    #[cfg(not(feature = "parallel"))]
    println!("Mode: SINGLE-THREADED");

    println!("----------------------------------------\n");

    // Test 1: Small blocks (100 tx/block)
    println!("Test 1: Small blocks (100 tx/block, 100 blocks)");
    let throughput1 = benchmark_block_processing(100, 100);
    println!("Events: 10,000");
    println!("Throughput: {:.2} events/sec\n", throughput1);

    // Test 2: Medium blocks (500 tx/block)
    println!("Test 2: Medium blocks (500 tx/block, 100 blocks)");
    let throughput2 = benchmark_block_processing(500, 100);
    println!("Events: 50,000");
    println!("Throughput: {:.2} events/sec\n", throughput2);

    // Test 3: Large blocks (1000 tx/block)
    println!("Test 3: Large blocks (1000 tx/block, 50 blocks)");
    let throughput3 = benchmark_block_processing(1000, 50);
    println!("Events: 50,000");
    println!("Throughput: {:.2} events/sec\n", throughput3);

    println!("========================================");
    println!(
        "Average throughput: {:.2} events/sec",
        (throughput1 + throughput2 + throughput3) / 3.0
    );
    println!("========================================");
}
