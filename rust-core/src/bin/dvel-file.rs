use dvel_core::storage::{
    chunk_file_to_dir, manifest_path, read_manifest, reassemble, sign_manifest_inplace,
    verify_chunks, verify_manifest_signature, write_manifest,
};
use std::env;
use std::path::PathBuf;

fn parse_hex_array<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(s).map_err(|_| "bad hex")?;
    if bytes.len() != N {
        return Err(format!("expected {} bytes hex, got {}", N, bytes.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn usage() {
    eprintln!("Usage:");
    eprintln!(
        "  dvel-file upload <input_file> <out_dir> <chunk_size_bytes> [--sign <secret_hex32>]"
    );
    eprintln!(
        "  dvel-file download <manifest_path> <chunk_dir> <output_path> [--expect-signer <pubkey_hex32>]"
    );
}

fn handle_upload(args: &[String]) -> Result<(), String> {
    if args.len() < 3 {
        return Err("upload requires <input_file> <out_dir> <chunk_size_bytes>".into());
    }
    let input = PathBuf::from(&args[0]);
    let out_dir = PathBuf::from(&args[1]);
    let chunk_size: usize = args[2]
        .parse()
        .map_err(|_| "chunk_size must be an integer")?;

    let mut sign_key: Option<[u8; 32]> = None;
    let mut idx = 3;
    while idx < args.len() {
        match args[idx].as_str() {
            "--sign" => {
                if idx + 1 >= args.len() {
                    return Err("missing value for --sign".into());
                }
                sign_key = Some(parse_hex_array::<32>(&args[idx + 1])?);
                idx += 2;
            }
            other => return Err(format!("unknown arg {}", other)),
        }
    }

    let mut manifest =
        chunk_file_to_dir(&input, &out_dir, chunk_size).map_err(|e| format!("{}", e))?;
    if let Some(sk) = sign_key {
        sign_manifest_inplace(&mut manifest, &sk).map_err(|e| format!("{}", e))?;
    }

    let mpath = manifest_path(&out_dir, &manifest.file_name);
    write_manifest(&manifest, &mpath).map_err(|e| format!("{}", e))?;

    println!(
        "Chunked {} into {} chunks -> {}",
        manifest.file_name,
        manifest.chunks.len(),
        mpath.display()
    );
    Ok(())
}

fn handle_download(args: &[String]) -> Result<(), String> {
    if args.len() < 3 {
        return Err("download requires <manifest_path> <chunk_dir> <output_path>".into());
    }
    let manifest_path = PathBuf::from(&args[0]);
    let chunk_dir = PathBuf::from(&args[1]);
    let output_path = PathBuf::from(&args[2]);

    let mut expect_signer: Option<[u8; 32]> = None;
    let mut idx = 3;
    while idx < args.len() {
        match args[idx].as_str() {
            "--expect-signer" => {
                if idx + 1 >= args.len() {
                    return Err("missing value for --expect-signer".into());
                }
                expect_signer = Some(parse_hex_array::<32>(&args[idx + 1])?);
                idx += 2;
            }
            other => return Err(format!("unknown arg {}", other)),
        }
    }

    let manifest = read_manifest(&manifest_path).map_err(|e| format!("{}", e))?;
    if let Some(exp) = expect_signer
        && manifest.signer != Some(exp)
    {
        return Err("manifest signer does not match expected key".into());
    }

    if manifest.signature.is_some() {
        verify_manifest_signature(&manifest).map_err(|e| format!("{}", e))?;
    }

    verify_chunks(&manifest, &chunk_dir).map_err(|e| format!("{}", e))?;
    reassemble(&manifest, &chunk_dir, &output_path).map_err(|e| format!("{}", e))?;
    println!("Reassembled -> {}", output_path.display());
    Ok(())
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    let _bin = args.remove(0);
    if args.is_empty() {
        usage();
        std::process::exit(1);
    }

    let cmd = args.remove(0);
    let result: Result<(), String> = match cmd.as_str() {
        "upload" => handle_upload(&args),
        "download" => handle_download(&args),
        _ => {
            usage();
            Err("unknown command".into())
        }
    };

    if let Err(e) = result {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
