//! Run with `cargo test --locked -p core-cli --test policy-bundle-demo -- --nocapture`.

#[path = "../src/bundle_adapter.rs"]
mod bundle_adapter;
#[path = "../src/bundle_adapter_demo.rs"]
mod bundle_adapter_demo;

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

#[test]
fn baseline_and_promoted_boots_preserve_the_kernel_bearing_host() {
    let host = Path::new(env!("CARGO_BIN_EXE_core"));
    let before = file_digest(host).unwrap();
    let result = bundle_adapter_demo::run().unwrap();
    let after = file_digest(host).unwrap();

    println!("baseline_tools={}", result.baseline_tools.join(","));
    println!("promoted_tools={}", result.promoted_tools.join(","));
    println!("kernel_host_sha256={before}");
    println!("kernel_tcb_unchanged={}", before == after);

    assert_ne!(result.baseline_tools, result.promoted_tools);
    assert_eq!(before, after);
}

fn file_digest(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
