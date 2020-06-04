use std::env;
use std::path::PathBuf;
use zkp::verify_from_bytes;

pub fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("Use like: zkp-verify ./proofs_files/mimc_proof");
        return;
    }

    let path = PathBuf::from(&args[1].as_str());
    let bytes = if path.exists() {
        let b = std::fs::read(&path).expect("file not found!");
        println!("Start verify {:?}...", path);
        b
    } else {
        println!("Not found file: {:?}.", path);
        return;
    };

    let res = verify_from_bytes(&bytes);
    println!("Verify is: {}", res);
}
