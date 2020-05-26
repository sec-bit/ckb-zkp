use std::env;
use std::path::PathBuf;
use zkp::{verify, Curve, Scheme};

pub fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 4 && args.len() != 2 {
        println!("Args. like: zkp-verify ./proofs_files/mimc_proof");
        println!("            zkp-verify groth16 bn256 ./proofs_files/mimc_proof");
        return;
    }

    let (s, c) = if args.len() == 2 {
        (Scheme::Groth16, Curve::Bn_256)
    } else {
        let s = match args[1].as_str() {
            "groth16" => Scheme::Groth16,
            _ => Scheme::Groth16,
        };

        let c = match args[2].as_str() {
            "bn256" => Curve::Bn_256,
            "bls12_381" => Curve::Bls12_381,
            _ => Curve::Bn_256,
        };

        (s, c)
    };

    let f = args[if args.len() == 2 { 1 } else { 3 }].as_str();
    let path = PathBuf::from(&f);
    let bytes = if path.exists() {
        let b = std::fs::read(&path).expect("file not found!");
        println!("Start verify {:?}...", path);
        b
    } else {
        println!("Not found file: {:?}.", path);
        return;
    };

    let res = verify(s, c, &bytes);
    println!("Verify is: {}", res);
}
