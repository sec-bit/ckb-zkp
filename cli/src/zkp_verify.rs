use std::env;
use std::path::PathBuf;
use zkp::{verify_from_bytes, Curve, Scheme};

const SETUP_DIR: &'static str = "./trusted_setup";

fn print_common() {
    println!("");
    println!("scheme:");
    println!("    groth16      -- Groth16 zero-knowledge proof system. [Default]");
    println!("    bulletproofs -- Bulletproofs zero-knowledge proof system.");
    println!("");
    println!("curve:");
    println!("    bn_256    -- BN_256 pairing curve. [Default]");
    println!("    bls12_381 -- BLS12_381 pairing curve.");
    println!("");
    println!("OPTIONS:");
    println!("    --json    -- input/ouput use json type file.");
    println!("    --prepare -- use prepare verify key when verify proof.");
    println!("");
}

fn print_help() {
    println!("zkp-verify");
    println!("");
    println!("Usage: zkp-verify [GADGET] <scheme> <curve> [FILE] <OPTIONS>");
    println!("");
    println!("GADGET: ");
    println!("    mimc    -- MiMC hash & proof.");
    println!("    greater -- Greater than comparison proof.");
    println!("    less    -- Less than comparison proof.");
    println!("    between -- Between comparison proof.");
    print_common();
}

pub fn handle_args() -> Result<(String, String), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() < 3 {
        print_help();

        return Err("Params invalid!".to_owned());
    }

    let (s, c, n) = match args[2].as_str() {
        "groth16" => match args[3].as_str() {
            "bls12_381" => (Scheme::Groth16, Curve::Bls12_381, 4),
            "bn_256" => (Scheme::Groth16, Curve::Bn_256, 4),
            _ => (Scheme::Groth16, Curve::Bn_256, 3),
        },
        "bulletproofs" => match args[3].as_str() {
            "bls12_381" => (Scheme::Bulletproofs, Curve::Bls12_381, 4),
            "bn_256" => (Scheme::Bulletproofs, Curve::Bn_256, 4),
            _ => (Scheme::Bulletproofs, Curve::Bn_256, 3),
        },
        "bls12_381" => (Scheme::Groth16, Curve::Bls12_381, 3),
        "bn_256" => (Scheme::Groth16, Curve::Bn_256, 3),
        _ => (Scheme::Groth16, Curve::Bn_256, 2),
    };

    let vk_file = format!("{}-{}-{}.vk", args[1], s.to_str(), c.to_str());

    Ok((vk_file, args[n].clone()))
}

pub fn main() -> Result<(), String> {
    let (vk_file, filename) = handle_args()?;

    // load pk file.
    let mut vk_path = PathBuf::from(SETUP_DIR);
    vk_path.push(vk_file);
    if !vk_path.exists() {
        return Err(format!("Cannot found setup file: {:?}", vk_path));
    }
    let vk = std::fs::read(&vk_path).unwrap();

    let path = PathBuf::from(filename);
    let bytes = if path.exists() {
        let b = std::fs::read(&path).expect("file not found!");
        println!("Start verify {:?}...", path);
        b
    } else {
        return Err(format!("Not found file: {:?}.", path));
    };

    let res = verify_from_bytes(&bytes, &vk);
    println!("Verify is: {}", res);

    Ok(())
}
