use ckb_zkp::{Curve, Gadget, Scheme};
use std::env;
use std::path::PathBuf;

const SETUP_DIR: &'static str = "./trusted_setup";

mod mimc;
mod range;

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
    println!("    --prepare -- use prepare verify key when verify proof.");
    println!("");
}

fn print_help() {
    println!("trusted-setup");
    println!("");
    println!("Usage: trusted-setup [GADGET] <scheme> <curve> <OPTIONS>");
    println!("");
    println!("GADGET: ");
    println!("    mimc    -- MiMC hash & proof.");
    println!("    greater -- Greater than comparison proof.");
    println!("    less    -- Less than comparison proof.");
    println!("    between -- Between comparison proof.");
    print_common();
}

pub fn handle_args() -> Result<(Gadget, Scheme, Curve, String, bool), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        print_help();

        return Err("Params invalid!".to_owned());
    }

    let is_pp = args.contains(&"--prepare".to_owned());

    let g = match args[1].as_str() {
        "mimc" => Gadget::MiMC(vec![]),
        "greater" => Gadget::GreaterThan(0, 0),
        "less" => Gadget::GreaterThan(0, 0), // use some range setup
        "between" => Gadget::GreaterThan(0, 0), // use some range setup
        _ => return Err(format!("{} unimplemented!", args[1])),
    };

    let (s, c) = if args.len() < 3 {
        (Scheme::Groth16, Curve::Bn_256)
    } else {
        match args[2].as_str() {
            "groth16" => {
                if args.len() < 4 {
                    (Scheme::Groth16, Curve::Bn_256)
                } else {
                    match args[3].as_str() {
                        "bls12_381" => (Scheme::Groth16, Curve::Bls12_381),
                        _ => (Scheme::Groth16, Curve::Bn_256),
                    }
                }
            }
            "bulletproofs" => {
                if args.len() < 4 {
                    (Scheme::Bulletproofs, Curve::Bn_256)
                } else {
                    match args[3].as_str() {
                        "bls12_381" => (Scheme::Bulletproofs, Curve::Bls12_381),
                        _ => (Scheme::Bulletproofs, Curve::Bn_256),
                    }
                }
            }
            "bls12_381" => (Scheme::Groth16, Curve::Bls12_381),
            _ => (Scheme::Groth16, Curve::Bn_256),
        }
    };

    let filename = format!("{}-{}-{}", args[1], s.to_str(), c.to_str());

    Ok((g, s, c, filename, is_pp))
}

macro_rules! handle_curve {
    ($func_name:ident, $rng_name:ident, $c:expr, $rng:expr, $pp:expr) => {
        match $c {
            Curve::Bls12_381 => $func_name::<ckb_zkp::curve::Bls12_381, $rng_name>($rng, $pp),
            Curve::Bn_256 => $func_name::<ckb_zkp::curve::Bn_256, $rng_name>($rng, $pp),
        }
    };
}

macro_rules! handle_gadget {
    ($gadget:ident, $rng_name:ident, $s:expr, $c:expr, $rng:expr, $pp:expr) => {
        match $s {
            Scheme::Groth16 => {
                use $gadget::groth16_setup;
                handle_curve!(groth16_setup, $rng_name, $c, $rng, $pp)
            }
            _ => return Err(("unimplemented!!".to_owned())),
        }
    };
}

fn main() -> Result<(), String> {
    let (g, s, c, filename, is_pp) = handle_args()?;

    // use rand thread_rng as PRNG.
    use rand::rngs::ThreadRng;
    let rng = rand::thread_rng();

    let (pk, vk) = match g {
        Gadget::MiMC(..) => handle_gadget!(mimc, ThreadRng, s, c, rng, is_pp)?,
        Gadget::GreaterThan(..) => handle_gadget!(range, ThreadRng, s, c, rng, is_pp)?,
        _ => return Err(format!("{} unimplemented!", "Gadget")),
    };

    let path = PathBuf::from(SETUP_DIR);
    if !path.exists() {
        std::fs::create_dir_all(&path).unwrap();
    }
    let mut pk_path = path.clone();
    pk_path.push(format!("{}.pk", filename));

    let mut vk_path = path;
    vk_path.push(format!("{}.vk", filename));

    std::fs::write(pk_path.clone(), pk).unwrap();
    std::fs::write(vk_path.clone(), vk).unwrap();

    println!("Trusted setup file:");
    println!("  prove  key: {:?}", pk_path);
    println!("  verify key: {:?}", vk_path);

    Ok(())
}
