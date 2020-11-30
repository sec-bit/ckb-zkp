use ckb_zkp::math::Curve;
use std::env;
use std::path::PathBuf;

mod circuits;
use circuits::CliCircuit;

use circuits::hash::Hash;
use circuits::mini::Mini;

const SETUP_DIR: &'static str = "./setup_files";

macro_rules! handle_circuit {
    ($curve:ident, $curve_name:expr, $scheme:expr, $circuit:expr) => {
        match $circuit {
            "mini" => {
                let c = Mini::<<$curve as Curve>::Fr>::power_off();
                handle_scheme!($curve, c, $curve_name, $scheme, $circuit);
            }
            "hash" => {
                let c = Hash::<<$curve as Curve>::Fr>::power_off();
                handle_scheme!($curve, c, $curve_name, $scheme, $circuit);
            }
            _ => return Err(format!("CIRCUIT: {} not implement.", $circuit)),
        };
    };
}

macro_rules! handle_scheme {
    ($curve:ident, $c:expr, $curve_name:expr, $scheme:expr, $circuit:expr) => {
        let mut vk_path = PathBuf::from(SETUP_DIR);
        if !vk_path.exists() {
            std::fs::create_dir_all(&vk_path).unwrap();
        }
        let rng = &mut rand::thread_rng();
        let (vk_bytes, pk_bytes) = match $scheme {
            "groth16" => {
                use ckb_zkp::groth16::generate_random_parameters;
                let params = generate_random_parameters::<$curve, _, _>($c, rng).unwrap();
                let vk = postcard::to_allocvec(&params.vk).unwrap();
                let pk = postcard::to_allocvec(&params).unwrap();
                (vk, pk)
            }
            "marlin" => {
                use ckb_zkp::marlin::universal_setup;
                // set max circuit num: 2^16
                let srs = universal_setup::<$curve, _>(2usize.pow(16), rng).unwrap();
                let srs_bytes = postcard::to_allocvec(&srs).unwrap();
                let vk_name = format!("{}-{}.universal_setup", $scheme, $curve_name);
                println!("Marlin universal setup: {}", vk_name);
                vk_path.push(vk_name);
                std::fs::write(vk_path, srs_bytes).unwrap();
                return Ok(());
            }
            _ => return Err(format!("SCHEME: {} not implement.", $scheme)),
        };

        let pk_name = format!("{}-{}-{}.pk", $scheme, $curve_name, $circuit);
        let vk_name = format!("{}-{}-{}.vk", $scheme, $curve_name, $circuit);
        let mut pk_path = vk_path.clone();
        vk_path.push(vk_name.clone());
        pk_path.push(pk_name.clone());

        std::fs::write(pk_path, pk_bytes).unwrap();
        std::fs::write(vk_path, vk_bytes).unwrap();

        println!("Prove Key: {}, Verify Key: {}, ", pk_name, vk_name);
    };
}

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        println!("setup");
        println!("");
        println!("Usage: setup [SCHEME] [CURVE] [CIRCUIT]");
        println!("");
        println!("SCHEME:");
        println!("    groth16      -- Groth16 zero-knowledge proof system.");
        println!("    marlin       -- Marlin zero-knowledge proof system.");
        println!("    clinkv2      -- CLINKv2 zero-knowledge proof system.");
        println!("    spartan      -- Spartan zero-knowledge proof system.");
        println!("");
        println!("CURVE:");
        println!("    bn_256    -- BN_256 pairing curve.");
        println!("    bls12_381 -- BLS12_381 pairing curve.");
        println!("");
        println!("CIRCUIT:");
        println!("    mini    -- Mini circuit. proof: x * (y + 2) = z.");
        println!("    hash    -- Hash circuit. proof: mimc hash.");
        println!("");
        println!("");

        return Err("Params invalid!".to_owned());
    }

    let circuit = if args.len() > 3 {
        args[3].as_str()
    } else {
        "mini" // it will use in marlin.
    };
    let (curve, scheme, circuit) = (args[2].as_str(), args[1].as_str(), circuit);
    println!("Start setup...");

    match curve {
        "bn_256" => {
            use ckb_zkp::bn_256::Bn_256;
            handle_circuit!(Bn_256, curve, scheme, circuit);
        }
        "bls12_381" => {
            use ckb_zkp::bls12_381::Bls12_381;
            handle_circuit!(Bls12_381, curve, scheme, circuit);
        }
        _ => return Err(format!("Curve: {} not implement.", curve)),
    }

    Ok(())
}
