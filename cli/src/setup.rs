use ark_serialize::*;
use std::env;
use std::path::PathBuf;
use zkp_curve::Curve;

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
                use zkp_groth16::generate_random_parameters;
                let params = generate_random_parameters::<$curve, _, _>($c, rng).unwrap();
                let mut vk = Vec::new();
                params.vk.serialize(&mut vk).unwrap();
                let mut pk = Vec::new();
                params.serialize(&mut pk).unwrap();
                (vk, pk)
            }
            "spartan_snark" => {
                use zkp_spartan::snark::generate_random_parameters;
                let vk_name = format!("{}-{}-{}.universal_setup", $scheme, $curve_name, $circuit);
                println!("Spartan snark universal setup: {}", vk_name);
                vk_path.push(vk_name);
                // use hash circuit because it is bigger.
                //let hash_off = Hash::<<$curve as Curve>::Fr>::power_off();
                let srs = generate_random_parameters::<$curve, _, _>($c, rng).unwrap();
                let mut srs_bytes = Vec::new();
                srs.serialize(&mut srs_bytes).unwrap();
                std::fs::write(vk_path, srs_bytes).unwrap();
                return Ok(());
            }
            "spartan_nizk" => {
                use zkp_spartan::nizk::generate_random_parameters;
                let vk_name = format!("{}-{}-{}.universal_setup", $scheme, $curve_name, $circuit);
                println!("Spartan nizk universal setup: {}", vk_name);
                vk_path.push(vk_name);
                // use hash circuit because it is bigger.
                //let hash_off = Hash::<<$curve as Curve>::Fr>::power_off();
                let srs = generate_random_parameters::<$curve, _, _>($c, rng).unwrap();
                let mut srs_bytes = Vec::new();
                srs.serialize(&mut srs_bytes).unwrap();
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
        println!("    groth16       -- Groth16 zero-knowledge proof system.");
        println!("    spartan_snark -- Spartan with snark zero-knowledge proof system.");
        println!("    spartan_nizk  -- Spartan with nizk zero-knowledge proof system.");
        println!("");
        println!("CURVE:");
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
        "bls12_381" => {
            use ark_bls12_381::Bls12_381;
            handle_circuit!(Bls12_381, curve, scheme, circuit);
        }
        _ => return Err(format!("Curve: {} not implement.", curve)),
    }

    Ok(())
}
