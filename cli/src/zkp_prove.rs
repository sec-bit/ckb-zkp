use ark_serialize::*;
use serde_json::json;
use std::env;
use std::path::PathBuf;
use zkp_curve::Curve;

mod circuits;
use circuits::{CliCircuit, Publics};

use circuits::hash::Hash;
use circuits::mini::Mini;

const PROOFS_DIR: &'static str = "./proof_files";
const SETUP_DIR: &'static str = "./setup_files";

macro_rules! handle_circuit {
    ($curve:ident, $curve_name:expr, $scheme:expr, $circuit:expr, $args:expr) => {
        match $circuit {
            "mini" => {
                let (c, publics) = Mini::<<$curve as Curve>::Fr>::power_on($args);
                let _off_c = Mini::<<$curve as Curve>::Fr>::power_off();
                handle_scheme!($curve, c, _off_c, publics, $curve_name, $scheme, $circuit);
            }
            "hash" => {
                let (c, publics) = Hash::<<$curve as Curve>::Fr>::power_on($args);
                let _off_c = Hash::<<$curve as Curve>::Fr>::power_off();
                handle_scheme!($curve, c, _off_c, publics, $curve_name, $scheme, $circuit);
            }
            _ => return Err(format!("CIRCUIT: {} not implement.", $circuit)),
        };
    };
}

macro_rules! handle_scheme {
    ($curve:ident, $c:expr, $off_c:expr, $publics:expr, $curve_name:expr, $scheme:expr, $circuit:expr) => {
        let mut pk_path = PathBuf::from(SETUP_DIR);
        pk_path.push(format!("{}-{}-{}.pk", $scheme, $curve_name, $circuit));
        let pk = std::fs::read(&pk_path).unwrap_or(vec![]);
        let rng = &mut rand::thread_rng();

        let proof_bytes = match $scheme {
            "groth16" => {
                println!("Will use pk file: {:?}", pk_path);
                use zkp_groth16::{create_random_proof, Parameters};
                let params = Parameters::<$curve>::deserialize(&pk[..]).unwrap();
                let proof = create_random_proof(&params, $c, rng).unwrap();
                let mut proof_bytes = Vec::new();
                proof.serialize(&mut proof_bytes).unwrap();
                proof_bytes
            }
            "bulletproofs" => {
                use zkp_bulletproofs::create_random_proof;
                let (gens, r1cs, proof) = create_random_proof::<$curve, _, _>($c, rng).unwrap();
                let mut bytes = vec![];
                gens.serialize(&mut bytes).unwrap();
                r1cs.serialize(&mut bytes).unwrap();
                proof.serialize(&mut bytes).unwrap();

                bytes
            }
            "spartan_snark" => {
                use zkp_spartan::snark::{Parameters, create_random_proof};
                let mut srs_path = PathBuf::from(SETUP_DIR);
                srs_path.push(format!("{}-{}-{}.universal_setup", $scheme, $curve_name, $circuit));
                println!("Will use universal setup file: {:?}", srs_path);
                let srs_bytes = std::fs::read(&srs_path).unwrap_or(vec![]);
                let srs = Parameters::<$curve>::deserialize(&srs_bytes[..]).unwrap();
                let (pk, _vk) = srs.keypair();

                let r1cs_to_hash = pk.r1cs.r1cs_to_hash();
                let param_to_hash = pk.params.param_to_hash();
                let encode_to_hash = pk.encode_comm.encode_to_hash();

                let proof = create_random_proof(&pk, $c, r1cs_to_hash,param_to_hash, encode_to_hash, rng).unwrap();
                let mut proof_bytes = Vec::new();
                proof.serialize(&mut proof_bytes).unwrap();
                proof_bytes
            }
            "spartan_nizk" => {
                use zkp_spartan::nizk::{Parameters, create_random_proof};
                let mut srs_path = PathBuf::from(SETUP_DIR);
                srs_path.push(format!("{}-{}-{}.universal_setup", $scheme, $curve_name, $circuit));
                println!("Will use universal setup file: {:?}", srs_path);
                let srs_bytes = std::fs::read(&srs_path).unwrap_or(vec![]);
                let srs = Parameters::<$curve>::deserialize(&srs_bytes[..]).unwrap();
                let (pk, _vk) = srs.keypair();
                
                let r1cs_to_hash = pk.r1cs.r1cs_to_hash();
                let param_to_hash = pk.params.param_to_hash();

                let proof = create_random_proof(&pk, $c, r1cs_to_hash, param_to_hash, rng).unwrap();
                let mut proof_bytes = Vec::new();
                proof.serialize(&mut proof_bytes).unwrap();
                proof_bytes
            }
            _ => return Err(format!("SCHEME: {} not implement.", $scheme)),
        };

        let mut path = PathBuf::from(PROOFS_DIR);
        if !path.exists() {
            std::fs::create_dir_all(&path).unwrap();
        }
        path.push(format!("{}-{}-{}.proof.json", $scheme, $curve_name, $circuit));
        println!("Proof file: {:?}", path);

        let params = match $publics {
            Publics::Mini(z) => vec![format!("{}", z)],
            Publics::Hash(image) => {
                let mut image_bytes = Vec::new();
                image.serialize(&mut image_bytes).unwrap();
                vec![
                    format!("{}", to_hex(&image_bytes))
                ]
            }
        };

        let content = json!({
            "circuit": $circuit,
            "scheme": $scheme,
            "curve": $curve_name,
            "params": params,
            "proof": to_hex(&proof_bytes)
        });
        serde_json::to_writer(&std::fs::File::create(path).unwrap(), &content).unwrap();
    };
}

fn to_hex(v: &[u8]) -> String {
    let mut s = String::with_capacity(v.len() * 2);
    s.extend(v.iter().map(|b| format!("{:02x}", b)));
    s
}

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        println!("zkp-prove");
        println!("");
        println!("Usage: zkp-prove [SCHEME] [CURVE] [CIRCUIT] [ARGUMENTS]");
        println!("");
        println!("SCHEME:");
        println!("    groth16       -- Groth16 zero-knowledge proof system.");
        println!("    bulletproofs  -- Bulletproofs zero-knowledge proof system.");
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
        println!("CIRCUIT ARGUMENTS:");
        println!("    [arguments]    -- circuits arguments.");
        println!("");
        println!("");

        return Err("Params invalid!".to_owned());
    }

    let (curve, scheme, circuit) = (args[2].as_str(), args[1].as_str(), args[3].as_str());

    match curve {
        "bls12_381" => {
            use ark_bls12_381::Bls12_381;
            handle_circuit!(Bls12_381, curve, scheme, circuit, &args[4..]);
        }
        _ => return Err(format!("Curve: {} not implement.", curve)),
    }

    Ok(())
}
