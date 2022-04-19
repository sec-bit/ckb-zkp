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
    ($curve:ident, $curve_name:expr, $scheme:expr, $circuit:expr, $proof_bytes:expr, $params:expr) => {
        match $circuit {
            "mini" => {
                let num: u64 = $params[0].as_str().unwrap().parse().unwrap();
                let _c = Mini::<<$curve as Curve>::Fr>::power_off();
                let publics = vec![<$curve as Curve>::Fr::from(num)];
                handle_scheme!(
                    $curve,
                    _c,
                    &publics,
                    $curve_name,
                    $scheme,
                    $circuit,
                    $proof_bytes
                );
            }
            "hash" => {
                let fr_bytes = from_hex($params[0].as_str().unwrap()).unwrap();
                let image = <$curve as Curve>::Fr::deserialize(&fr_bytes[..]).unwrap();
                let _c = Hash::<<$curve as Curve>::Fr>::power_off();
                let publics = vec![image];
                handle_scheme!(
                    $curve,
                    _c,
                    &publics,
                    $curve_name,
                    $scheme,
                    $circuit,
                    $proof_bytes
                );
            }
            _ => return Err(format!("CIRCUIT: {} not implement.", $circuit)),
        };
    };
}

macro_rules! handle_scheme {
    ($curve:ident, $c:expr, $publics:expr, $curve_name:expr, $scheme:expr, $circuit:expr, $proof_bytes:expr) => {
        let mut vk_path = PathBuf::from(SETUP_DIR);
        vk_path.push(format!("{}-{}-{}.vk", $scheme, $curve_name, $circuit));
        let vk_bytes = std::fs::read(&vk_path).unwrap_or(vec![]);

        let proof_result = match $scheme {
            "groth16" => {
                println!("Will use vk file: {:?}", vk_path);
                use zkp_groth16::{prepare_verifying_key, verify_proof, Proof, VerifyKey};
                let vk = VerifyKey::<$curve>::deserialize(&vk_bytes[..]).unwrap();
                let proof = Proof::<$curve>::deserialize(&$proof_bytes[..]).unwrap();
                let pvk = prepare_verifying_key(&vk);
                verify_proof(&pvk, &proof, &$publics).unwrap()
            }
            "bulletproofs" => {
                use zkp_bulletproofs::{verify_proof, Generators, Proof, R1csCircuit};
                let (gens, r1cs, proof) =
                    <(Generators<$curve>, R1csCircuit<$curve>, Proof<$curve>)>::deserialize(
                        &$proof_bytes[..],
                    )
                    .unwrap();
                verify_proof(&gens, &proof, &r1cs, $publics).unwrap()
            }
            "spartan_snark" => {
                use zkp_spartan::snark::{verify_proof, Parameters, Proof};
                let mut srs_path = PathBuf::from(SETUP_DIR);
                srs_path.push(format!(
                    "{}-{}-{}.universal_setup",
                    $scheme, $curve_name, $circuit
                ));
                println!("Will use universal setup file: {:?}", srs_path);
                let srs_bytes = std::fs::read(&srs_path).unwrap_or(vec![]);
                let srs = Parameters::<$curve>::deserialize(&srs_bytes[..]).unwrap();
                let (_pk, vk) = srs.keypair();
                let proof = Proof::<$curve>::deserialize(&$proof_bytes[..]).unwrap();
                verify_proof(&vk, &proof, $publics).unwrap()
            }
            "spartan_nizk" => {
                use zkp_spartan::nizk::{verify_proof, Parameters, Proof};
                let mut srs_path = PathBuf::from(SETUP_DIR);
                srs_path.push(format!(
                    "{}-{}-{}.universal_setup",
                    $scheme, $curve_name, $circuit
                ));
                println!("Will use universal setup file: {:?}", srs_path);
                let srs_bytes = std::fs::read(&srs_path).unwrap_or(vec![]);
                let srs = Parameters::<$curve>::deserialize(&srs_bytes[..]).unwrap();
                let (_pk, vk) = srs.keypair();
                let proof = Proof::<$curve>::deserialize(&$proof_bytes[..]).unwrap();
                verify_proof(&vk, &proof, $publics).unwrap()
            }
            _ => return Err(format!("SCHEME: {} not implement.", $scheme)),
        };

        println!("Verify is: {}", proof_result);
    };
}

fn from_hex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }

    let mut value = vec![0u8; s.len() / 2];

    for i in 0..(s.len() / 2) {
        let res = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_e| ())?;
        value[i] = res;
    }

    Ok(value)
}

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        println!("zkp-verify");
        println!("");
        println!("Usage: zkp-prove [FILE]");
        println!("");
        println!("");

        return Err("Params invalid!".to_owned());
    }

    let content = std::fs::read_to_string(&PathBuf::from(&args[1])).expect("file not found!");
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let circuit = json["circuit"].as_str().unwrap();
    let scheme = json["scheme"].as_str().unwrap();
    let curve = json["curve"].as_str().unwrap();
    let params = &json["params"];
    let proof = from_hex(json["proof"].as_str().unwrap()).expect("proof invalid");

    println!("Start verify...");

    match curve {
        "bls12_381" => {
            use ark_bls12_381::Bls12_381;
            handle_circuit!(Bls12_381, curve, scheme, circuit, proof, params);
        }
        _ => return Err(format!("Curve: {} not implement.", curve)),
    }

    Ok(())
}
