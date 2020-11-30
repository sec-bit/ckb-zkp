use ckb_zkp::math::Curve;
use std::env;
use std::path::PathBuf;

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
                let c = Mini::<<$curve as Curve>::Fr>::power_off();
                let publics = vec![<$curve as Curve>::Fr::from(num)];
                handle_scheme!(
                    $curve,
                    c,
                    &publics,
                    $curve_name,
                    $scheme,
                    $circuit,
                    $proof_bytes
                );
            }
            "hash" => {
                let fr_bytes = from_hex($params[0].as_str().unwrap()).unwrap();
                let image: <$curve as Curve>::Fr = postcard::from_bytes(&fr_bytes).unwrap();
                let c = Hash::<<$curve as Curve>::Fr>::power_off();
                let publics = vec![image];
                handle_scheme!(
                    $curve,
                    c,
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
                use ckb_zkp::groth16::{prepare_verifying_key, verify_proof, Proof, VerifyKey};
                let vk: VerifyKey<$curve> = postcard::from_bytes(&vk_bytes).unwrap();
                let proof: Proof<$curve> = postcard::from_bytes(&$proof_bytes).unwrap();
                let pvk = prepare_verifying_key(&vk);
                verify_proof(&pvk, &proof, &$publics).unwrap()
            }
            "bulletproofs" => {
                use ckb_zkp::bulletproofs::{verify_proof, Generators, Proof, R1csCircuit};
                let mut gens_len_bytes = [0u8; 4];
                gens_len_bytes.copy_from_slice($proof_bytes.drain(0..4).as_slice());
                let gens_len = u32::from_le_bytes(gens_len_bytes) as usize;
                let gens: Generators<$curve> =
                    postcard::from_bytes($proof_bytes.drain(0..gens_len).as_slice()).unwrap();
                let mut r1cs_len_bytes = [0u8; 4];
                r1cs_len_bytes.copy_from_slice($proof_bytes.drain(0..4).as_slice());
                let r1cs_len = u32::from_le_bytes(r1cs_len_bytes) as usize;
                let r1cs: R1csCircuit<$curve> =
                    postcard::from_bytes($proof_bytes.drain(0..r1cs_len).as_slice()).unwrap();
                let proof: Proof<$curve> = postcard::from_bytes(&$proof_bytes).unwrap();
                verify_proof(&gens, &proof, &r1cs, $publics).unwrap()
            }
            "marlin" => {
                use ckb_zkp::marlin::{index, verify_proof, Proof, UniversalParams};
                let mut srs_path = PathBuf::from(SETUP_DIR);
                srs_path.push(format!("{}-{}.universal_setup", $scheme, $curve_name));
                println!("Will use universal setup file: {:?}", srs_path);
                let srs_bytes = std::fs::read(&srs_path).unwrap_or(vec![]);
                let srs: UniversalParams<$curve> = postcard::from_bytes(&srs_bytes).unwrap();
                let (_ipk, ivk) = index(&srs, $c).unwrap();
                let proof: Proof<$curve> = postcard::from_bytes(&$proof_bytes).unwrap();
                verify_proof(&ivk, &proof, $publics).unwrap()
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
    let mut proof = from_hex(json["proof"].as_str().unwrap()).expect("proof invalid");

    println!("Start verify...");

    match curve {
        "bn_256" => {
            use ckb_zkp::bn_256::Bn_256;
            handle_circuit!(Bn_256, curve, scheme, circuit, proof, params);
        }
        "bls12_381" => {
            use ckb_zkp::bls12_381::Bls12_381;
            handle_circuit!(Bls12_381, curve, scheme, circuit, proof, params);
        }
        _ => return Err(format!("Curve: {} not implement.", curve)),
    }

    Ok(())
}
