use curve::bls12_381::Bls12_381;
use curve::bn_256::Bn_256;
use math::PairingEngine;
use rand::prelude::*;
use scheme::groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key};
use zkp::{
    gadget::mimc::{mimc_hash, MiMC},
    verify, Curve, Groth16Proof, Scheme,
};

use std::env;
use std::path::PathBuf;

const MIMC_ROUNDS: usize = 322;
const PROOFS_DIR: &'static str = "./proofs_files";

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 5 {
        println!("Args. like: mimc-zkp groth16 bn256 prove --file=./README.md");
        println!("            mimc-zkp groth16 bn256 prove --string=iamscretvalue");
        println!(
            "            mimc-zkp groth16 bn256 verify --file={}/mimc_proof",
            PROOFS_DIR
        );
        return;
    }

    let s = match args[1].as_str() {
        "groth16" => Scheme::Groth16,
        _ => Scheme::Groth16,
    };

    let c = match args[2].as_str() {
        "bn256" => Curve::Bn_256,
        "bls12_381" => Curve::Bls12_381,
        _ => Curve::Bn_256,
    };

    let f = args[4].as_str();
    let (bytes, filename) = if f.starts_with("--file=") {
        let path = PathBuf::from(&f[7..]);
        (
            std::fs::read(&path).expect("file not found!"),
            path.file_name()
                .map(|s| s.to_str())
                .flatten()
                .map(|s| format!("{}.proof", s))
                .unwrap_or(String::from("mimc_proof")),
        )
    } else if f.starts_with("--string=") {
        (f[9..].as_bytes().to_vec(), String::from("mimc_proof"))
    } else {
        panic!("unimplemented other file type.")
    };

    println!("Starting {} {}", args[3].as_str(), f);

    match args[3].as_str() {
        "prove" => match c {
            Curve::Bn_256 => {
                groth16_prove::<Bn_256>(&bytes, filename);
            }
            Curve::Bls12_381 => {
                groth16_prove::<Bls12_381>(&bytes, filename);
            }
        },
        "verify" => {
            let result = verify(s, c, &bytes);
            println!("Verify Result: {}", result);
        }
        _ => println!("not implemented!"),
    }
}

fn groth16_prove<E: PairingEngine>(bytes: &[u8], filename: String)
where
    rand::distributions::Standard: rand::distributions::Distribution<E::Fr>,
{
    println!("Prepareing...");

    let mut rng = rand::thread_rng();

    let constants: Vec<E::Fr> = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();

    let (xl, xr, image) = mimc_hash(bytes, &constants);
    println!("Mimc hash: {}", image);

    let c = MiMC::<E::Fr> {
        xl: None,
        xr: None,
        constants: &constants,
    };

    let params = generate_random_parameters::<E, _, _>(c, &mut rng).unwrap();

    let mc = MiMC {
        xl: Some(xl),
        xr: Some(xr),
        constants: &constants,
    };

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    // Create a groth16 proof with our parameters.
    let proof = create_random_proof(mc, &params, &mut rng).unwrap();

    let groth16_proof = Groth16Proof::new(pvk.clone(), proof, vec![image]).to_bytes(&params.vk);

    let mut path = PathBuf::from(PROOFS_DIR);
    if !path.exists() {
        std::fs::create_dir_all(&path).unwrap();
    }
    path.push(filename);
    println!("Proof file: {:?}", path);

    std::fs::write(path, groth16_proof).unwrap();
}
