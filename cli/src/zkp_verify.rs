use std::env;
use std::path::PathBuf;

use ckb_zkp::{verify, verify_from_bytes, CircuitProof, Curve, Proof, Scheme};

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
    println!("    --prepare -- use prepared verification key when verifying proof.");
    println!("");
}

fn print_help() {
    println!("zkp-verify");
    println!("");
    println!("Usage: zkp-verify [CIRCUIT] <scheme> <curve> [FILE] <OPTIONS>");
    println!("");
    println!("CIRCUIT: ");
    println!("    mini    -- Mini circuit.");
    println!("    mimc    -- MiMC hash & proof.");
    println!("    greater -- Greater than comparison proof.");
    println!("    less    -- Less than comparison proof.");
    println!("    between -- Between comparison proof.");
    print_common();
}

pub fn handle_args() -> Result<(String, Scheme, String, bool, bool), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() < 3 {
        print_help();

        return Err("Params invalid!".to_owned());
    }

    let is_pp = args.contains(&"--prepare".to_owned());
    let is_json = args.contains(&"--json".to_owned());

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

    Ok((vk_file, s, args[n].clone(), is_pp, is_json))
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

pub fn main() -> Result<(), String> {
    let (vk_file, s, filename, _is_pp, is_json) = handle_args()?;

    let vk = match s {
        Scheme::Groth16 => {
            // load pk file.
            let mut vk_path = PathBuf::from(SETUP_DIR);
            vk_path.push(vk_file);
            if !vk_path.exists() {
                return Err(format!("Cannot found setup file: {:?}", vk_path));
            }
            std::fs::read(&vk_path).unwrap()
        }
        Scheme::Bulletproofs => vec![],
    };

    let path = PathBuf::from(filename);

    let res = if path.exists() {
        println!("Start verify {:?}...", path);

        if is_json {
            let content = std::fs::read_to_string(&path).expect("file not found!");
            let json: serde_json::Value = serde_json::from_str(&content).unwrap();
            let g_str = json["circuit"].as_str().unwrap();
            let s_str = json["scheme"].as_str().unwrap();
            let c_str = json["curve"].as_str().unwrap();
            let params = &json["params"];
            let p_str = json["proof"].as_str().unwrap();

            let s = Scheme::from_str(s_str).unwrap();
            let c = Curve::from_str(c_str).unwrap();
            let p = match g_str {
                "mini" => {
                    let z = params[0].as_str().unwrap().parse::<u32>().unwrap();
                    CircuitProof::Mini(z, from_hex(p_str).unwrap())
                }
                "mimc" => CircuitProof::MiMC(
                    from_hex(params[0].as_str().unwrap()).unwrap(),
                    from_hex(p_str).unwrap(),
                ),
                "greater" => {
                    let n = params[0].as_str().unwrap().parse::<u64>().unwrap();
                    CircuitProof::GreaterThan(n, from_hex(p_str).unwrap())
                }
                "less" => {
                    let n = params[0].as_str().unwrap().parse::<u64>().unwrap();
                    CircuitProof::LessThan(n, from_hex(p_str).unwrap())
                }
                "between" => {
                    let l = params[0].as_str().unwrap().parse::<u64>().unwrap();
                    let r = params[1].as_str().unwrap().parse::<u64>().unwrap();
                    CircuitProof::Between(l, r, from_hex(p_str).unwrap())
                }
                _ => return Err("unimplemented".to_owned()),
            };

            verify(Proof { s, c, p }, &vk)
        } else {
            let b = std::fs::read(&path).expect("file not found!");
            verify_from_bytes(&b, &vk)
        }
    } else {
        return Err(format!("Not found file: {:?}.", path));
    };

    println!("Verify is: {}", res);

    Ok(())
}
