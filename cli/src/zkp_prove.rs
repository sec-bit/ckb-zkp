use serde_json::json;
use std::env;
use std::path::PathBuf;

use ckb_zkp::{prove, Circuit, CircuitProof, Curve, Scheme};

const PROOFS_DIR: &'static str = "./proofs_files";
const SETUP_DIR: &'static str = "./trusted_setup";

trait CircuitName {
    fn handle(&self, args: &[String]) -> Result<(Circuit, String), String>;
    fn options(&self) -> String;
}

struct MiMC;
struct Greater;
struct Less;
struct Between;
struct Mini;

impl CircuitName for MiMC {
    fn handle(&self, args: &[String]) -> Result<(Circuit, String), String> {
        if args.len() < 1 {
            return Err("unimplemented other file type.".to_owned());
        }

        let (bytes, filename) = if args[0].starts_with("--file=") {
            let path = PathBuf::from(&args[0][7..]);
            (
                std::fs::read(&path).expect("file not found!"),
                path.file_name()
                    .map(|f| f.to_str())
                    .flatten()
                    .map(|f| format!("{}.mimc", f))
                    .unwrap_or(format!("mimc")),
            )
        } else if args[0].starts_with("--string=") {
            (args[0][9..].as_bytes().to_vec(), format!("mimc"))
        } else {
            panic!("unimplemented other file type.")
        };

        Ok((Circuit::MiMC(bytes), filename))
    }

    fn options(&self) -> String {
        "[--file=xxx | --string=xx]".to_owned()
    }
}

impl CircuitName for Greater {
    fn handle(&self, args: &[String]) -> Result<(Circuit, String), String> {
        let sec = args[0]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");
        let com = args[1]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");

        Ok((Circuit::GreaterThan(sec, com), "greater".to_owned()))
    }

    fn options(&self) -> String {
        "[secret_integer] [compared_interger]".to_owned()
    }
}

impl CircuitName for Less {
    fn handle(&self, args: &[String]) -> Result<(Circuit, String), String> {
        let sec = args[0]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");
        let com = args[1]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");

        Ok((Circuit::GreaterThan(sec, com), "less".to_owned()))
    }

    fn options(&self) -> String {
        "[secret_integer] [compared_interger]".to_owned()
    }
}

impl CircuitName for Between {
    fn handle(&self, args: &[String]) -> Result<(Circuit, String), String> {
        let sec = args[0]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");
        let from = args[1]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");
        let to = args[2]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");

        Ok((Circuit::Between(sec, from, to), "between".to_owned()))
    }

    fn options(&self) -> String {
        "[secret_integer] [start_interger] [end_interger]".to_owned()
    }
}

impl CircuitName for Mini {
    fn handle(&self, args: &[String]) -> Result<(Circuit, String), String> {
        let x = args[0]
            .as_str()
            .parse::<u32>()
            .expect("Interger parse error");
        let y = args[1]
            .as_str()
            .parse::<u32>()
            .expect("Interger parse error");
        let z = args[2]
            .as_str()
            .parse::<u32>()
            .expect("Interger parse error");

        Ok((Circuit::Mini(x, y, z), "mini".to_owned()))
    }

    fn options(&self) -> String {
        "[x] [y] [z]".to_owned()
    }
}

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

fn parse_gadget_name(g: &str) -> Result<Box<(dyn CircuitName + 'static)>, String> {
    match g {
        "mimc" => Ok(Box::new(MiMC)),
        "greater" => Ok(Box::new(Greater)),
        "less" => Ok(Box::new(Less)),
        "between" => Ok(Box::new(Between)),
        "mini" => Ok(Box::new(Mini)),
        _ => Err(format!("{} unimplemented!", g)),
    }
}

pub fn handle_args() -> Result<(Circuit, Scheme, Curve, String, String, bool, bool), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        println!("zkp-prove");
        println!("");
        println!("Usage: zkp-prove [CIRCUIT] <scheme> <curve> [GADGET OPTIONS] <OPTIONS>");
        println!("");
        println!("CIRCUIT: ");
        println!("    mini    -- Mini circuit.");
        println!("    mimc    -- MiMC hash & proof.");
        println!("    greater -- Greater than comparison proof.");
        println!("    less    -- Less than comparison proof.");
        println!("    between -- Between comparison proof.");
        print_common();

        return Err("Params invalid!".to_owned());
    }

    let g = parse_gadget_name(args[1].as_str())?;
    let is_pp = args.contains(&"--prepare".to_owned());
    let is_json = args.contains(&"--json".to_owned());

    if args.len() == 2 {
        println!("zkp-prove {}", args[1]);
        println!("");
        println!(
            "Usage: zkp-prove {} <scheme> <curve> {} <OPTIONS>",
            args[1],
            g.options()
        );
        print_common();
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

    let pk_file = format!("{}-{}-{}.pk", args[1], s.to_str(), c.to_str());

    let (gadget, filename) = g.handle(&args[n..])?;

    let file = format!("{}.{}-{}.proof", filename, s.to_str(), c.to_str());

    Ok((gadget, s, c, pk_file, file, is_pp, is_json))
}

fn to_hex(v: &[u8]) -> String {
    let mut s = String::with_capacity(v.len() * 2);
    s.extend(v.iter().map(|b| format!("{:02x}", b)));
    s
}

fn main() -> Result<(), String> {
    let (g, s, c, pk_file, mut filename, _is_pp, is_json) = handle_args()?;

    let pk = match s {
        Scheme::Groth16 => {
            // load pk file.
            let mut pk_path = PathBuf::from(SETUP_DIR);
            pk_path.push(pk_file);
            if !pk_path.exists() {
                return Err(format!("Cannot found setup file: {:?}", pk_path));
            }
            std::fs::read(&pk_path).unwrap()
        }
        Scheme::Bulletproofs => vec![],
    };

    let proof = prove(g, s, c, &pk, rand::thread_rng()).unwrap();

    let mut path = PathBuf::from(PROOFS_DIR);
    if !path.exists() {
        std::fs::create_dir_all(&path).unwrap();
    }

    if is_json {
        filename.push_str(".json");
    }

    path.push(filename);
    println!("Proof file: {:?}", path);

    if is_json {
        let (name, params, p) = match proof.p {
            CircuitProof::Mini(z, proof) => ("mini", vec![format!("{}", z)], to_hex(&proof)),
            CircuitProof::MiMC(hash, proof) => ("mimc", vec![to_hex(&hash)], to_hex(&proof)),
            CircuitProof::GreaterThan(n, proof) => {
                ("greater", vec![format!("{}", n)], to_hex(&proof))
            }
            CircuitProof::LessThan(n, proof) => ("less", vec![format!("{}", n)], to_hex(&proof)),
            CircuitProof::Between(l, r, proof) => (
                "between",
                vec![format!("{}", l), format!("{}", r)],
                to_hex(&proof),
            ),
        };

        let content = json!({
            "circuit": name,
            "scheme": proof.s.to_str(),
            "curve": proof.c.to_str(),
            "params": params,
            "proof": p
        });
        serde_json::to_writer(&std::fs::File::create(path).unwrap(), &content).unwrap();
    } else {
        std::fs::write(path, proof.to_bytes()).unwrap();
    }

    Ok(())
}
