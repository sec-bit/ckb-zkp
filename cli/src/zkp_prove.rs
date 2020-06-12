use std::env;
use std::path::PathBuf;
use zkp::{prove_to_bytes, Curve, Gadget, Scheme};

const PROOFS_DIR: &'static str = "./proofs_files";
const SETUP_DIR: &'static str = "./trusted_setup";

trait GadgetName {
    fn handle(&self, args: &[String]) -> Result<(Gadget, String), String>;
    fn options(&self) -> String;
}

struct MiMC;
struct Greater;
struct Less;
struct Between;

impl GadgetName for MiMC {
    fn handle(&self, args: &[String]) -> Result<(Gadget, String), String> {
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
                    .map(|f| f.to_owned())
                    .unwrap_or(format!("mimc")),
            )
        } else if args[0].starts_with("--string=") {
            (args[0][9..].as_bytes().to_vec(), format!("mimc"))
        } else {
            panic!("unimplemented other file type.")
        };

        Ok((Gadget::MiMC(bytes), filename))
    }

    fn options(&self) -> String {
        "[--file=xxx | --string=xx]".to_owned()
    }
}

impl GadgetName for Greater {
    fn handle(&self, args: &[String]) -> Result<(Gadget, String), String> {
        let sec = args[0]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");
        let com = args[1]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");

        Ok((Gadget::GreaterThan(sec, com), "greater".to_owned()))
    }

    fn options(&self) -> String {
        "[secret_integer] [compared_interger]".to_owned()
    }
}

impl GadgetName for Less {
    fn handle(&self, args: &[String]) -> Result<(Gadget, String), String> {
        let sec = args[0]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");
        let com = args[1]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");

        Ok((Gadget::GreaterThan(sec, com), "less".to_owned()))
    }

    fn options(&self) -> String {
        "[secret_integer] [compared_interger]".to_owned()
    }
}

impl GadgetName for Between {
    fn handle(&self, args: &[String]) -> Result<(Gadget, String), String> {
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

        Ok((Gadget::Between(sec, from, to), "between".to_owned()))
    }

    fn options(&self) -> String {
        "[secret_integer] [start_interger] [end_interger]".to_owned()
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
    println!("    --prepare -- use prepare verify key when verify proof.");
    println!("");
}

fn parse_gadget_name(g: &str) -> Result<Box<(dyn GadgetName + 'static)>, String> {
    match g {
        "mimc" => Ok(Box::new(MiMC)),
        "greater" => Ok(Box::new(Greater)),
        "less" => Ok(Box::new(Less)),
        "between" => Ok(Box::new(Between)),
        _ => Err(format!("{} unimplemented!", g)),
    }
}

pub fn handle_args() -> Result<(Gadget, Scheme, Curve, String, String), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        println!("zkp-prove");
        println!("");
        println!("Usage: zkp-prove [GADGET] <scheme> <curve> [GADGET OPTIONS] <OPTIONS>");
        println!("");
        println!("GADGET: ");
        println!("    mimc    -- MiMC hash & proof.");
        println!("    greater -- Greater than comparison proof.");
        println!("    less    -- Less than comparison proof.");
        println!("    between -- Between comparison proof.");
        print_common();

        return Err("Params invalid!".to_owned());
    }

    let g = parse_gadget_name(args[1].as_str())?;

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

    Ok((gadget, s, c, pk_file, file))
}

fn main() -> Result<(), String> {
    let (g, s, c, pk_file, filename) = handle_args()?;

    // load pk file.
    let mut pk_path = PathBuf::from(SETUP_DIR);
    pk_path.push(pk_file);
    if !pk_path.exists() {
        return Err(format!("Cannot found setup file: {:?}", pk_path));
    }
    let pk = std::fs::read(&pk_path).unwrap();
    let proof = prove_to_bytes(g, s, c, &pk, rand::thread_rng()).unwrap();

    let mut path = PathBuf::from(PROOFS_DIR);
    if !path.exists() {
        std::fs::create_dir_all(&path).unwrap();
    }
    path.push(filename);
    println!("Proof file: {:?}", path);

    // -- json output style
    // {
    //     "gadget": "mimc",
    //     "scheme": "groth16",
    //     "curve": "bn_256",
    //     "params": ["0xmimchash"],
    //     "proof": "0xsss"
    // }

    std::fs::write(path, proof).unwrap();

    Ok(())
}
