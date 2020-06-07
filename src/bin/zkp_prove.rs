use std::env;
use std::path::PathBuf;
use zkp::{prove_to_bytes, Curve, Gadget, Scheme};

const PROOFS_DIR: &'static str = "./proofs_files";

pub fn handle_args() -> Result<(Gadget, Scheme, Curve, Vec<u8>, String), ()> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 5 && args.len() != 3 {
        println!("Args. like: zkp-prove mimc --file=./README.md");
        println!("            zkp-prove mimc groth16 bn256 --file=./README.md");
        println!("            zkp-prove mimc groth16 bn256 --string=iamscretvalue");
        return Err(());
    }

    let g = match args[1].as_str() {
        "mimc" => Gadget::MiMC,
        _ => Gadget::MiMC,
    };

    let (s, c) = if args.len() == 3 {
        (Scheme::Groth16, Curve::Bn_256)
    } else {
        let s = match args[2].as_str() {
            "groth16" => Scheme::Groth16,
            _ => Scheme::Groth16,
        };

        let c = match args[3].as_str() {
            "bn256" => Curve::Bn_256,
            "bls12_381" => Curve::Bls12_381,
            _ => Curve::Bn_256,
        };

        (s, c)
    };

    let f = args[if args.len() == 3 { 2 } else { 4 }].as_str();
    let (bytes, filename) = if f.starts_with("--file=") {
        let path = PathBuf::from(&f[7..]);
        (
            std::fs::read(&path).expect("file not found!"),
            path.file_name()
                .map(|s| s.to_str())
                .flatten()
                .map(|s| format!("{}.{}_proof", s, args[1].as_str()))
                .unwrap_or(format!("{}_proof", args[1].as_str())),
        )
    } else if f.starts_with("--string=") {
        (
            f[9..].as_bytes().to_vec(),
            format!("{}_proof", args[1].as_str()),
        )
    } else {
        panic!("unimplemented other file type.")
    };

    Ok((g, s, c, bytes, filename))
}

fn main() -> Result<(), ()> {
    let (g, s, c, bytes, filename) = handle_args()?;
    let proof = prove_to_bytes(g, s, c, &bytes, rand::thread_rng()).unwrap();

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
