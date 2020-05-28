use std::path::PathBuf;
use zkp::{
    curve::{Bls12_381, Bn_256},
    Curve, Scheme,
};

const PROOFS_DIR: &'static str = "./proofs_files";

mod args;
mod mimc;

use args::Gadget;

macro_rules! handle_curve {
    ($func_name:ident, $c:expr, $bytes:expr) => {
        match $c {
            Curve::Bls12_381 => $func_name::<Bls12_381>($bytes),
            Curve::Bn_256 => $func_name::<Bn_256>($bytes),
        }
    };
}

macro_rules! handle_gadget {
    ($gadget:ident, $s:expr, $c:expr, $bytes:expr) => {
        match $s {
            Scheme::Groth16 => {
                use $gadget::groth16_prove;
                handle_curve!(groth16_prove, $c, $bytes)
            }
            Scheme::Bulletproofs => {
                use $gadget::groth16_prove;
                handle_curve!(groth16_prove, $c, $bytes)
            }
        }
    };
}

fn main() -> Result<(), ()> {
    let (g, s, c, bytes, filename) = args::handle_args()?;

    let proof = match g {
        Gadget::Mimc => handle_gadget!(mimc, s, c, &bytes),
    };

    let mut path = PathBuf::from(PROOFS_DIR);
    if !path.exists() {
        std::fs::create_dir_all(&path).unwrap();
    }
    path.push(filename);
    println!("Proof file: {:?}", path);

    std::fs::write(path, proof).unwrap();

    Ok(())
}
