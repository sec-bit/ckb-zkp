use std::env;
use std::path::PathBuf;
use zkp::{Curve, Gadget, Scheme};

const SETUP_DIR: &'static str = "./trusted_setup";

mod mimc;

pub fn handle_args() -> Result<(Gadget, Scheme, Curve, String, bool), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 4 && args.len() != 2 {
        println!("Args. like: trusted-setup mimc");
        println!("            trusted-setup mimc groth16 bn_256");
        return Err("Params invalid!".to_owned());
    }

    let is_pp = args.contains(&"--prepare".to_owned());

    let g = match args[1].as_str() {
        "mimc" => Gadget::MiMC,
        _ => Gadget::MiMC,
    };

    let (s, c, filename) = if args.len() == 2 {
        (
            Scheme::Groth16,
            Curve::Bn_256,
            format!("{}-{}-{}", args[1], "groth16", "bn_256"),
        )
    } else {
        let s = match args[2].as_str() {
            "groth16" => Scheme::Groth16,
            "bulletproofs" => Scheme::Bulletproofs,
            _ => return Err(format!("{} not supported!", args[2])),
        };

        let c = match args[3].as_str() {
            "bn_256" => Curve::Bn_256,
            "bls12_381" => Curve::Bls12_381,
            _ => return Err(format!("{} not supported!", args[3])),
        };

        (s, c, format!("{}-{}-{}", args[1], args[2], args[3]))
    };

    Ok((g, s, c, filename, is_pp))
}

macro_rules! handle_curve {
    ($func_name:ident, $rng_name:ident, $c:expr, $rng:expr, $pp:expr) => {
        match $c {
            Curve::Bls12_381 => $func_name::<curve::Bls12_381, $rng_name>($rng, $pp),
            Curve::Bn_256 => $func_name::<curve::Bn_256, $rng_name>($rng, $pp),
        }
    };
}

macro_rules! handle_gadget {
    ($gadget:ident, $rng_name:ident, $s:expr, $c:expr, $rng:expr, $pp:expr) => {
        match $s {
            Scheme::Groth16 => {
                use $gadget::groth16_setup;
                handle_curve!(groth16_setup, $rng_name, $c, $rng, $pp)
            }
            _ => return Err(("unimplemented!!".to_owned())),
        }
    };
}

fn main() -> Result<(), String> {
    let (g, s, c, filename, is_pp) = handle_args()?;

    // use rand thread_rng as PRNG.
    use rand::rngs::ThreadRng;
    let rng = rand::thread_rng();

    let (pk, vk) = match g {
        Gadget::MiMC => handle_gadget!(mimc, ThreadRng, s, c, rng, is_pp)?,
    };

    let path = PathBuf::from(SETUP_DIR);
    if !path.exists() {
        std::fs::create_dir_all(&path).unwrap();
    }
    let mut pk_path = path.clone();
    pk_path.push(format!("{}.pk", filename));

    let mut vk_path = path;
    vk_path.push(format!("{}.vk", filename));

    std::fs::write(pk_path.clone(), pk).unwrap();
    std::fs::write(vk_path.clone(), vk).unwrap();

    println!("Trusted setup file:");
    println!("  prove  key: {:?}", pk_path);
    println!("  verify key: {:?}", vk_path);

    Ok(())
}
