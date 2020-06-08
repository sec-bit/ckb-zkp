use std::env;
use std::path::PathBuf;
use zkp::verify_from_bytes;

const SETUP_DIR: &'static str = "./trusted_setup";

pub fn handle_args() -> Result<(String, String), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 5 && args.len() != 3 {
        println!("Args. like: zkp-verify mimc ./proofs_files/mimc_proof");
        println!("            zkp-verify mimc groth16 bn_256 ./proofs_files/mimc_proof");
        return Err("Params invalid!".to_owned());
    }

    let (vk_file, filename) = if args.len() == 3 {
        (
            format!("{}-{}-{}.vk", args[1], "groth16", "bn_256"),
            args[2].as_str(),
        )
    } else {
        (
            format!("{}-{}-{}.vk", args[1], args[2], args[3]),
            args[4].as_str(),
        )
    };

    Ok((vk_file, filename.to_owned()))
}

pub fn main() -> Result<(), String> {
    let (vk_file, filename) = handle_args()?;

    // load pk file.
    let mut vk_path = PathBuf::from(SETUP_DIR);
    vk_path.push(vk_file);
    if !vk_path.exists() {
        return Err(format!("Cannot found setup file: {:?}", vk_path));
    }
    let vk = std::fs::read(&vk_path).unwrap();

    let path = PathBuf::from(filename);
    let bytes = if path.exists() {
        let b = std::fs::read(&path).expect("file not found!");
        println!("Start verify {:?}...", path);
        b
    } else {
        return Err(format!("Not found file: {:?}.", path));
    };

    let res = verify_from_bytes(&bytes, &vk);
    println!("Verify is: {}", res);

    Ok(())
}
