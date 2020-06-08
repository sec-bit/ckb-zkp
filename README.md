# zkp-toolkit

## Introduction
Zero-knowledge proof system toolkit with pure Rust.

Current zero-knowledge proof library is too low-level, and users must have a good knowledge before they can use it. The purpose of this project is to lower the difficulty for using zero-knowledge proof, and easy to use, so it can be used by users of all levels.
The project now is FOR EXPERIMENTS, DONOT USE IN PRODUCTION.

## Example
Use we supported MiMC gadget and groth16 zero-knowledge proof as an example. 
```rust
use rand::prelude::*;
use zkp::curve::bn_256::{Bn_256, Fr};
use zkp::gadget::mimc::{constants, MiMC};
use zkp::math::ToBytes;
use zkp::scheme::groth16::generate_random_parameters;
use zkp::{prove, prove_to_bytes, verify, verify_from_bytes, Curve, Gadget, Scheme};

/// test for use groth16 & bn_256 & mimc gadget.
fn main() {
    let bytes = vec![1, 2, 3, 4, 5]; // this is your secret.
    let mut rng = thread_rng();

    // TRUSTED SETUP
    println!("TRUSTED SETUP...");
    let constants = constants::<Fr>();
    let c = MiMC::<Fr> {
        xl: None,
        xr: None,
        constants: &constants,
    };
    let params = generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap();

    // you need save this prove key,
    // when prove, use it as a params.
    let mut pk_bytes = vec![];
    params.write(&mut pk_bytes).unwrap();

    // you need save this verify key,
    // when verify, use it as a params.
    let mut vk_bytes = vec![];
    params.vk.write(&mut vk_bytes).unwrap();

    println!("START PROVE...");
    let proof = prove(
        Gadget::MiMC,
        Scheme::Groth16,
        Curve::Bn_256,
        &bytes,
        &pk_bytes,
        rng,
    )
    .unwrap();

    println!("START VERIFY...");
    let is_ok = verify(proof, &vk_bytes);
    assert!(is_ok);
}
```

## Cli-Command.
Use MiMC zero-knowledge proof as an example. 
- **YOU NEED TRUSTED-SETUP** use groth16 & bn_256 as an example.
  - `cargo run --bin trusted-setup mimc groth16 bn_256` (When success, it will create prove key and verify key in the current trusted_setup directory)
- Use default groth16 as scheme and bn_256 as curve，and prove the secret string.
  - `cargo run --bin zkp-prove mimc --string=iamsecret` (When success, it will create a proof file at proofs_files/mimc_proof)
  - `cargo run --bin zkp-verify mimc proofs_files/mimc_proof`

- Use custom schemes and curves as backend, and prove the file value.
  - `cargo run --bin zkp-prove mimc groth16 bls12_381 --file=README.md` (When success, it will create a proof file at proofs_files/REAME.md.mimc_proof)
  - `cargo run --bin zkp-verify mimc groth16 bls12_381 proofs_files/REAME.md.mimc_proof`

## Features
1. Efficient mathematics compute.
2. Variety of curves.
3. Variety of zkp schemes.
4. Multiple out-of-the-box gadgets.
5. no-std is support.

## Gadgets
1. MiMC - hash for prove things. - OK
2. boolean - prove the bool value. - OK
3. Rangeproof - prove the range. - WIP
4. ... Continue ...


## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

Inspired by [bellman](https://github.com/zkcrypto/bellman), [zexe](https://github.com/scipr-lab/zexe), [libsnark](https://github.com/scipr-lab/libsnark), [dalek-bulletproofs](https://github.com/dalek-cryptography/bulletproofs) and other great projects.
