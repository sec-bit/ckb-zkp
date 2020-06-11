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
        Gadget::MiMC(bytes),
        Scheme::Groth16,
        Curve::Bn_256,
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
See [details](./cli)

## Features
1. Efficient mathematics compute.
2. Variety of curves.
3. Variety of zkp schemes.
4. Multiple out-of-the-box gadgets.
5. no-std is support.

## Gadgets
See more [details](./src/gadget)
- MiMC hash
- GreaterThan
- LessThan
- Between
- Boolean
- ... Continue others...


## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

Inspired by [bellman](https://github.com/zkcrypto/bellman), [zexe](https://github.com/scipr-lab/zexe), [libsnark](https://github.com/scipr-lab/libsnark), [dalek-bulletproofs](https://github.com/dalek-cryptography/bulletproofs) and other great projects.
