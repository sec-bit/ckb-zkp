# zkp-toolkit

## Introduction

Zero-knowledge proofs toolkit with pure Rust, empowering the community with the cutting-edge techniques of zero-knowledge proofs to develop all kinds of decentralized applications.

The project is going to bridge the gap of cryptographic engineering between thriving academic research and aspiring dAPPs developers, by providing multiple zkp scheme and curve options, a more user-friendly interface, many useful gadget libraries, and many more tutorials and examples.

This project is part of *zkp-toolkit-ckb* and is supported by the Nervos Foundation. Check out the [original proposal](https://talk.nervos.org/t/secbit-labs-zkp-toolkit-ckb-a-zero-knowledge-proof-toolkit-for-ckb/4254) and [grant announcement](https://medium.com/nervosnetwork/three-new-ecosystem-grants-awarded-892b97e8bc06).

It can be used in conjunction with the [ckb-zkp](https://github.com/sec-bit/ckb-zkp) project to implement on-chain zkp verifiers for the CKB-VM.

## Example

Use the [MiMC](http://eprint.iacr.org/2016/492) gadget and [Groth16](https://eprint.iacr.org/2016/260) scheme we supported as an example.

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

## Features

1. Efficient computation.
2. Variety of curves.
3. Variety of zkp schemes.
4. Multiple out-of-the-box gadgets.
5. `no-std` is supported.

Currently, [Groth16](https://eprint.iacr.org/2016/260) and [bulletproofs](https://crypto.stanford.edu/bulletproofs/) are supported. You can describe zkp circuits for the Groth16 scheme through the powerful constraint system. Specially, we implemented a modified version of bulletproofs with R1CS support. It also supports to describe constraints through the same constraint system. So gadgets could be sharable between Groth16 and bulletproofs. We're working on that.

You can check the [original proposal](https://talk.nervos.org/t/secbit-labs-zkp-toolkit-ckb-a-zero-knowledge-proof-toolkit-for-ckb/4254) for more feature details.

## CLI-Command

Check [CLI usage](./cli) for hands-on examples.

## Gadgets

- MiMC hash
- GreaterThan
- LessThan
- Between
- Boolean
- ... Many others ...

Check the [gadget doc](./src/gadget) for more details.

## Security

This project is still under active development and is currently being used for research and experimental purposes only, please **DO NOT USE IT IN PRODUCTION** for now.

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

Inspired by [bellman](https://github.com/zkcrypto/bellman), [zexe](https://github.com/scipr-lab/zexe), [libsnark](https://github.com/scipr-lab/libsnark), [dalek-bulletproofs](https://github.com/dalek-cryptography/bulletproofs) and other great projects.
