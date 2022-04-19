# zkp-toolkit

## Introduction

Zero-knowledge proofs toolkit with pure Rust.

This project is part of *zkp-toolkit-ckb* and is supported by the Nervos Foundation. It provides multiple zkp schemes and curve options, which can also be used to implement on-chain zkp verifiers for the CKB-VM. You can check the [original proposal](https://talk.nervos.org/t/secbit-labs-zkp-toolkit-ckb-a-zero-knowledge-proof-toolkit-for-ckb/4254) for more feature details.

## Examples

Use the Mini circuit and [Groth16](https://eprint.iacr.org/2016/260) scheme we supported as an example.

```rust
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use zkp_groth16::{
    create_random_proof, generate_random_parameters, verifier::prepare_verifying_key, verify_proof,
    Parameters, Proof, VerifyKey,
};
use zkp_r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use rand::prelude::*;

struct Mini<F: PrimeField> {
    pub x: Option<F>,
    pub y: Option<F>,
    pub z: Option<F>,
    pub num: u32,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Mini<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let var_x = cs.alloc(|| "x", || self.x.ok_or(SynthesisError::AssignmentMissing))?;

        let var_y = cs.alloc(|| "y", || self.y.ok_or(SynthesisError::AssignmentMissing))?;

        let var_z = cs.alloc_input(
            || "z(output)",
            || self.z.ok_or(SynthesisError::AssignmentMissing),
        )?;

        for _ in 0..self.num {
            cs.enforce(
                || "x * (y + 2) = z",
                |lc| lc + var_x,
                |lc| lc + var_y + (F::from(2u32), CS::one()),
                |lc| lc + var_z,
            );
        }

        Ok(())
    }
}

/// test for use groth16 & bls12_381 & mimc gadget.
fn main() {
    let mut rng = thread_rng();

    // TRUSTED SETUP
    println!("TRUSTED SETUP...");
    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: 10, // 10-times constraints
    };
    let params = generate_random_parameters::<Bls12_381, _, _>(c, &mut rng).unwrap();

    // you need to save this verify key,
    // when verify, use it as a param.
    let vk_bytes = postcard::to_allocvec(&params.vk).unwrap();

    // you need to save this prove key,
    // when prove, use it as a param.
    let params_bytes = postcard::to_allocvec(&params).unwrap();

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    let x = Fr::from(2u32);
    let y = Fr::from(3u32);
    let z = Fr::from(10u32);

    let circuit = Mini {
        x: Some(x),
        y: Some(y),
        z: Some(z),
        num: 10,
    };

    println!("GROTH16 START PROVE...");
    let proof = create_random_proof(&params, circuit, &mut rng).unwrap();

    println!("GROTH16 START VERIFY...");
    assert!(verify_proof(&pvk, &proof, &[Fr::from(10u32)]).unwrap());
}
```

### More

Check more examples at [ckb-zkp/examples](./examples/).

## Features

1. Efficient computation.
2. Variety of curves.
3. Variety of zkp schemes.
4. Multiple out-of-the-box gadgets.
5. `no-std` is supported.

Currently, We supported multiple zkp schemes and curves, And we also supported some useful gadgets that could be sharable between schemes by standard R1CS.

### Schemes

- [Groth16](https://eprint.iacr.org/2016/260) The most popular zkSNARK scheme, smallest proof size.
- [Bulletproofs](https://crypto.stanford.edu/bulletproofs/) Short proofs, no trusted-setup.
- [Spartan](https://eprint.iacr.org/2019/550) Efficient and general-purpose zkSNARKs without trusted setup.
- [Marlin](https://eprint.iacr.org/2019/1047) Universal and Updatable SRS.
- [CLINKv2]() Optimized for parallel data processing, support large-scale data (up to GigaBytes), no trusted-setup.
- [Libra](https://eprint.iacr.org/2019/317) Succinct Zero-Knowledge Proofs with Optimal Prover Computation.
- [Hyrax](https://eprint.iacr.org/2017/1132) Doubly-efficient zkSNARKs without trusted setup.
- [aSVC](https://eprint.iacr.org/2020/527) Aggregatable Subvector Commitments for Stateless Cryptocurrencies.

### Curves
- [ark-curves](https://github.com/arkworks-rs/curves)
- [curve25519](./curve25519)

### gadgets

- BLAKE2s
- Boolean
- Lookup
- Merkletree
- MiMC
- Multieq
- Poseidon
- Rangeproof
- Rescue
- SHA256
- ... Many others ...

Check the [gadget doc](./gadgets) for more details.

## CLI-Command

Check [CLI usage](./cli) for hands-on examples.

## Security

This project is still under active development and is currently being used for research and experimental purposes only. Please **DO NOT USE IT IN PRODUCTION** for now.

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

Inspired by [bellman](https://github.com/zkcrypto/bellman), [zexe](https://github.com/scipr-lab/zexe), [libsnark](https://github.com/scipr-lab/libsnark), [dalek-bulletproofs](https://github.com/dalek-cryptography/bulletproofs) and other great projects.
