# zkp-toolkit

## Introduction
Zero-knowledge proof system toolkit with pure Rust.

Current zero-knowledge proof library is too low-level, and users must have a good knowledge before they can use it. The purpose of this project is to lower the difficulty for using zero-knowledge proof, and easy to use, so it can be used by users of all levels.
The project now is FOR EXPERIMENTS, DONOT USE IN PRODUCTION.

## Example
Use we supported MiMC gadget and groth16 zero-knowledge proof as an example. 
```rust
use zkp::{prove, prove_to_bytes, verify, verify_from_bytes, Curve, Gadget, Scheme};

fn main() {
    let bytes = vec![1, 2, 3, 4, 5]; // this is your secret.

    // Method1: use Proof struct.
    use curve::bn_256::Bn_256;
    let proof = prove::<Bn_256>(Gadget::MiMC, Scheme::Groth16, Curve::Bn_256, &bytes).unwrap();
    let is_ok = verify(&proof);
    assert!(is_ok);

    // Method2: use Bytes.
    let proof_bytes = prove_to_bytes(Gadget::MiMC, Scheme::Groth16, Curve::Bn_256, &bytes).unwrap();
    let is_ok2 = verify_from_bytes(&proof_bytes);
    assert!(is_ok2);

    println!("all is ok");
}
```

## Cli-Command.
Use MiMC zero-knowledge proof as an example. 
- Use default groth16 as scheme and bn256 as curve，and prove the secret string.
   - `cargo run --bin zkp-prove mimc --string=iamsecret` (When success, it will create a proof file at proofs_files/mimc_proof)
   - `cargo run --bin zkp-verify proofs_files/mimc_proof`

- Use custom schemes and curves as backend, and prove the file value.
   - `cargo run --bin zkp-prove mimc groth16 bls12_381 --file=README.md` (When success, it will create a proof file at proofs_files/REAME.md.mimc_proof)
   - `cargo run --bin zkp-verify proofs_files/REAME.md.mimc_proof`

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
