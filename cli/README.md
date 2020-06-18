# zkp-cli
A cli toolkit for zkp.

*Currently zkp-cli uses the already implemented gadgets as separate circuits for a simple demonstration. As more zkp algorithms are added in the future, we will refactor and add more features to zkp-cli.*

## Usage
- **YOU NEED TRUSTED-SETUP** use groth16 & bn_256 as default.
  - `cargo run --bin trusted-setup mimc` (When success, it will create prove key and verify key in the current trusted_setup directory)
- Use default groth16 as scheme and bn_256 as curve, and prove the secret string.
  - `cargo run --bin zkp-prove mimc --string=iamsecret` (When success, it will create a proof file at proofs_files)
  - `cargo run --bin zkp-verify mimc proofs_files/mimc.groth16-bn_256.proof`

- Use custom schemes and curves as backend, and prove the file value.
  - `cargo run --bin zkp-prove mimc groth16 bls12_381 --file=README.md` (When success, it will create a proof file at proofs_files)
  - `cargo run --bin zkp-verify mimc groth16 bls12_381 proofs_files/README.md.mimc.groth16-bls12_381.proof`
  
### trusted-setup
```
trusted-setup

Usage: trusted-setup [GADGET] <scheme> <curve> <OPTIONS>

GADGET: 
    mimc    -- MiMC hash & proof.
    greater -- Greater than comparison proof.
    less    -- Less than comparison proof.
    between -- Between comparison proof.

scheme:
    groth16      -- Groth16 zero-knowledge proof system. [Default]
    bulletproofs -- Bulletproofs zero-knowledge proof system.

curve:
    bn_256    -- BN_256 pairing curve. [Default]
    bls12_381 -- BLS12_381 pairing curve.

OPTIONS:
    --prepare -- use prepare verify key when verify proof.

```
  
### zkp-prove
```
zkp-prove

Usage: zkp-prove [GADGET] <scheme> <curve> [GADGET OPTIONS] <OPTIONS>

```

### zkp-verify
```
zkp-verify

Usage: zkp-verify [GADGET] <scheme> <curve> [FILE] <OPTIONS>

```
