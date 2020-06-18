# zkp-cli

A cli toolkit for zkp.

*Currently zkp-cli uses the already implemented gadgets as separate circuits for a simple demonstration. As more zkp algorithms are added in the future, we will refactor and add more features to zkp-cli.*

## Usage

- **YOU NEED TRUSTED-SETUP** to run Groth16 scheme
  - `cargo run --bin trusted-setup mimc` (Prove key and verify key will be generated in the `trusted_setup` directory)
  - The random common reference string (CRS) generated in this way is for testing purposes only. These parameters would have to be generated securely by a trusted setup, which is normally through a trusted third party or a multi-party computation.

- Use default groth16 as scheme and bn_256 as curve, and prove knowledge of the preimage of a MiMC hash invocation which is the secret string.
  - `cargo run --bin zkp-prove mimc --string=iamsecret` (A proof file will be generated at `proofs_files` directory)
  - `cargo run --bin zkp-verify mimc proofs_files/mimc.groth16-bn_256.proof`

- Use custom schemes and curves as backend, and prove knowledge of the preimage of a MiMC hash invocation which is the file value.
  - `cargo run --bin zkp-prove mimc groth16 bls12_381 --file=README.md` (A proof file will be generated at `proofs_files` directory)
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
    --json    -- input/ouput use json type file.
    --prepare -- use prepare verify key when verify proof.
```

You can use the `--json` option to get the proof file in JSON format.

### zkp-verify

```
zkp-verify

Usage: zkp-verify [GADGET] <scheme> <curve> [FILE] <OPTIONS>

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
    --json    -- input/ouput use json type file.
    --prepare -- use prepare verify key when verify proof.
```

You can use the `--json` option to pass the proof file in JSON format.