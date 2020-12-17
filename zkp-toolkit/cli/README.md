# zkp-cli

A cli toolkit for zkp.

*Currently zkp-cli uses the already implemented gadgets as separate circuits for a simple demonstration. As more zkp algorithms are added in the future, we will refactor and add more features to zkp-cli.*

## Usage

- **YOU NEED TRUSTED-SETUP** to run Groth16 scheme
  - `cargo run --bin setup groth16 bn_256 hash` (Proving key and verification key will be generated in the `setup_files` directory)
  - The random common reference string (CRS) generated in this way is for testing purposes only. These parameters would have to be generated securely by a trusted setup, which is normally through a trusted third party or a multi-party computation.

- Use groth16 as scheme and bn_256 as curve, and prove knowledge of the preimage of a MiMC hash invocation which is the secret string.
  - `cargo run --bin zkp-prove groth16 bn_256 hash iamsecret` (A proof file will be generated at `proof_files` directory)
  - `cargo run --bin zkp-verify proofs_files/groth16-bn_256-hash.proof.json`

### setup

```
setup

Usage: setup [SCHEME] [CURVE] [CIRCUIT]

SCHEME:
    groth16       -- Groth16 zero-knowledge proof system.
    marlin        -- Marlin zero-knowledge proof system.
    spartan_snark -- Spartan with snark zero-knowledge proof system.
    spartan_nizk  -- Spartan with nizk zero-knowledge proof system.

CURVE:
    bn_256    -- BN_256 pairing curve.
    bls12_381 -- BLS12_381 pairing curve.

CIRCUIT:
    mini    -- Mini circuit. proof: x * (y + 2) = z.
    hash    -- Hash circuit. proof: mimc hash.

```

### zkp-prove

```
zkp-prove

Usage: zkp-prove [SCHEME] [CURVE] [CIRCUIT] [ARGUMENTS]

SCHEME:
    groth16       -- Groth16 zero-knowledge proof system.
    bulletproofs  -- Bulletproofs zero-knowledge proof system.
    marlin        -- Marlin zero-knowledge proof system.
    spartan_snark -- Spartan with snark zero-knowledge proof system.
    spartan_nizk  -- Spartan with nizk zero-knowledge proof system.

CURVE:
    bn_256    -- BN_256 pairing curve.
    bls12_381 -- BLS12_381 pairing curve.

CIRCUIT:
    mini    -- Mini circuit. proof: x * (y + 2) = z.
    hash    -- Hash circuit. proof: mimc hash.

CIRCUIT ARGUMENTS:
    [arguments]    -- circuits arguments.

```

### zkp-verify

```
zkp-verify

Usage: zkp-verify [PROOF_FILE]

```
