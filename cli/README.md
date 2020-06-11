# zkp-cli
A cli toolkit for zkp.

## Usage
- **YOU NEED TRUSTED-SETUP** use groth16 & bn_256 as an example.
  - `cargo run --bin trusted-setup mimc groth16 bn_256` (When success, it will create prove key and verify key in the current trusted_setup directory)
- Use default groth16 as scheme and bn_256 as curve，and prove the secret string.
  - `cargo run --bin zkp-prove mimc --string=iamsecret` (When success, it will create a proof file at proofs_files/mimc_proof)
  - `cargo run --bin zkp-verify mimc proofs_files/mimc_proof`

- Use custom schemes and curves as backend, and prove the file value.
  - `cargo run --bin zkp-prove mimc groth16 bls12_381 --file=README.md` (When success, it will create a proof file at proofs_files/REAME.md.mimc_proof)
  - `cargo run --bin zkp-verify mimc groth16 bls12_381 proofs_files/REAME.md.mimc_proof`
