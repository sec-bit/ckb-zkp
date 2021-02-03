# ckb-zkp

[![CI](https://flat.badgen.net/github/checks/sec-bit/ckb-zkp/master)](https://github.com/sec-bit/ckb-zkp/actions)
[![License:Apache](https://flat.badgen.net/badge/license/Apache%202.0/blue)](./LICENSE-APACHE)
[![License: MIT](https://flat.badgen.net/badge/license/MIT/orange)](./LICENSE-MIT)

<!-- The badge below is for future usage. -->
<!-- [![crates.io](https://flat.badgen.net/crates/v/ckb-zkp)]() -->

_(a.k.a. zkp-toolkit-ckb)_

Zero-knowledge proofs toolkit for CKB, empowering the community with the cutting-edge techniques of zero-knowledge proofs to develop all kinds of decentralized applications.

The project is going to bridge the gap of cryptographic engineering between thriving academic research and aspiring dAPPs developers, by providing multiple zkp schemes and curve options, a more user-friendly interface, many useful gadget libraries, and many more tutorials and examples.

Besides, it provides smart contracts that run as zero-knowledge proof verifiers on the Nervos CKB chain. CKB developers and users can implement various complex zero-knowledge verification processes through the simplest contract invocation. Cooperate with the core [zkp-toolkit](./zkp-toolkit.md) to complete off-chain prove and on-chain verify.

This project is also known as _zkp-toolkit-ckb_ and is supported by the Nervos Foundation. Check out the [original proposal](https://talk.nervos.org/t/secbit-labs-zkp-toolkit-ckb-a-zero-knowledge-proof-toolkit-for-ckb/4254) and [grant announcement](https://medium.com/nervosnetwork/three-new-ecosystem-grants-awarded-892b97e8bc06).

The following document is more focused on CKB smart contracts. [Check this doc](./zkp-toolkit.md) for more details on zkp-toolkit usage and features.

## What's new?

### Milestone #2 (2020/12/20)

- More schemes: Marlin, Spartan, CLINKv2, Libra, Hyrax, and aSVC
- Efficient ECC for zkSNARKs: Jubjub and BabyJubJub
- More useful gadgets: sha256, blake2s, Poseidon, rescue, and Merkle tree
- More examples
- Many new zkp verifiers on CKB-VM
- Benchmarks on curves, schemes, and CKB-VM

### Milestone #1 (2020/07/10)

An early runnable version of the toolkit with basic features.

- Schemes: Groth16 and Bulletproofs with R1CS
- Curves: BN256 and BLS12-381
- Gadgets: basic gadgets
- Smart contracts: Groth16 verifier on CKB-VM

## Table of contents

- [ckb-zkp](#ckb-zkp)
  - [What's new?](#whats-new)
    - [Milestone #2 (2020/12/20)](#milestone-2-20201220)
    - [Milestone #1 (2020/07/10)](#milestone-1-20200710)
  - [Table of contents](#table-of-contents)
  - [How does this contract help to verify a zero-knowledge proof?](#how-does-this-contract-help-to-verify-a-zero-knowledge-proof)
  - [Prerequisites](#prerequisites)
  - [Build contracts](#build-contracts)
    - [Enable `debug!` macro in release mode](#enable-debug-macro-in-release-mode)
  - [Tests](#tests)
    - [Run zkp-toolkit cli tests](#run-zkp-toolkit-cli-tests)
    - [Run CKB contacts tests](#run-ckb-contacts-tests)
  - [Deployment](#deployment)
    - [Invoking the contract on-chain](#invoking-the-contract-on-chain)
    - [Debugging the `capsule` itself (Temporary usage)](#debugging-the-capsule-itself-temporary-usage)
  - [Optimizations & Benchmarks](#optimizations--benchmarks)
    - [Binary size optimization](#binary-size-optimization)
    - [Curve benchmark](#curve-benchmark)
    - [Disabling ckb-zkp's crate features of curves for the verifier contract](#disabling-ckb-zkps-crate-features-of-curves-for-the-verifier-contract)
    - [Further optimizations](#further-optimizations)
  - [Troubleshooting](#troubleshooting)
    - [`capsule` complained `error: Can't found capsule.toml, current directory is not a project`](#capsule-complained-error-cant-found-capsuletoml-current-directory-is-not-a-project)
    - [I can't see any output of my contract in the CKB's log on dev chain.](#i-cant-see-any-output-of-my-contract-in-the-ckbs-log-on-dev-chain)
    - [The test can't find contract binary.](#the-test-cant-find-contract-binary)
    - [How is the project mounted into the Docker container?](#how-is-the-project-mounted-into-the-docker-container)
    - [What does "cycles" mean in Nervos ckb?](#what-does-cycles-mean-in-nervos-ckb)
  - [Acknowledgement](#acknowledgement)
  - [Security](#security)
  - [License](#license)

## How does this contract help to verify a zero-knowledge proof?

A contract for verification is deployed on the ckb chain. The prover and the verifier know where the contract is deployed.

1. The prover completes the trusted-setup, and generates a proof (in the form of a file);
2. The prover sends a transaction that creates some new cells(aka. utxo, but carrying some data), with one containing the proof and vk files and using the previous contract as its type script (which means, this cell should pass the verification of the contract logic);
3. The miner collects the transaction and executes the assigned contract. All the cells in a transaction assigning one contract as type script are verified by the contract logic. Otherwise, the transaction is rejected by the miner.
4. The prover goes public with the transaction, the proof, the vk file, and the verification contract address that is needed to do the verification.
5. The verifier is able to verify the proof using the information provided by the prover.

## Prerequisites

1. Ensure the version of rustc is **not lower than** 1.42 and use **stable** version of toolchain.

2. Install the CKB contract development framework [capsule](https://github.com/nervosnetwork/capsule). Access the [wiki page](https://github.com/nervosnetwork/capsule/wiki) for more details about `capsule`.

   ```sh
   cargo install ckb-capsule
   ```

3. Deploy a ckb dev chain if you need to deploy the contract to the blockchain. See https://docs.nervos.org/dev-guide/devchain.html for guidance.

## Build contracts

You can choose to build the contract in **dev** mode or **release** mode like Cargo. The product under release mode is suitable for deployment with a reasonable size and execution consumption, and, `debug!` macro is disabled. Dev mode product allows you to use `debug!` macro to print logs in ckb log, but on the cost of larger binary size and execution cycles. The product resides in _./ckb-contracts/build/[release|debug]/universal_groth16_verifier_.

ATTENTION:

- all the `capsule` commands should be executed at the project root.
- Users in mainland China can add the [tuna's mirror of crates.io](https://mirrors.tuna.tsinghua.edu.cn/help/crates.io-index.git/) in the file _./cargo/config_ for a faster download of dependencies.

```sh
# At ckb-contracts directory.
# Dev mode, enable debug! macro but result in bloated size.
cd ckb-contracts
capsule build
# Release mode. Slim, no outputs in the logs.
capsule build --release
```

### Enable `debug!` macro in release mode

**In `ckb-std` version 0.7.2 and newer, `debug!` macro is disabled in release mode**. If you still want to enable `debug!` macro in **release** mode, insert `debug-assertions = true` under `[profile.release]` in `ckb-contracts/Cargo.toml`.

## Tests

A simplified, one-time blockchain context is used in the test environment using [ckb-tool](https://github.com/jjyr/ckb-tool) crate. Needless to setup an authentic blockchain and run a ckb node, one can simply send a transaction to invoke the contract and checkout if the contract works as expected.

### Run cli tests

1. Go to _./cli_ and generate a vk file and a proof file using ckb-zkp's command line utility.

   Use groth16 scheme & bls12_381 curve:

   1. Complete trusted-setup:

      ```sh
      # ./cli
      cargo run --bin setup groth16 bls12_381 hash
      ```

   2. Prove the secret string.

      ```sh
      # ./cli
      cargo run --bin zkp-prove groth16 bls12_381 hash iamsecret
      ```

      When successful, it will create a proof file at proof_files.

   3. (Optional) Do the verification.

      ```sh
      # ./cli
      cargo run --bin zkp-verify proof_files/groth16-bls12_381-hash.proof.json
      ```

   Check supported schemes and curves:

   ```sh
   # ./cli
   cargo run --bin setup
   cargo run --bin zkp-prove
   cargo run --bin zkp-verify
   ```

   See [cli document](./cli) for further help.

### Run CKB contacts tests

ATTENTION:

- If you build the contract with `--release` flag, you should run tests with `CAPSULE_TEST_ENV=release`.
- The flag `--test-threads 1` after `--` is used to ensure `debug!` outputs print in order.
- In the file _./tests/src/tests.rs_, you can uncomment the `#[ignore]` attribute (By remove the leading double slants `//`) before a test function to omit during the testing. Or specify the test function name to filter others out.
- Or you can specify a test function name, and perform only one test.

```sh
# At ckb-contracts/bench-tests directory root
# Dev mode contracts.
cargo test -- --nocapture --test-threads 1
# Release mode contracts.
CAPSULE_TEST_ENV=release cargo test -- --nocapture
# Specify a test name `test_groth16` that you want to execute
CAPSULE_TEST_ENV=release cargo test test_groth16 -- --nocapture
```

## Deployment

`Capsule` brings out-of-box contract deploying and migrating. It works for development and test on dev chain. To deploy a contract you have just cooked, you need:

- A running ckb client on the local machine or the net.
- A ckb-cli executable. `capsule` uses ckb-cli to interact with ckb client.
- An account with sufficient CKBs for deployment (1 Byte of contract binary will consume 1 CKB. The transaction body will also take some extra CKBs, but not much). This account should be imported into ckb-cli.
- A deployment manifest _./ckb-contracts/deployment.toml_, which assigns the contract binary and cell lock-arg.

When everything needed is met, you should theoretically be able to deploy the contract. Use the command below to launch the transaction, and note that commonly the `<ADDRESS>` is a 46-bit alphanumeric string (Starting with `ckt1` if you use a test net or dev chain).

```shell
# At ckb-contracts directory root
capsule deploy --address <ADDRESS>
```

### Invoking the contract on-chain

No ready-to-use gear for invoking a contract on a real chain. Use ckb-cli, or an [SDK](https://docs.ckb.dev/docs/docs/sdk/sdk-overview) to build a transaction to invoke the contract on-chain.

### Debugging the `capsule` itself (Temporary usage)

You can use the **master** branch of `capsule` and the following commands to track the panics.

```shell
# At ckb-contracts directory root
RUST_LOG=capsule=trace capsule deploy --address <ADDRESS>
```

## Optimizations & Benchmarks

In Nervos ckb, [one should pay for data storage, transaction fees and computer resources](https://docs.nervos.org/key-concepts/economics.html#the-economics-of-the-ckbyte). Paying for data storage means, one needs to pay a number of ckb tokens in direct proportion to the size of the transaction he raises. Paying for computer resources means one should pay extra ckbs based on the amount of computer resources that are used to verify a transaction. The computer resources are measured as [**cycles**](https://docs.nervos.org/glossary/glossary-general.html#cycles).

On the other hand, [On mainnet Lina, the value of `MAX_BLOCK_BYTES` is `597_000` and `MAX_BLOCK_CYCLES` is `3_500_000_000`.](https://docs.nervos.org/technical-concepts/architecture.html#computing-cycles-and-transaction-size)

For these reasons, we take contract binary size and execution cost both into consideration.

### Binary size optimization

The deployer should pay for storing his contract on-chain. The larger the binary is, the more ckb tokens will be spent for deployment. So several compiling options are analyzed to reduce the contract binary size.

- To build in release mode, this is enabled by default.
- LTO
- Strip
- `opt-level`
- `codegen-units`

To use LTO, `opt-level` and `codegen-units`, modify _Cargo.toml_:

```toml
# File: ckb-contracts/Cargo.toml
[profile.release]
overflow-checks = true
# lto: true, "thin", false(default)
lto = true
# opt-level: 0, 1, 2, 3(default), "s", "z"
opt-level = "z"
# codegen-units: greater than 0, default 16
codegen-units = 1
```

To strip the binary, use `rustflags = "-C link-arg=-s"` in cargo config, which is a default option in Capsule with release compiling mode.

We will not try to explain what each option means (Explained in _The Cargo Book_), but list the size and running cost of the contract binaries under different combinations of these building options.

Test setup:

- Release mode;
- stripped;
- using `jjy0/ckb-capsule-recipe-rust:2020-9-28` to build and test and measure running costs;
- using scheme groth16 and curve bn_256;
- ckb-std version 0.7.2;
- ckb-tool and ckb-testtool version 0.2.2;
- Default profile setting: `overflow-checks = true` and `panic = 'abort'`.

| LTO     | `opt-level` | `codegen-units` | Binary size(Byte) | Execution cost (cycles) |
| ------- | ----------- | --------------- | ----------------- | ----------------------- |
| not set | not set     | not set         | 192,152           | 90,944,391              |
| `true`  | not set     | not set         | 172,976           | 93,392,615              |
| `true`  | `"s"`       | not set         | 107,440           | 151,462,521             |
| `true`  | `"z"`       | not set         | 70,576            | 191,976,741             |
| `true`  | `"z"`       | `1`             | 58,288            | 195,535,979             |

Here comes a rough result:

- Generally, size decreasing results to execution cost increasing.
- Enabling LTO, use `opt-level = "z"`, `codegen-units = 1` and `panic = "abort"` for minimum binary size, at the cost of a higher cycle consumption.

### Curve benchmark

Currently, we use different curves in proving and verifying, so we performed a simple benchmark on execution costs separately.

Test setup:

- Release mode;
- stripped;
- Profile: `LTO = true`, `codegen-units = 1`, `panic = "abort"`, `overflow-checks = true`, `opt-level = "z"`;
- using `jjy0/ckb-capsule-recipe-rust:2020-9-28` to build and test and measure running costs;
- using scheme bulletproofs (it can use all curves);
- ckb-std version 0.7.2;
- ckb-tool and ckb-testtool version 0.2.2.

| Curve       | Binary size(Byte) | Execution cost (cycles) |
| ----------- | ----------------- | ----------------------- |
| bn_256      | 91,056            | 796,836,045             |
| bls12_381   | 91,056            | 1,908,755,330           |
| JubJub      | 74,672            | 695,621,515             |
| Baby_JubJub | 74,762            | 691,819,058             |

### Disabling ckb-zkp's crate features of curves for the verifier contract

Currently, we use different schemes in proving and verifying, so we performed a simple benchmark on execution costs separately.

Test setup:

- Release mode;
- stripped;
- Profile: `LTO = true`, `codegen-units = 1`, `panic = "abort"`, `overflow-checks = true`, `opt-level = "z"`;
- using `jjy0/ckb-capsule-recipe-rust:2020-9-28` to build and test and measure running costs;
- using curve bn_256 (it can use all schemes);
- ckb-std 0.7.2;
- ckb-tool and ckb-testtool version 0.2.2.

| Scheme          | Binary size(Byte) | Execution cost (cycles) |
| --------------- | ----------------- | ----------------------- |
| Groth16         | 58,288            | 195,535,979             |
| Bulletproofs    | 91,056            | 796,836,045             |
| Marlin          | 132,016           | 500,725,146             |
| Spartan (nizk)  | 91,056            | 1,085,652,230           |
| Spartan (snark) | 119,728           | 1,911,833,747           |
| CLINKv2 (ipa)   | 82,864            | 508,330,342             |
| CLINKv2 (kzg10) | 82,864            | 213,212,113             |

### Further optimizations

We have accomplished the main goal we set for the Milestone-I of the [zkp-toolkit-ckb](https://talk.nervos.org/t/secbit-labs-zkp-toolkit-ckb-a-zero-knowledge-proof-toolkit-for-ckb/4254), which was a simple on-chain verifier for CKB. The proof-of-concept smart contract code shows that we can make a usable zkp verifier for CKB with pure Rust without modifying the underlying chain. This also gives us a baseline on the performance of zkp verifiers for CKB-VM.

We'll implement more zkp verifiers in the following milestones, looking at reducing the binary size and [execution](https://xuejie.space/2020_03_03_introduction_to_ckb_script_programming_performant_wasm/) [cost](https://xuejie.space/2020_04_09_language_choices/), as well as the best practice to integrate with other contracts.

## Troubleshooting

### `capsule` complained `error: Can't found capsule.toml, current directory is not a project`

All the commands executed by `capsule` should be executed under the project root.

### I can't see any output of my contract in the CKB's log on dev chain.

Modify ckb's configuration as below:

```toml
# File: ckb.toml of your chain.
[logger]
filter = "info,ckb-script=debug"
```

### The test can't find contract binary.

Make sure you **build and test the contract in the same mode** (dev or release, specified by flag `--release`).

```sh
# At ckb-contracts directory root
capsule build && cargo test -p tests --tests -- --nocapture --test-threads 1
# Or
capsule build --release && CAPSULE_TEST_ENV=release cargo test -p tests --tests -- --nocapture
```

As capsule executes building and testing in docker, the absolute path may not work as expected, so **use relative path**. And currently, the Capsule (nervosnetwork/capsule) mount the whole project folder into docker, so any relative location inside the project folder is allowed.

### How is the project mounted into the Docker container?

In the `nervosnetwork/capsule`, `capsule` mounts the project folder into the container with path _/code_. But in the main source `nervosnetwork/capsule`, `capsule` may only mount the contract folder into the container. As docker is used, the absolute path is not recommended.

### What does "cycles" mean in Nervos ckb?

The concept and intruduction of cycles can be found [here](https://docs.nervos.org/glossary/glossary-general.html#cycles).

## Acknowledgement

- Many, many thanks to [jjy](https://github.com/jjyr), a developer of [nervosnetwork](https://github.com/nervosnetwork), for his selfless help and advice on this project.

## Security

This project is still under active development and is currently being used for research and experimental purposes only, please **DO NOT USE IT IN PRODUCTION** for now.

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.
