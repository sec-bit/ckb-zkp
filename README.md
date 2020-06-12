# ckb-zkp

Smart contracts that run a zero-knowledge proof system on the [Nervos CKB chain](https://www.nervos.org/). CKB developers and users can implement various complex zero-knowledge verification processes through the simplest contract invocation. Cooperate with zkp-toolkit to complete offline prove and online verify.

## Table of contents

- [ckb-zkp](#ckb-zkp)
  - [Table of contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Build contracts](#build-contracts)
    - [Enable `debug!` macro in release mode](#enable-debug-macro-in-release-mode)
  - [Tests](#tests)
    - [Prerequises for testing](#prerequises-for-testing)
    - [Run tests](#run-tests)
  - [Deployment](#deployment)
    - [Invoking the contract on-chain](#invoking-the-contract-on-chain)
    - [Debugging the `capsule` itself (Temporary feature)](#debugging-the-capsule-itself-temporary-feature)
  - [Binary optimization](#binary-optimization)
  - [Curve benchmark](#curve-benchmark)
  - [Troubleshooting](#troubleshooting)
    - [I can't see any output in the ckb's log on dev vhain.](#i-cant-see-any-output-in-the-ckbs-log-on-dev-vhain)
    - [The test can't find contract binary/proof file/vk file.](#the-test-cant-find-contract-binaryproof-filevk-file)
    - [How is the project mounted into the Docker container?](#how-is-the-project-mounted-into-the-docker-container)
  - [References](#references)
  - [License](#license)

## Prerequisites

1. Install the development framework [`capsule`](https://github.com/nervosnetwork/capsule). Access its [wiki page](https://github.com/nervosnetwork/capsule/wiki) for more details about `capsule`.

   ```sh
   cargo install capsule --git https://github.com/jjyr/capsule.git --rev=2f9513f8
   ```

   `capsule` is under development and not stable, so please specify the revision when installing.

2. Pull the [docker image](https://hub.docker.com/r/jjy0/ckb-capsule-recipe-rust) used to build contracts.

   ```sh
   docker pull jjy0/ckb-capsule-recipe-rust:2020-6-2
   ```

3. Deploy a ckb dev chain. See https://docs.nervos.org/dev-guide/devchain.html for guidance.

4. Add the local dependency (optional) and specify the revision of dependency (necessary).

   ATTENTION: **This step is not necessary when the `zkp-toolkit` repo is available on Github. Only use local dependency on development, especially when developing `zkp-toolkit`.**

   - `zkp-toolkit` is available on Github or crates.io, and you don't need to modify `zkp-toolkit`.

     Simply use git url or version tag in manifest of the contract. If you want to modify the `zkp-toolkit` library, see the section below.

     Specify the revision of dependency `zkp-toolkit`.

     ```toml
     # File: ./contracts/ckb-zkp/Cargo.toml
     [dependencies]
     zkp = { git = "https://github.com/sec-bit/zkp-toolkit.git", rev = "3bfcda742a", default-features = false, features = [
         "groth16",
         "bn_256"
     ] }
     ```

   - `zkp-toolkit` is not available on Github or crates.io, or you want to modify `zkp-toolkit`.

     Pull the dependency `zkp-toolkit` into _dependencies_ folder like _./dependencies/zkp-toolkit_, and specifiy the revision:

     ```sh
     # At ./dependencies/zkp-toolkit
     git checkout 3bfcda742a
     ```

     Readon: During early development, the dependency `zkp-toolkit` is not available via a public git url, so we can only access this dependency via local path.

## Build contracts

Like Cargo, you can choose to build contract in **dev** mode or **release** mode. The product under release mode is suitable for deployment with a reasonable size and execution consumption, and, `debug!` macro is disabled. Dev mode product allows you to use `debug!` macro to print logs in ckb log, but on cost of larger binary size. The product resides in _./build/[release|debug]/ckb-zkp_.

```sh
# Dev mode, enable debug! macro but result in bloated size.
capsule build
# Release mode. Slim, no debug!.
capsule build --release
```

### Enable `debug!` macro in release mode

**In `ckb-std` in version 0.2.2, `debug!` macro is disabled in release mode**. If you still want to enable `debug!` macro in **release** mode, insert `debug-assertions = true` under `[profile.release]` in `contracts/ckb-zkp/Cargo.toml`.

## Tests

### Prerequises for testing

1. Generate a vk file and a proof file.

   Generate a vk file and a proof file. See https://aciclo.net/zkp/zkp-toolkit#cli-command for help.

   Put these files into anywhere of project folder, and assign the positions and names of the files in _./tests/src/tests.rs_. The default location and names suits the local dependency pattern.

### Run tests

Make sure vk file(s) and proof file(s) are prepared.

Then type the following command.

ATTENTION: If you build the contract with `--release` flag, you should run test with `--release`, and vice versa.

```sh
# Dev mode
capsule test
# Release mode, built with --release flag.
capsule test --release
```

If you find it slow to run testing, use the following command instead:

```sh
# Dev mode contracts.
cargo test -p tests --tests -- --nocapture
# Release mode contracts.
CAPSULE_TEST_ENV=release cargo test -p tests --tests -- --nocapture
```

You can uncomment the `#[ignore]` attribute before a test function to omit it.


## Deployment

`Capsule` brings out-of-box contract deploying and migrating. It works for development and test on dev chain. To deploy a contract you have just cooked, you need:

- A running ckb client on local machine or on the net.
- A ckb-cli executable. `capsule` uses ckb-cli to interact with ckb client.
- An account with sufficient CKBs for deployment (1 Byte of contract binary will comsume 1 CKB. The transaction body will also take some extra CKBs, but not much). This account should be imported into ckb-cli.
- A deployment manifest _capsuled-contracts/deployment.toml_, which assigns the contract binary and cell lock-arg.

When everything needed is met, you should theoretically be able to deploy the contract. Use the command below to launch the transaction, and note that commonly the `<ADDRESS>` is a 46-bit alphanumeric string (Starting with `ckt1` if you use a test net or dev chain).

```shell
capsule deploy --address <ADDRESS>
```

### Invoking the contract on-chain

TODO: No ready-to-use gear for invoking, use `ckb-cli` or an sdk to build a transaction to invoke the contract.

### Debugging the `capsule` itself (Temporary feature)

You can use the **master** branch of `capsule` and the following commands to track the panics.

```shell
RUST_LOG=capsule=trace capsule deploy --address <ADDRESS>
```

## Binary optimization

In ckb, the costs comes from the size of the built transaction. Heavier in size means higher in cost, while running cost (total instructs executed).So several compiling options are used to try to reduce the contract binary size.

- To build in release mode, this is enabled by default.
- LTO
- Strip
- `opt-level`
- `codegen-units`

To use LTO, `opt-level` and `codegen-units`, modify _Cargo.toml_:

```toml
# File: contracts/ckb-zkp/Cargo.toml
[profile.release]
overflow-checks = true
# lto: true, "thin", false(default)
lto = true
# opt-level: 0(default), 1, 2, 3, "s", "z"
opt-level = "z"
# codegen-units: greater than 0, default 16
codegen-units = 1
```

To strip the binary, use `rustflags = "-C link-arg=-s"` in cargo config.

We will not try to explain what each option means (Explained in _The Cargo Book_), but list the size and running cost of the contract binaries under different option combinations.

Common setup: Release mode, stripped, using `capsule` to build and test and measure running costs.

| LTO   | `opt-level` | `codegen-units` | Binary size(Byte) | cycles        |
| ----- | ----------- | --------------- | ----------------- | ------------- |
| false | not set     | not set         | 213792            | 102902773     |
| true  | not set     | not set         | 221912            | 101517377     |
| true  | “z”         | not set         | 90840             | 279663892     |
| false | “z”         | not set         | 99104             | failed to run |
| true  | “z”         | 1               | 74456             | 290196835     |
| true  | “s”         | 1               | 86744             | 203553832     |

Here comes a rough result:

- Enable LTO, use `opt-level = "z"`, `codegen-units = 1` for minimun binary size, with a large cycle consumption.
- Enable LTO, use `opt-level = "s"`, `codegen-units = 1` for a balance of binary size and cycle consumption.

## Curve benchmark

TODO, test curve bn256 and bls12_381 for cycle consumption.

## Troubleshooting

### I can't see any output in the ckb's log on dev vhain.

Modify ckb's configuration as below:

```toml
# File: ckb.toml of your chain.
[logger]
filter = "info,ckb-script=debug"
```

### The test can't find contract binary/proof file/vk file.

Make sure you **build and test the contract in the same mode** (dev or release, specified by flag `--release`).

```sh
capsule build && capsule test
# Or
capsule build --release && capsule test --release
```

As capsule executes building and testing in docker, absolute path may not work as expected, so **use relative path**. And currently capsule (jjyr/capsule revision 2f9513f8) mount the whole project folder into docker, so any relative location inside the project folder is allowed.

### How is the project mounted into the Docker container?

In the fork of `jjyr/capsule` revision `2f9513f8`, `capsule` mounts the project folder into the container with path _/code/capsuled-contracts_. But in the main source `nervosnetwork/capsule`, `capsule` may only mount the contract folder into the container. As docker is used, absolute path is not recommended.

## References

<!-- TODO -->

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.
