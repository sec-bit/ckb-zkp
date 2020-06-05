# ckb-zkp
Smart contracts that run a zero-knowledge proof system on the Nervos CKB chain. CKB developers and users can implement various complex zero-knowledge verification processes through the simplest contract invocation. Cooperate with zkp-toolkit to complete offline prove and online verify.

- [ckb-zkp](#ckb-zkp)
  - [Prerequisites](#prerequisites)
  - [Build contracts](#build-contracts)
    - [Enable `debug!` macro](#enable-debug-macro)
  - [Run tests](#run-tests)
  - [Binary Optimization](#binary-optimization)
  - [Deployment](#deployment)
    - [Invoking the contract on-chain](#invoking-the-contract-on-chain)
    - [Debugging the `capsule` itself (Temporary feature)](#debugging-the-capsule-itself-temporary-feature)
  - [References](#references)
  - [License](#license)

## Prerequisites

1. Install the development framework [`capsule`](https://github.com/nervosnetwork/capsule)

   ```sh
   cargo install capsule --git https://github.com/nervosnetwork/capsule.git --tag v0.0.1-pre.2
   ```

2. Pull the docker image used to build contracts.

   ```sh
   # docker imaged needing
   docker pull jjy0/ckb-capsule-recipe-rust:2020-5-9
   ```

3. Add dependencies.(Workaround)

   Add the dependency `zkp-toolkit` under the root of the contract folder, whose path looks like this: _./contracts/ckb-zkp/zkp-toolkit_, and exclude the dependency folders in cargo manifest as follow:

   ```toml
   # File: contracts/ckb-zkp/Cargo.toml
   [workspace]
   exclude = ["zkp-toolkit"]
   ```

   Reason: By now, the dependency `zkp-toolkit` is not available via a public git url, and we can only add this dependency from local file. However, `capsule` did not support using local files as dependencies. So as workaround, we put dependencies into the contract folder and exclude them.

4. Generate a proof file

   Generate a proof file and put it into the contract folder _./contracts/ckb-zkp/_, and assign the position of the proof file in ./tests/src/tests.rs, the constant PROOF_FILE.

   Attention: If you want to build and run `zkp-toolkit` at _./contracts/ckb-zkp/zkp-toolkit_, you should explicitly pass `target` parameter to cargo.

## Build contracts

Build the contract. The product is suitable for deployment with a reasonable size and execution consumption. In `release` mode, `debug!` macro is disabled. The product resides in _./build/release/ckb-zkp_.

```sh
capsule build --release
```


### Enable `debug!` macro

**In `ckb-std` in version 0.2.2, `debug!` macro is disabled in release mode build**. So if you need to `debug!`, use `dev` mode to build contract. In order to shrink the size and execution time of `dev` product, use the following configurations. 

```toml
# File: contracts/ckb-zkp/Cargo.toml
[profile.dev]
overflow-checks = true
lto = true
opt-level = "s"
codegen-units = 1
debug = 0
# debug-assertions = false
```

And do the construction.

```shell
capsule build
```

- If you still want to enable `debug!` macro in RELEASE mode, insert `debug-assertions = true` under `[profile.release]` in `contracts/ckb-zkp/Cargo.toml`.

## Run tests

To run tests with a proof, you need to provide the path of the **proof file** to the test _./tests/src/tests.rs_, using the constant `PROOF_FILE`.

Then the following command.

```sh
capsule test
# Or
capsule test --release
```

## Binary Optimization

In ckb, the costs comes from the size of the built transaction. Heavier in size means higher in cost, while running cost (total instructs executed).So several compiling options are used to try to reduce the contract binary size.

- To build in release mode, this is used by default.
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

We will not try to explain what each option means, but list the size and running cost of the contract binaries under different option combinations.

Condition: Release mode, stripped, using `capsule` to build and test and measure running costs.

| LTO   | `opt-level` | `codegen-units` | Binary size(Byte) | cycles        |
| ----- | ----------- | --------------- | ----------------- | ------------- |
| false | not set     | not set         | 213792            | 102902773     |
| true  | not set     | not set         | 221912            | 101517377     |
| true  | “z”         | not set         | 90840             | 279663892     |
| false | “z”         | not set         | 99104             | failed to run |
| true  | “z”         | 1               | 74456             | 290196835     |
| true  | “s”         | 1               | 86744             | 203553832     |

## Deployment

`Capsule` brings out-of-box contract deploying and migrating. It just works for development and test on dev chain. To deploy a contract you have just cooked, you need:

- A running ckb client on local machine or on the net.
- A ckb-cli executable. `capsule` uses ckb-cli to interact with ckb client.
- An account with sufficient CKBs for deployment (1 Byte of contract binary will comsume 1 CKB. The transaction body will also take some extra CKBs, but not much). This account should be imported into ckb-cli.
- A deployment manifest _capsuled-contracts/deployment.toml_, which assigns the contract binary and cell lock-arg.

When everything needed is met, you should theoretically be able to deploy the contract. Use the command below to launch the transaction, and note that commonly the `<ADDRESS>` is a 46-bit alphanumeric string (Starting with `ckt1` if you use a test net or dev chain).

```shell
capsule deploy --address <ADDRESS>
```

### Invoking the contract on-chain

TODO: No ready-to-use gear for invoking, use the Go script written by myself.

### Debugging the `capsule` itself (Temporary feature)

You can use the **master** branch of `capsule` and the following commands to track the panics.

```shell
RUST_LOG=capsule=trace capsule deploy --address <ADDRESS>
```

## References

TODO

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.
