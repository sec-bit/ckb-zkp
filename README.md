# ckb-zkp

- [ckb-zkp](#ckb-zkp)
  - [Prerequisites](#prerequisites)
  - [Build contracts](#build-contracts)
  - [Run tests](#run-tests)
  - [Binary Optimization](#binary-optimization)

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

3. Add dependencies.

   Add the dependency `zkp-toolkit` under the root of the contract folder, whose path looks like this: _./contracts/ckb-zkp/zkp-toolkit_, and exclude the dependency folders in cargo manifest as follow:

   ```toml
    [workspace]
    exclude = ["zkp-toolkit"]
   ```

   Reason: By now, the dependency `zkp-toolkit` is not available via a public git url, and we can only add this dependency from local file. However, `capsule` did not support using local files as dependencies. So as workaround, we put dependencies into the contract folder and exclude them.

4. Generate a proof file

   Generate a proof file and put it into the contract folder _./contracts/ckb-zkp/_, and assign the position of the proof file in ./tests/src/tests.rs, the constant PROOF_FILE.

   Attention: If you want to build and run `zkp-toolkit` at _./contracts/ckb-zkp/zkp-toolkit_, you should explicitly pass `target` parameter to cargo.

## Build contracts

```sh
capsule build --release
```

## Run tests

To run tests with a proof, you need to provide the path of the proof file to the test _./tests/src/tests.rs_, using the constant `PROOF_FILE`.

Then the following command.

```sh
capsule test --release
```

## Binary Optimization

In ckb, the costs comes from the size of the built transaction. Heavier in size means higher in cost, while running cost (total instructs executed).So several compiling options are used to try to reduce the contract binary size.

- To build in release mode, this is used by default.
- LTO
- Strip
- `opt-level`
- `codegen-units`

To use LTO, `opt-level` and `codegen-units`, modify *Cargo.toml*:

```toml
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

| LTO   | `opt-level` | `codegen-units` | Binary size | cycles        |
| ----- | ----------- | --------------- | ----------- | ------------- |
| false | not set     | not set         | 213792      | 102902773     |
| true  | not set     | not set         | 221912      | 101517377     |
| true  | “z”         | not set         | 90840       | 279663892     |
| false | “z”         | not set         | 99104       | failed to run |
| true  | “z”         | 1               | 74456       | 290196835     |
| true  | “s”         | 1               | 86744       | 203553832     |
