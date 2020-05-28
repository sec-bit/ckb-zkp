# ckb-zkp

## Prerequisites

0. Install the development framework [`capsule`](https://github.com/nervosnetwork/capsule)
    ```sh
    cargo install capsule --git https://github.com/nervosnetwork/capsule.git --tag v0.0.1-pre.2
    ```

1. Docker image used to build contracts.

    ```sh
    # docker imaged needing
    docker pull jjy0/ckb-capsule-recipe-rust
    ```

2. Dependencies: as now, the dependency `zkp-toolkit` is not available via a public git url, this dependency should reside under the root of the contract folder, whose path looks like this: *./contracts/ckb-zkp/zkp-toolkit*. Besides, ckb contracts is written with `no_std`, remember to use features with `no_std`.
    
## Build contracts

```sh
capsule build
```

## Run tests

To run tests with a proof, you need to provide the path of the proof file to the test *./tests/src/tests.rs*, using the constant `PROOF_FILE`.

Then the following command.

```sh
capsule test
```
