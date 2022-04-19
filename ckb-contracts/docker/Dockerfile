FROM nervos/ckb-riscv-gnu-toolchain@sha256:7b168b4b109a0f741078a71b7c4dddaf1d283a5244608f7851f5714fbad273ba

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly-2021-02-17 -y
ENV PATH=/root/.cargo/bin:$PATH
# Install RISC-V target
RUN rustup target add riscv64imac-unknown-none-elf
# Install CKB binary patcher
RUN cargo install --git https://github.com/xxuejie/ckb-binary-patcher.git --rev 930f0b468a8f426ebb759d9da735ebaa1e2f98ba
# Install CKB debugger
RUN git clone https://github.com/xxuejie/ckb-standalone-debugger.git \
    && cd ckb-standalone-debugger && git checkout 7c62220552fb90de0e6cd30cb6f95bf1bdcce18f && cd - \
    && cargo install --path ckb-standalone-debugger/bins \
    && rm -r ckb-standalone-debugger
