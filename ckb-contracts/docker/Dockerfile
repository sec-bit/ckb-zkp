FROM nervos/ckb-riscv-gnu-toolchain:bionic-20191209

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly-2021-05-30 -y
ENV PATH=/root/.cargo/bin:$PATH
# Install RISC-V target
RUN rustup target add riscv64imac-unknown-none-elf
# Install CKB binary patcher
RUN cargo install --git https://github.com/xxuejie/ckb-binary-patcher.git --rev 930f0b468a8f426ebb759d9da735ebaa1e2f98ba
# Install CKB debugger
RUN git clone https://github.com/sunhuachuang/ckb-standalone-debugger.git \
    && cd ckb-standalone-debugger \
    && cd - \
    && cargo install --path ckb-standalone-debugger/bins \
    && rm -r ckb-standalone-debugger
