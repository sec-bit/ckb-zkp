#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

use alloc::vec::Vec;
use ckb_std::{ckb_constants, debug, default_alloc, entry, error::SysError, syscalls};
use ckb_types::{packed::*, prelude::*};
use zkp::verify_from_bytes;

#[no_mangle]
pub fn main() -> i8 {
    debug!("Started.");
    let mut index = 0;
    // Proof file size:
    // MIMC groth16 bn256: 299 B
    // MIMC groth16 bls12_381: 427 B
    const DATA_LEN: usize = 427;
    // Vk file size:
    // MIMC groth16 bn256: 590 B
    // MIMC groth16 bls12_381: 878 B
    const ARG_LEN: usize = 878;
    const OFFSET: usize = 0;

    loop {
        let mut data_buffer = [0u8; DATA_LEN];
        let mut arg_buffer = [0u8; ARG_LEN];
        // read proof from output data field.
        match syscalls::load_cell_data(
            &mut data_buffer,
            OFFSET,
            index,
            ckb_constants::Source::GroupOutput,
        ) {
            Ok(data_len_result) => {
                // read vk file from script arg field.
                match syscalls::load_cell_by_field(
                    &mut arg_buffer,
                    OFFSET,
                    index,
                    ckb_constants::Source::GroupOutput,
                    ckb_constants::CellField::Type,
                ) {
                    Ok(arg_len_result) => {
                        let type_script =
                            Script::new_unchecked(arg_buffer[..arg_len_result].into());
                        let args: Vec<u8> = type_script.args().unpack();

                        // execute the verification.
                        if verify_from_bytes(&data_buffer[0..data_len_result], &args) {
                            debug!("Verification succeeded.");
                        // return 0;
                        } else {
                            debug!("Verification failed.");
                            return -1;
                        }
                    }
                    Err(err) => {
                        debug!("{:?}", err);
                    }
                }
            }
            Err(err) => {
                debug!("{:?}", err);
                if err == SysError::IndexOutOfBound {
                    break;
                }
            }
        }
        index += 1;
    }
    return 0;
}

entry!(main);
default_alloc!(4 * 1024, 64 * 1024, 64);
