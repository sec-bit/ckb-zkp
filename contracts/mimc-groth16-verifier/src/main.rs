#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

use alloc::vec::Vec;
use ckb_std::{
    ckb_constants::{CellField, Source},
    debug, default_alloc, entry,
    error::SysError,
    syscalls,
};
use ckb_types::{packed::*, prelude::*};
use ckb_zkp::verify_from_bytes;

entry!(main);
default_alloc!(4 * 1024, 512 * 1024, 64);

#[no_mangle]
pub fn main() -> i8 {
    let mut index = 0;
    // Proof file size:
    // MIMC groth16 bn256: 299 B
    // MIMC groth16 bls12_381: 427 B
    const DATA_BUF_SIZE: usize = 427;
    // Vk file size:
    // MIMC groth16 bn256: 590 B
    // MIMC groth16 bls12_381: 878 B
    // A Script struct with empty `args` will take up a constant size of 53 B (currently),
    // so buffer_size = 53 + Max(590, 878)
    const SCRIPT_BUF_SIZE: usize = 931;
    const OFFSET: usize = 0;

    debug!("Started");
    loop {
        let mut data_buffer = [0u8; DATA_BUF_SIZE];
        let mut script_buffer = [0u8; SCRIPT_BUF_SIZE];

        // read proof from output data
        let data_len_result =
            match syscalls::load_cell_data(&mut data_buffer, OFFSET, index, Source::GroupOutput) {
                Ok(size) => {
                    debug!("Index {} read data buffer size: {}", index, size);
                    size
                }
                Err(err) => {
                    if err == SysError::IndexOutOfBound {
                        debug!("All cells traversed, verification over");
                        break;
                    } else {
                        debug!("Read cell data (proof) error: {:?}", err);
                        return -2;
                    }
                }
            };
        // read type script
        let type_script_len_result = match syscalls::load_cell_by_field(
            &mut script_buffer,
            OFFSET,
            index,
            Source::GroupOutput,
            CellField::Type,
        ) {
            Ok(size) => {
                debug!("Index {} read arg buffer size: {}", index, size);
                size
            }
            Err(_err) => {
                debug!("Read type script (vk) error: {:?}", _err);
                return -2;
            }
        };
        // load args field from type script
        let args: Vec<u8> = {
            let type_script = Script::new_unchecked(script_buffer[..type_script_len_result].into());
            type_script.args().unpack()
        };
        if verify_from_bytes(&data_buffer[0..data_len_result], &args) {
            debug!(
                "Verification succeeded, vk size: {}, proof size: {}",
                args.len(),
                data_len_result
            );
        } else {
            debug!(
                "Verification failed, vk size: {}, proof size: {}",
                args.len(),
                data_len_result
            );
            return -1;
        }
        index += 1;
    }
    return 0;
}
