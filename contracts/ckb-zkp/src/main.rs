#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

use ckb_std::{ckb_constants, debug, default_alloc, entry, syscalls, error::SysError};
use zkp::verify_from_int;

#[no_mangle]
pub fn main() -> i8 {
    let mut index = 0;
    const LEN: usize = 889; // MIMC test size
    let offset = 0;

    loop {
        let mut buffer = [0u8; LEN];
        match syscalls::load_cell_data(
            &mut buffer,
            offset,
            index,
            ckb_constants::Source::GroupOutput,
        ) {
            Ok(_) => {
                debug!("idx: {}, data length: {}", index, buffer.len());
                // debug!("{:?}", buffer);
                if verify_from_int(0, 1, &buffer) {
                    debug!("Verification succeeded.");
                // return 0;
                } else {
                    debug!("Verification failed.");
                    return -1;
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
default_alloc!(256 * 1024, 16);
