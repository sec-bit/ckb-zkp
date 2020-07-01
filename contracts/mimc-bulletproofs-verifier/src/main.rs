#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

use ckb_std::{ckb_constants::Source, debug, default_alloc, entry, error::SysError, syscalls};
use ckb_zkp::verify_from_bytes;

entry!(main);
default_alloc!(4 * 1024, 512 * 1024, 64);

#[no_mangle]
pub fn main() -> i8 {
    let index = 0;
    // Proof file size:
    const DATA_BUF_SIZE: usize = 500 * 1024; // 500KB

    debug!("Started");
    loop {
        let mut data_buffer = [0u8; DATA_BUF_SIZE];

        //let offest: usize = 0;
        let mut data_len: usize = 0;

        loop {
            match syscalls::load_cell_data(
                &mut data_buffer[data_len..],
                data_len,
                index,
                Source::GroupOutput,
            ) {
                Ok(size) => {
                    debug!("Index {} read data buffer size: {}", index, size);
                    if size == 0 {
                        break;
                    }

                    data_len += size;
                    if data_len < DATA_BUF_SIZE {
                        continue;
                    }
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
        }

        if verify_from_bytes(&data_buffer[0..data_len], &[]) {
            debug!("Verification succeeded, proof size: {}", data_len);
            return 0;
        } else {
            debug!("Verification failed, proof size: {}", data_len);
            return -1;
        }

        //index += 1;
    }
}
