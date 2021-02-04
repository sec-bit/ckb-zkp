//! An implementation of the [`Marlin`].
//!
//! [`Marlin`]: https://eprint.iacr.org/2019/1047.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused, future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(clippy::op_ref, clippy::suspicious_op_assign_impl)]
#![cfg_attr(not(use_asm), forbid(unsafe_code))]
#![cfg_attr(use_asm, feature(llvm_asm))]
#![cfg_attr(use_asm, deny(unsafe_code))]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{collections::HashMap, vec::Vec};

#[cfg(feature = "std")]
use std::{collections::HashMap, vec::Vec};

mod constraint_system;
