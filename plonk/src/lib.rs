//! An implementation of the [`PlonK`].
//!
//! [`PlonK`]: https://eprint.iacr.org/2019/953.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused, future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(clippy::op_ref, clippy::suspicious_op_assign_impl)]
#![cfg_attr(not(use_asm), forbid(unsafe_code))]
#![cfg_attr(use_asm, feature(llvm_asm))]
#![cfg_attr(use_asm, deny(unsafe_code))]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap as Map, vec::Vec};

#[cfg(feature = "std")]
use std::{collections::HashMap as Map, vec::Vec};

pub mod composer;
