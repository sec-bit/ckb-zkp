//! An implementation of the [`Hyrax`].
//!
//! [`Hyrax`]: https://eprint.iacr.org/2017/1132.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused, future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(clippy::op_ref, clippy::suspicious_op_assign_impl)]
#![cfg_attr(not(use_asm), forbid(unsafe_code))]
#![cfg_attr(use_asm, feature(llvm_asm))]
#![cfg_attr(use_asm, deny(unsafe_code))]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

pub mod circuit;
pub mod commitment;
pub mod evaluate;
pub mod hyrax_proof;
pub mod params;
pub mod test;
pub mod zk_sumcheck_proof;
