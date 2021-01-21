//! An implementation of the `CLINKv2`.
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused, future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(clippy::op_ref, clippy::suspicious_op_assign_impl)]
#![cfg_attr(not(use_asm), forbid(unsafe_code))]
#![cfg_attr(use_asm, feature(llvm_asm))]
#![cfg_attr(use_asm, deny(unsafe_code))]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[macro_use]
extern crate derivative;

#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{borrow::Cow, string::String, vec::Vec};

/// Clinkv2 unique r1cs.
pub mod r1cs;

/// Clinkv2-kzg10 scheme.
pub mod kzg10;

/// Clinkv2-ipa scheme.
pub mod ipa;
