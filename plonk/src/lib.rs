//! An implementation of the [`PlonK`].
//!
//! [`PlonK`]: https://eprint.iacr.org/2019/953.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(clippy::op_ref, clippy::suspicious_op_assign_impl)]
#![cfg_attr(not(use_asm), forbid(unsafe_code))]
#![cfg_attr(use_asm, feature(llvm_asm))]
#![cfg_attr(use_asm, deny(unsafe_code))]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{
    borrow::Cow,
    collections::{BTreeMap as Map, BTreeSet as Set},
};

#[cfg(feature = "std")]
use std::{
    borrow::Cow,
    collections::{HashMap as Map, HashSet as Set},
};

mod data_structures;
use data_structures::*;

mod utils;
use utils::*;

mod composer;
mod protocol;

#[derive(Debug)]
pub enum Error {
    PolynomialDegreeTooLarge,
    AlreadyPreprocessed,
    MissingEvaluation(String),
    Other,
}
