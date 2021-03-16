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
use alloc::collections::BTreeMap as Map;

#[cfg(feature = "std")]
use std::collections::HashMap as Map;

use protocol::Error as PError;

mod data_structures;

mod composer;
mod protocol;

mod rng;
mod utils;

mod plonk;
pub use plonk::Plonk;

#[derive(Debug)]
pub enum Error<E> {
    PolynomialDegreeTooLarge,
    CircuitTooLarge,
    AlreadyPreprocessed,
    MissingEvaluation(String),
    PolynomialCommitmentError(E),
    PolynomialProtocolError(PError),
    Other,
}

impl<E> From<PError> for Error<E> {
    fn from(err: PError) -> Self {
        Error::PolynomialProtocolError(err)
    }
}

impl<E> Error<E> {
    pub fn from_pc_err(err: E) -> Self {
        Error::PolynomialCommitmentError(err)
    }
}
