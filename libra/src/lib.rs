//! An implementation of the [`Libra`].
//!
//! [`Libra`]: https://eprint.iacr.org/2019/317.pdf
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
pub mod libra_linear_gkr;
pub mod libra_zk_linear_gkr;
pub mod params;
pub mod sumcheck;
pub mod test;

use ark_poly::polynomial::univariate::DensePolynomial;
use ark_serialize::CanonicalSerialize;
use zkp_curve::Curve;

pub(crate) fn polynomial_to_bytes<G: Curve>(p: &DensePolynomial<G::Fr>) -> Vec<u8> {
    let mut bytes = vec![];
    p.serialize(&mut bytes).unwrap();
    bytes
}
