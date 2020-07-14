//! An implementation of the [`Groth16`] zkSNARK.
//!
//! [`Groth16`]: https://eprint.iacr.org/2016/260.pdf
//! [`Bulletproofs`]: https://eprint.iacr.org/2017/1066.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_import_braces, unused_qualifications, trivial_casts)]
#![deny(trivial_numeric_casts, private_in_public, variant_size_differences)]
#![deny(stable_features, unreachable_pub, non_shorthand_field_patterns)]
#![deny(unused_attributes, unused_imports, unused_mut)]
#![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
#![deny(unused_comparisons, bare_trait_objects, unused_must_use, const_err)]
#![forbid(unsafe_code)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(all(
    not(feature = "std"),
    any(feature = "groth16", feature = "bulletproofs")
))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::{string::String, vec::Vec};

#[cfg(feature = "groth16")]
#[macro_use]
extern crate math;

extern crate curve;

pub mod r1cs;

#[cfg(feature = "groth16")]
pub mod groth16;

#[cfg(feature = "bulletproofs")]
pub mod bulletproofs;
