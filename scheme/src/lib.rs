//! An implementation of the [`Groth16`] zkSNARK.
//!
//! [`Groth16`]: https://eprint.iacr.org/2016/260.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(trivial_numeric_casts, private_in_public)]
#![deny(stable_features, /* unreachable_pub, */ non_shorthand_field_patterns)]
#![deny(unused_attributes, unused_imports, unused_mut)]
#![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
#![deny(unused_comparisons, bare_trait_objects, unused_must_use, const_err)]
#![forbid(unsafe_code)]
#![deny(trivial_casts)]

#[allow(unused_imports)]
#[macro_use]
extern crate derivative;

#[macro_use]
extern crate serde;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use alloc::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "std")]
#[allow(unused_imports)]
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};

#[allow(unused_imports)]
#[macro_use]
extern crate math;

extern crate curve;

pub mod r1cs;

#[cfg(feature = "groth16")]
pub mod groth16;

#[cfg(feature = "bulletproofs")]
pub mod bulletproofs;

#[cfg(feature = "asvc")]
pub mod asvc;

#[cfg(feature = "marlin")]
pub mod marlin;

#[cfg(feature = "clinkv2")]
pub mod clinkv2;

#[cfg(feature = "spartan")]
pub mod spartan;

#[cfg(feature = "hyrax")]
pub mod hyrax;

#[cfg(feature = "libra")]
pub mod libra;

