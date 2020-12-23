#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(not(feature = "std"), feature = "gadgets"))]
#[macro_use]
extern crate alloc;

#[cfg(all(not(feature = "std"), feature = "gadgets"))]
use alloc::{string::String, vec::Vec};

#[cfg(all(feature = "std", feature = "gadgets"))]
use std::{string::String, vec::Vec};

/// gadgets can used in circuits.
#[cfg(feature = "gadgets")]
pub mod gadgets;

/// re-export math.
pub use math;

/// re-export scheme standard r1cs.
pub use scheme::r1cs;

/// re-export groth16.
#[cfg(feature = "groth16")]
pub use scheme::groth16;

/// re-export bulletproofs.
#[cfg(feature = "bulletproofs")]
pub use scheme::bulletproofs;

/// re-export marlin.
#[cfg(feature = "marlin")]
pub use scheme::marlin;

/// re-export clinkv2.
#[cfg(feature = "clinkv2")]
pub use scheme::clinkv2;

/// re-export spartan.
#[cfg(feature = "spartan")]
pub use scheme::spartan;

/// re-export hyrax.
#[cfg(feature = "hyrax")]
pub use scheme::hyrax;

/// re-export libra.
#[cfg(feature = "libra")]
pub use scheme::libra;

/// re-export bn_256.
#[cfg(feature = "bn_256")]
pub use curve::bn_256;

/// re-export bls12_381.
#[cfg(feature = "bls12_381")]
pub use curve::bls12_381;

/// re-export jubjub.
#[cfg(feature = "jubjub")]
pub use curve::jubjub;

/// re-export baby_jubjub.
#[cfg(feature = "baby_jubjub")]
pub use curve::baby_jubjub;
