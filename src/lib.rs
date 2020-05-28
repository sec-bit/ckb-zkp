#![cfg_attr(not(feature = "std"), no_std)]

// re-export
pub use curve;
pub use math;
pub use scheme;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

pub mod gadget;

#[cfg(feature = "groth16")]
mod groth16;
#[cfg(feature = "groth16")]
pub use groth16::{groth16_verify, Groth16Proof};

#[cfg(feature = "bulletproofs")]
mod bulletproofs;
#[cfg(feature = "bulletproofs")]
pub use bulletproofs::{bulletproofs_verify, BulletproofsProof};

#[derive(Copy, Clone)]
pub enum Scheme {
    #[cfg(feature = "groth16")]
    Groth16,
    #[cfg(feature = "bulletproofs")]
    Bulletproofs,
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
pub enum Curve {
    #[cfg(feature = "bls12_381")]
    Bls12_381,
    #[cfg(feature = "bn_256")]
    Bn_256,
}

#[cfg(all(
    any(feature = "groth16", feature = "bulletproofs"),
    any(feature = "bn_256", feature = "bls12_381")
))]
macro_rules! handle_curve {
    ($func_name:ident, $c:expr, $bytes:expr) => {
        match $c {
            #[cfg(feature = "bls12_381")]
            Curve::Bls12_381 => $func_name::<curve::Bls12_381>($bytes),
            #[cfg(feature = "bn_256")]
            Curve::Bn_256 => $func_name::<curve::Bn_256>($bytes),
        }
    };
}

#[cfg(all(
    any(feature = "groth16", feature = "bulletproofs"),
    any(feature = "bn_256", feature = "bls12_381")
))]
pub fn verify(s: Scheme, c: Curve, bytes: &[u8]) -> bool {
    match s {
        #[cfg(feature = "groth16")]
        Scheme::Groth16 => handle_curve!(groth16_verify, c, bytes),
        #[cfg(feature = "bulletproofs")]
        Scheme::Bulletproofs => handle_curve!(bulletproofs_verify, c, bytes),
    }
}

#[cfg(all(
    any(feature = "groth16", feature = "bulletproofs"),
    any(feature = "bn_256", feature = "bls12_381")
))]
pub fn verify_from_int(si: u8, ci: u8, bytes: &[u8]) -> bool {
    let s = match si {
        #[cfg(feature = "groth16")]
        0u8 => Scheme::Groth16,
        #[cfg(feature = "bulletproofs")]
        1u8 => Scheme::Bulletproofs,
        #[cfg(feature = "groth16")]
        _ => Scheme::Groth16,
    };

    let c = match ci {
        #[cfg(feature = "bls12_381")]
        0u8 => Curve::Bls12_381,
        #[cfg(feature = "bn_256")]
        1u8 => Curve::Bn_256,
        #[cfg(feature = "bn_256")]
        _ => Curve::Bn_256,
    };

    verify(s, c, bytes)
}
