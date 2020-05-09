#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{string::String, vec::Vec};

use curve::{Bls12_381, Bn_256};

mod prove;
mod verify;

pub mod gadget;

use verify::{bulletproofs_verify, groth16_verify};

pub use verify::Groth16Proof;

#[derive(Copy, Clone)]
pub enum Scheme {
    Groth16,
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
pub enum Curve {
    Bls12_381,
    Bn_256,
}

pub fn prove(s: Scheme, c: Curve, bytes: Vec<u8>) -> Vec<u8> {
    vec![]
}

pub fn verify(s: Scheme, c: Curve, bytes: Vec<u8>) -> bool {
    match s {
        Scheme::Groth16 => match c {
            Curve::Bls12_381 => groth16_verify::<Bls12_381>(bytes),
            Curve::Bn_256 => groth16_verify::<Bn_256>(bytes),
        },
    }
}

pub fn verify_from_int(si: u8, ci: u8, bytes: Vec<u8>) -> bool {
    let s = match si {
        0u8 => Scheme::Groth16,
        _ => Scheme::Groth16,
    };

    let c = match ci {
        0u8 => Curve::Bls12_381,
        1u8 => Curve::Bn_256,
        _ => Curve::Bls12_381,
    };

    verify(s, c, bytes)
}
