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

/// Supported zero-knowledge proof schemes.
/// Now include: Groth16, Bulletproofs.
#[derive(Copy, Clone)]
pub enum Scheme {
    Groth16,
    Bulletproofs,
}

impl Scheme {
    pub fn to_byte(&self) -> u8 {
        match self {
            Scheme::Groth16 => 0,
            Scheme::Bulletproofs => 1,
        }
    }

    pub fn from_byte(bytes: u8) -> Result<Self, ()> {
        match bytes {
            0u8 => Ok(Scheme::Groth16),
            1u8 => Ok(Scheme::Bulletproofs),
            _ => Err(()),
        }
    }
}

/// Supported pairing curves for zkp use.
/// Now include: Bls12_381, Bn_256.
#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
pub enum Curve {
    Bls12_381,
    Bn_256,
}

impl Curve {
    pub fn to_byte(&self) -> u8 {
        match self {
            Curve::Bls12_381 => 0,
            Curve::Bn_256 => 1,
        }
    }

    pub fn from_byte(bytes: u8) -> Result<Self, ()> {
        match bytes {
            0u8 => Ok(Curve::Bls12_381),
            1u8 => Ok(Curve::Bn_256),
            _ => Err(()),
        }
    }
}

/// Supported use-friendly gadgets for zkp.
/// Now include: MiMC hash proof.
#[derive(Copy, Clone)]
pub enum Gadget {
    MiMC,
}

impl Gadget {
    pub fn to_byte(&self) -> u8 {
        match self {
            Gadget::MiMC => 0,
        }
    }

    pub fn from_byte(bytes: u8) -> Result<Self, ()> {
        match bytes {
            0u8 => Ok(Gadget::MiMC),
            _ => Err(()),
        }
    }
}

/// Proof struct type. It include used gadget, scheme, curve enum, and GadgetProof type.
pub struct Proof {
    pub g: Gadget,
    pub s: Scheme,
    pub c: Curve,
    pub p: GadgetProof,
}

impl Proof {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.push(self.g.to_byte());
        bytes.push(self.s.to_byte());
        bytes.push(self.c.to_byte());
        bytes.append(&mut self.p.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < 3 {
            return Err(());
        }

        let g = Gadget::from_byte(bytes[0])?;
        let s = Scheme::from_byte(bytes[1])?;
        let c = Curve::from_byte(bytes[2])?;
        let p = GadgetProof::from_bytes(&bytes[3..])?;

        Ok(Self { g, s, c, p })
    }

    pub fn to_hex() {
        todo!();
    }

    pub fn from_hex() {
        todo!();
    }
}

/// GadgetProof enum type. It include gadget's parameters and SchemeProof type.
pub enum GadgetProof {
    MiMC(Vec<u8>, Vec<u8>),
}

impl GadgetProof {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![];
        match self {
            GadgetProof::MiMC(mut e, mut s) => {
                bytes.push(0u8);
                bytes.append(&mut (e.len() as u32).to_le_bytes().to_vec());
                bytes.append(&mut e);
                bytes.append(&mut s);
            } // ADD OTHER GADGET
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < 5 {
            return Err(());
        }

        let (g, n_bytes) = bytes.split_at(1);
        let (e_len_bytes, es_bytes) = n_bytes.split_at(4);
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&e_len_bytes);
        let e_len = u32::from_le_bytes(len_bytes);
        let (e, s) = es_bytes.split_at(e_len as usize);

        match g {
            [0u8] => Ok(GadgetProof::MiMC(e.to_vec(), s.to_vec())),
            _ => Err(()),
        }
    }
}

macro_rules! handle_curve_prove {
    ($func_name:ident, $rng_name:ident, $c:expr, $bytes:expr, $rng:expr) => {
        match $c {
            Curve::Bls12_381 => {
                #[cfg(not(feature = "bls12_381"))]
                return Err(());

                #[cfg(feature = "bls12_381")]
                $func_name::<curve::Bls12_381, $rng_name>($bytes, $rng)
            }
            Curve::Bn_256 => {
                #[cfg(not(feature = "bn_256"))]
                return Err(());

                #[cfg(feature = "bn_256")]
                $func_name::<curve::Bn_256, $rng_name>($bytes, $rng)
            }
        }
    };
}

macro_rules! handle_gadget_prove {
    ($gadget:ident, $rng_name:ident, $s:expr, $c:expr, $bytes:expr, $rng:expr) => {
        match $s {
            Scheme::Groth16 => {
                #[cfg(not(feature = "groth16"))]
                return Err(());

                #[cfg(feature = "groth16")]
                {
                    use $gadget::groth16_prove;
                    handle_curve_prove!(groth16_prove, $rng_name, $c, $bytes, $rng)
                }
            }
            Scheme::Bulletproofs => {
                // TODO
                Err(())
            }
        }
    };
}

macro_rules! handle_curve_verify {
    ($func_name:ident, $c:expr, $bytes:expr) => {
        match $c {
            Curve::Bls12_381 => {
                #[cfg(not(feature = "bls12_381"))]
                return false;

                #[cfg(feature = "bls12_381")]
                $func_name::<curve::Bls12_381>($bytes).unwrap_or(false)
            }
            Curve::Bn_256 => {
                #[cfg(not(feature = "bn_256"))]
                return false;

                #[cfg(feature = "bn_256")]
                $func_name::<curve::Bn_256>($bytes).unwrap_or(false)
            }
        }
    };
}

macro_rules! handle_gadget_verify {
    ($gadget:ident, $s:expr, $c:expr, $gp:expr) => {
        match $s {
            Scheme::Groth16 => {
                #[cfg(not(feature = "groth16"))]
                return false;

                #[cfg(feature = "groth16")]
                {
                    use $gadget::groth16_verify;
                    handle_curve_verify!(groth16_verify, $c, $gp)
                }
            }
            Scheme::Bulletproofs => {
                // TODO
                false
            }
        }
    };
}

use gadget::mimc;

/// main prove functions.
/// it will return Proof struct.
pub fn prove<R: rand::Rng>(g: Gadget, s: Scheme, c: Curve, b: &[u8], rng: R) -> Result<Proof, ()> {
    let p = match g {
        Gadget::MiMC => handle_gadget_prove!(mimc, R, s, c, b, rng)?,
    };

    Ok(Proof { g, s, c, p })
}

/// main prove functions, use Bytes.
/// it will return Proof's Bytes.
pub fn prove_to_bytes<R: rand::Rng>(
    g: Gadget,
    s: Scheme,
    c: Curve,
    b: &[u8],
    rng: R,
) -> Result<Vec<u8>, ()> {
    prove(g, s, c, b, rng).map(|p| p.to_bytes())
}

/// main verify functions.
/// it will return bool.
pub fn verify(proof: Proof) -> bool {
    match proof.g {
        Gadget::MiMC => handle_gadget_verify!(mimc, proof.s, proof.c, proof.p),
    }
}

/// main verify functions, use Bytes.
/// it will return bool.
pub fn verify_from_bytes(bytes: &[u8]) -> bool {
    if let Ok(proof) = Proof::from_bytes(bytes) {
        return verify(proof);
    }

    return false;
}
