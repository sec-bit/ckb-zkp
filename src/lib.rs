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
#[derive(Debug)]
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

    pub fn to_str<'a>(&self) -> &'a str {
        match self {
            Scheme::Groth16 => "groth16",
            Scheme::Bulletproofs => "bulletproofs",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "groth16" => Ok(Scheme::Groth16),
            "bulletproofs" => Ok(Scheme::Bulletproofs),
            _ => Err(()),
        }
    }
}

/// Supported pairing curves for zkp use.
/// Now include: Bls12_381, Bn_256.
#[allow(non_camel_case_types)]
#[derive(Debug)]
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

    pub fn to_str<'a>(&self) -> &'a str {
        match self {
            Curve::Bls12_381 => "bls12_381",
            Curve::Bn_256 => "bn_256",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "bls12_381" => Ok(Curve::Bls12_381),
            "bn_256" => Ok(Curve::Bn_256),
            _ => Err(()),
        }
    }
}

/// Supported use-friendly gadgets for zkp.
/// Now include: MiMC hash proof.
#[derive(Debug)]
pub enum Gadget {
    /// pre-image content (plaintext).
    MiMC(Vec<u8>),
    /// secret num, public compared num. secret > public.
    GreaterThan(u64, u64),
    /// secret num, public compared num. secret < public.
    LessThan(u64, u64),
    /// secret num, public compared nums. public_a < secret < public_b.
    Between(u64, u64, u64),
}

impl Gadget {
    pub fn to_byte(self) -> Vec<u8> {
        let mut bytes = vec![];
        match self {
            Gadget::MiMC(mut p) => {
                bytes.extend_from_slice(&0u16.to_le_bytes());
                bytes.extend_from_slice(&(p.len() as u64).to_le_bytes());
                bytes.append(&mut p);
            }
            _ => {}
        }
        bytes
    }

    pub fn from_byte(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < 2 {
            return Err(());
        }

        let mut g_len = [0u8; 2];
        let (g, bytes) = bytes.split_at(2);
        g_len.copy_from_slice(g);

        match u16::from_le_bytes(g_len) {
            0u16 => {
                let (len_bytes, bytes) = bytes.split_at(8);
                let mut tmp_len = [0u8; 8];
                tmp_len.copy_from_slice(len_bytes);
                let bytes_len = u64::from_le_bytes(tmp_len) as usize;
                if bytes.len() < bytes_len {
                    return Err(());
                }
                Ok(Gadget::MiMC(bytes[..bytes_len].to_vec()))
            }
            _ => Err(()),
        }
    }
}

/// GadgetProof enum type. It include gadget's parameters and SchemeProof type.
#[derive(Debug)]
pub enum GadgetProof {
    /// MiMC hash value, and proof.
    MiMC(Vec<u8>, Vec<u8>),
    /// compared num, and proof.
    GreaterThan(u64, Vec<u8>),
    /// compared num, and proof.
    LessThan(u64, Vec<u8>),
    /// compared left num and right num, and proof.
    Between(u64, u64, Vec<u8>),
}

impl GadgetProof {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![];
        match self {
            GadgetProof::MiMC(mut e, mut s) => {
                bytes.extend_from_slice(&0u16.to_le_bytes());
                bytes.append(&mut (e.len() as u32).to_le_bytes().to_vec());
                bytes.append(&mut e);
                bytes.append(&mut s);
            } // ADD OTHER GADGET
            GadgetProof::GreaterThan(n, mut p) => {
                bytes.extend_from_slice(&1u16.to_le_bytes());
                bytes.extend_from_slice(&n.to_le_bytes());
                bytes.append(&mut p);
            }
            GadgetProof::LessThan(n, mut p) => {
                bytes.extend_from_slice(&2u16.to_le_bytes());
                bytes.extend_from_slice(&n.to_le_bytes());
                bytes.append(&mut p);
            }
            GadgetProof::Between(l, r, mut p) => {
                bytes.extend_from_slice(&3u16.to_le_bytes());
                bytes.extend_from_slice(&l.to_le_bytes());
                bytes.extend_from_slice(&r.to_le_bytes());
                bytes.append(&mut p);
            }
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < 2 {
            return Err(());
        }

        let mut g_len = [0u8; 2];
        let (g, bytes) = bytes.split_at(2);
        g_len.copy_from_slice(g);

        match u16::from_le_bytes(g_len) {
            0u16 => {
                let mut h_len_bytes = [0u8; 4];
                let (h_len_b, bytes) = bytes.split_at(4);
                h_len_bytes.copy_from_slice(h_len_b);
                let h_len = u32::from_le_bytes(h_len_bytes);
                let (h, p) = bytes.split_at(h_len as usize);
                Ok(GadgetProof::MiMC(h.to_vec(), p.to_vec()))
            }
            1u16 => {
                let mut n_bytes = [0u8; 8];
                let (n_b, bytes) = bytes.split_at(8);
                n_bytes.copy_from_slice(n_b);
                let n = u64::from_le_bytes(n_bytes);
                Ok(GadgetProof::GreaterThan(n, bytes.to_vec()))
            }
            2u16 => {
                let mut n_bytes = [0u8; 8];
                let (n_b, bytes) = bytes.split_at(8);
                n_bytes.copy_from_slice(n_b);
                let n = u64::from_le_bytes(n_bytes);
                Ok(GadgetProof::LessThan(n, bytes.to_vec()))
            }
            3u16 => {
                let mut l_bytes = [0u8; 8];
                let (l_b, bytes) = bytes.split_at(8);
                l_bytes.copy_from_slice(l_b);
                let l = u64::from_le_bytes(l_bytes);
                let mut r_bytes = [0u8; 8];
                let (r_b, bytes) = bytes.split_at(8);
                r_bytes.copy_from_slice(r_b);
                let r = u64::from_le_bytes(r_bytes);
                Ok(GadgetProof::Between(l, r, bytes.to_vec()))
            }
            _ => Err(()),
        }
    }
}

/// Proof struct type. It include used gadget, scheme, curve enum, and GadgetProof type.
#[derive(Debug)]
pub struct Proof {
    pub s: Scheme,
    pub c: Curve,
    pub p: GadgetProof,
}

impl Proof {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.push(self.s.to_byte());
        bytes.push(self.c.to_byte());
        bytes.append(&mut self.p.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < 2 {
            return Err(());
        }

        let s = Scheme::from_byte(bytes[0])?;
        let c = Curve::from_byte(bytes[1])?;
        let p = GadgetProof::from_bytes(&bytes[2..])?;

        Ok(Self { s, c, p })
    }

    pub fn to_hex() {
        todo!();
    }

    pub fn from_hex() {
        todo!();
    }
}

macro_rules! handle_curve_prove {
    ($func_name:ident, $rng_name:ident, $c:expr, $g:expr, $pk:expr, $rng:expr) => {
        match $c {
            Curve::Bls12_381 => {
                #[cfg(not(feature = "bls12_381"))]
                panic!("Cound not found bls12_381 feature");

                #[cfg(feature = "bls12_381")]
                $func_name::<curve::Bls12_381, $rng_name>($g, $pk, $rng)
            }
            Curve::Bn_256 => {
                #[cfg(not(feature = "bn_256"))]
                panic!("Cound not found bn_256 feature");

                #[cfg(feature = "bn_256")]
                $func_name::<curve::Bn_256, $rng_name>($g, $pk, $rng)
            }
        }
    };
}

macro_rules! handle_gadget_prove {
    ($gadget:ident, $rng_name:ident, $s:expr, $c:expr, $g:expr, $pk:expr, $rng:expr) => {
        match $s {
            Scheme::Groth16 => {
                #[cfg(not(feature = "groth16"))]
                panic!("Cound not found groth16 feature");

                #[cfg(feature = "groth16")]
                {
                    use $gadget::groth16_prove;
                    handle_curve_prove!(groth16_prove, $rng_name, $c, $g, $pk, $rng)
                }
            }
            Scheme::Bulletproofs => {
                #[cfg(not(feature = "bulletproofs"))]
                panic!("Cound not found bulletproofs feature");

                #[cfg(feature = "bulletproofs")]
                {
                    use $gadget::bulletproofs_prove;
                    handle_curve_prove!(bulletproofs_prove, $rng_name, $c, $g, $pk, $rng)
                }
            }
        }
    };
}

macro_rules! handle_curve_verify {
    ($func_name:ident, $c:expr, $gp:expr, $vk:expr, $pp:expr) => {
        match $c {
            Curve::Bls12_381 => {
                #[cfg(not(feature = "bls12_381"))]
                panic!("Cound not found bls12_381 feature");

                #[cfg(feature = "bls12_381")]
                $func_name::<curve::Bls12_381>($gp, $vk, $pp).unwrap_or(false)
            }
            Curve::Bn_256 => {
                #[cfg(not(feature = "bn_256"))]
                panic!("Cound not found bn_256 feature");

                #[cfg(feature = "bn_256")]
                $func_name::<curve::Bn_256>($gp, $vk, $pp).unwrap_or(false)
            }
        }
    };
}

macro_rules! handle_gadget_verify {
    ($gadget:ident, $s:expr, $c:expr, $gp:expr, $vk:expr, $pp:expr) => {
        match $s {
            Scheme::Groth16 => {
                #[cfg(not(feature = "groth16"))]
                panic!("Cound not found groth16 feature");

                #[cfg(feature = "groth16")]
                {
                    use $gadget::groth16_verify;
                    handle_curve_verify!(groth16_verify, $c, $gp, $vk, $pp)
                }
            }
            Scheme::Bulletproofs => {
                #[cfg(not(feature = "bulletproofs"))]
                panic!("Cound not found bulletproofs feature");

                #[cfg(feature = "bulletproofs")]
                {
                    use $gadget::bulletproofs_verify;
                    handle_curve_verify!(bulletproofs_verify, $c, $gp, $vk, $pp)
                }
            }
        }
    };
}

use gadget::mimc;
use gadget::rangeproof;

/// main prove functions.
/// it will return Proof struct.
pub fn prove<R: rand::Rng>(g: Gadget, s: Scheme, c: Curve, pk: &[u8], rng: R) -> Result<Proof, ()> {
    let p = match g {
        Gadget::MiMC(..) => handle_gadget_prove!(mimc, R, s, c, &g, pk, rng)?,
        Gadget::GreaterThan(..) | Gadget::LessThan(..) | Gadget::Between(..) => {
            handle_gadget_prove!(rangeproof, R, s, c, &g, pk, rng)?
        }
    };

    Ok(Proof { s, c, p })
}

/// main prove functions, use Bytes.
/// it will return Proof's Bytes.
pub fn prove_to_bytes<R: rand::Rng>(
    g: Gadget,
    s: Scheme,
    c: Curve,
    pk: &[u8],
    rng: R,
) -> Result<Vec<u8>, ()> {
    prove(g, s, c, pk, rng).map(|p| p.to_bytes())
}

/// main verify functions.
/// it will return bool.
pub fn verify(proof: Proof, vk: &[u8]) -> bool {
    match proof.p {
        GadgetProof::MiMC(..) => handle_gadget_verify!(mimc, proof.s, proof.c, proof.p, vk, false),
        GadgetProof::GreaterThan(..) | GadgetProof::LessThan(..) | GadgetProof::Between(..) => {
            handle_gadget_verify!(rangeproof, proof.s, proof.c, proof.p, vk, false)
        }
    }
}

/// main verify functions, use Bytes.
/// it will return bool.
pub fn verify_from_bytes(bytes: &[u8], vk: &[u8]) -> bool {
    if let Ok(proof) = Proof::from_bytes(bytes) {
        return verify(proof, vk);
    }

    return false;
}

/// main verify functions, use Bytes.
/// it will return bool.
pub fn verify_with_prepare(bytes: &[u8], pvk: &[u8]) -> bool {
    if let Ok(proof) = Proof::from_bytes(bytes) {
        match proof.p {
            GadgetProof::MiMC(..) => {
                handle_gadget_verify!(mimc, proof.s, proof.c, proof.p, pvk, true)
            }
            _ => false,
        }
    } else {
        false
    }
}
