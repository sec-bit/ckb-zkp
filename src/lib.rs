#![cfg_attr(not(feature = "std"), no_std)]

// re-export
pub use curve;
pub use math;
pub use scheme;

use math::{FromBytes, PairingEngine, ToBytes};

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

pub mod gadget;

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

pub fn prove<E: PairingEngine>(g: Gadget, s: Scheme, c: Curve, b: &[u8]) -> Result<Proof<E>, ()> {
    match s {
        Scheme::Groth16 => {
            use scheme::groth16::create_random_proof;
            // TODO
            match g {
                Gadget::MiMC => {
                    use gadget::mimc::{constants, groth16_params, mimc_hash, MiMC};
                    let constants = constants::<E::Fr>();
                    let params = groth16_params::<E>(&constants).unwrap();

                    let (xl, xr, image) = mimc_hash(b, &constants);

                    let mc = MiMC {
                        xl: Some(xl),
                        xr: Some(xr),
                        constants: &constants,
                    };

                    let proof = create_random_proof(mc, &params, &mut rand::thread_rng()).unwrap();
                    Ok(Proof {
                        g,
                        s,
                        c,
                        p: GadgetProof::MiMC(image, SchemeProof::Groth16(proof, vec![image])),
                    })
                }
            }
        }
        Scheme::Bulletproofs => {
            // TODO
            Err(())
        }
    }
}

pub fn prove_to_bytes(g: Gadget, s: Scheme, c: Curve, b: &[u8]) -> Result<Vec<u8>, ()> {
    match c {
        Curve::Bls12_381 => {
            let p = prove::<curve::Bls12_381>(g, s, c, b)?;
            Ok(p.to_bytes())
        }
        Curve::Bn_256 => {
            let p = prove::<curve::Bn_256>(g, s, c, b)?;
            Ok(p.to_bytes())
        }
    }
}

pub fn verify<E: PairingEngine>(proof: &Proof<E>) -> bool {
    match proof.s {
        Scheme::Groth16 => {
            use scheme::groth16::{prepare_verifying_key, verify_proof};
            match &proof.p {
                GadgetProof::MiMC(_, p) => match p {
                    SchemeProof::Groth16(proof, public_inputs) => {
                        use gadget::mimc::{constants, groth16_params};
                        let constants = constants::<E::Fr>();
                        let params = groth16_params::<E>(&constants).unwrap();
                        let pvk = prepare_verifying_key(&params.vk);
                        verify_proof(&pvk, &proof, &public_inputs).unwrap_or(false)
                    }
                },
            }
        }
        Scheme::Bulletproofs => {
            // TODO
            false
        }
    }
}

pub fn verify_from_bytes(bytes: &[u8]) -> bool {
    if bytes.len() < 3 {
        return false;
    }

    let c = Curve::from_byte(bytes[2]);
    if c.is_err() {
        return false;
    }

    match c.unwrap() {
        Curve::Bls12_381 => {
            let proof = Proof::<curve::Bls12_381>::from_bytes(bytes);
            if proof.is_err() {
                return false;
            }
            verify(&proof.unwrap())
        }
        Curve::Bn_256 => {
            let proof = Proof::<curve::Bn_256>::from_bytes(bytes);
            if proof.is_err() {
                return false;
            }
            verify(&proof.unwrap())
        }
    }
}

pub struct Proof<E: PairingEngine> {
    pub g: Gadget,
    pub s: Scheme,
    pub c: Curve,
    pub p: GadgetProof<E>,
}

impl<E: PairingEngine> Proof<E> {
    pub fn to_bytes(&self) -> Vec<u8> {
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
        let p = GadgetProof::<E>::from_bytes(&bytes[3..])?;

        Ok(Self { g, s, c, p })
    }
}

pub enum GadgetProof<E: PairingEngine> {
    MiMC(E::Fr, SchemeProof<E>),
}

impl<E: PairingEngine> GadgetProof<E> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        match self {
            GadgetProof::MiMC(e, s) => {
                bytes.push(0u8);
                e.write(&mut bytes).unwrap();
                bytes.append(&mut s.to_bytes());
            } // ADD OTHER GADGET
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < 1 {
            return Err(());
        }

        match bytes.split_at(1) {
            ([0u8], mut bytes) => {
                let e = E::Fr::read(&mut bytes).map_err(|_| ())?;
                let f = SchemeProof::from_bytes(bytes)?;
                Ok(GadgetProof::MiMC(e, f))
            }
            _ => Err(()),
        }
    }
}

use scheme::groth16::Proof as Groth16Proof;

pub enum SchemeProof<E: PairingEngine> {
    Groth16(Groth16Proof<E>, Vec<E::Fr>),
}

impl<E: PairingEngine> SchemeProof<E> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        match self {
            SchemeProof::Groth16(p, i) => {
                bytes.push(0u8);
                p.write(&mut bytes).unwrap();
                (i.len() as u64).write(&mut bytes).unwrap();
                for f in i {
                    f.write(&mut bytes).unwrap();
                }
            }
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < 1 {
            return Err(());
        }
        match bytes.split_at(1) {
            ([0u8], mut bytes) => {
                let p = Groth16Proof::<E>::read(&mut bytes).map_err(|_| ())?;
                let public_inputs_len = u64::read(&mut bytes).map_err(|_| ())?;
                let mut i = vec![];
                for _ in 0..public_inputs_len {
                    let f = <E::Fr>::read(&mut bytes).map_err(|_| ())?;
                    i.push(f);
                }

                Ok(SchemeProof::Groth16(p, i))
            }
            _ => Err(()),
        }
    }
}
