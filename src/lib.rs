#![cfg_attr(not(feature = "std"), no_std)]

// re-export
pub use curve;
pub use math;
pub use scheme;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{string::String, vec::Vec};

/// gadgets can used in circuits.
pub mod gadgets;

/// circuits can learning who to use gadgets.
pub mod circuits;

/// Supported zero-knowledge proof schemes.
/// Now include: Groth16, Bulletproofs.
#[derive(Debug)]
pub enum Scheme {
    Groth16,
    Bulletproofs,
    Marlin,
}

impl Scheme {
    pub fn to_byte(&self) -> u8 {
        match self {
            Scheme::Groth16 => 0,
            Scheme::Bulletproofs => 1,
            Scheme::Marlin => 2,
        }
    }

    pub fn from_byte(bytes: u8) -> Result<Self, ()> {
        match bytes {
            0u8 => Ok(Scheme::Groth16),
            1u8 => Ok(Scheme::Bulletproofs),
            2u8 => Ok(Scheme::Marlin),
            _ => Err(()),
        }
    }

    pub fn to_str<'a>(&self) -> &'a str {
        match self {
            Scheme::Groth16 => "groth16",
            Scheme::Bulletproofs => "bulletproofs",
            Scheme::Marlin => "marlin",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "groth16" => Ok(Scheme::Groth16),
            "bulletproofs" => Ok(Scheme::Bulletproofs),
            "marlin" => Ok(Scheme::Marlin),
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

#[allow(unused_imports)] // for when no-default-features
use math::{FromBytes, PairingEngine, ToBytes};
use scheme::r1cs::ConstraintSynthesizer;

/// main prove functions.
/// it will return Proof bytes struct.
#[allow(unused_mut)] // for when no-default-features
#[allow(unused_variables)] // for when no-default-features
pub fn prove_to_bytes<E: PairingEngine, C: ConstraintSynthesizer<E::Fr>, R: rand::Rng>(
    s: Scheme,
    pk: &[u8],
    circuit: C,
    mut rng: R,
) -> Result<Vec<u8>, ()> {
    match s {
        #[cfg(feature = "groth16")]
        Scheme::Groth16 => {
            use scheme::groth16::{create_random_proof, Parameters};
            let params = Parameters::<E>::read(pk).map_err(|_| ())?;
            let proof = create_random_proof(circuit, &params, &mut rng).map_err(|_| ())?;

            let mut p_bytes = Vec::new();
            proof.write(&mut p_bytes).map_err(|_| ())?;
            Ok(p_bytes)
        }
        #[cfg(feature = "bulletproofs")]
        Scheme::Bulletproofs => {
            use scheme::bulletproofs::arithmetic_circuit::create_proof;
            let (generators, r1cs_circuit, proof, _assignment) =
                create_proof::<E, C, R>(circuit, &mut rng).map_err(|_| ())?;

            let mut p_bytes = Vec::new();
            generators.write(&mut p_bytes).map_err(|_| ())?;
            r1cs_circuit.write(&mut p_bytes).map_err(|_| ())?;
            proof.write(&mut p_bytes).map_err(|_| ())?;
            Ok(p_bytes)
        }
        #[cfg(feature = "marlin")]
        Scheme::Marlin => {
            use scheme::marlin::{prove, IndexProverKey};
            let ipk = IndexProverKey::<E>::read(pk).map_err(|_| ())?;
            let proof = prove(&ipk, circuit, &mut rng).map_err(|_| ())?;

            let mut p_bytes = Vec::new();
            proof.write(&mut p_bytes).map_err(|_| ())?;
            Ok(p_bytes)
        }
        #[cfg(any(
            not(feature = "groth16"),
            not(feature = "bulletproofs"),
            not(feature = "marlin")
        ))]
        _ => Err(()),
    }
}

/// main verify functions, use Bytes.
/// it will return bool.
#[allow(unused_mut)] // for when no-default-features
#[allow(unused_variables)] // for when no-default-features
pub fn verify_from_bytes<E: PairingEngine>(
    s: Scheme,
    vk_bytes: &[u8],
    mut proof_bytes: &[u8],
    mut publics_bytes: &[u8],
) -> Result<bool, ()> {
    match s {
        #[cfg(feature = "groth16")]
        Scheme::Groth16 => {
            use scheme::groth16::{prepare_verifying_key, verify_proof, Proof, VerifyingKey};
            let proof = Proof::<E>::read(proof_bytes).map_err(|_| ())?;
            let vk = VerifyingKey::<E>::read(vk_bytes).map_err(|_| ())?;
            let pvk = prepare_verifying_key(&vk);
            let publics_len = u32::read(&mut publics_bytes).map_err(|_| ())?;
            let mut publics = Vec::new();
            for _ in 0..publics_len {
                publics.push(E::Fr::read(publics_bytes).map_err(|_| ())?);
            }
            verify_proof(&pvk, &proof, &publics).map_err(|_| ())
        }
        #[cfg(feature = "bulletproofs")]
        Scheme::Bulletproofs => {
            use scheme::bulletproofs::arithmetic_circuit::{
                verify_proof, Generators, Proof, R1csCircuit,
            };
            let generators = Generators::<E>::read(&mut proof_bytes).map_err(|_| ())?;
            let r1cs_circuit = R1csCircuit::<E>::read(&mut proof_bytes).map_err(|_| ())?;
            let proof = Proof::<E>::read(&mut proof_bytes).map_err(|_| ())?;

            let publics_len = u32::read(&mut publics_bytes).map_err(|_| ())?;
            let mut publics = Vec::new();
            for _ in 0..publics_len {
                publics.push(E::Fr::read(&mut publics_bytes).map_err(|_| ())?);
            }

            Ok(verify_proof(&generators, &proof, &r1cs_circuit, &publics))
        }
        #[cfg(feature = "marlin")]
        Scheme::Marlin => {
            use scheme::marlin::{verify, IndexVerifierKey, Proof};

            let proof = Proof::<E>::read(proof_bytes).map_err(|_| ())?;
            let vk = IndexVerifierKey::<E>::read(vk_bytes).unwrap();

            let publics_len = u32::read(&mut publics_bytes).map_err(|_| ())?;
            let mut publics = Vec::new();
            for _ in 0..publics_len {
                publics.push(E::Fr::read(&mut publics_bytes).map_err(|_| ())?);
            }

            verify(&vk, &proof, &publics).map_err(|_| ())
        }
        #[cfg(any(
            not(feature = "groth16"),
            not(feature = "bulletproofs"),
            not(feature = "marlin")
        ))]
        _ => Err(()),
    }
}

/// main verify functions, use curve.
/// it will return bool.
#[allow(unused_variables)] // for when no-default-features
pub fn verify_from_bytes_with_curve(
    c: Curve,
    s: Scheme,
    vk: &[u8],
    proof: &[u8],
    public: &[u8],
) -> Result<bool, ()> {
    if public.len() == 0 {
        return Err(());
    }

    match c {
        #[cfg(feature = "bn_256")]
        Curve::Bn_256 => verify_from_bytes::<curve::Bn_256>(s, vk, proof, public),
        #[cfg(feature = "bls12_381")]
        Curve::Bls12_381 => verify_from_bytes::<curve::Bls12_381>(s, vk, proof, public),
        #[cfg(any(not(feature = "bn_256"), not(feature = "bls12_381"),))]
        _ => Err(()),
    }
}
