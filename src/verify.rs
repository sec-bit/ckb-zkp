use math::PairingEngine;
use scheme::groth16::verify_proof as groth16_verify_proof;
use scheme::groth16::{PreparedVerifyingKey, Proof, VerifyingKey};

use crate::Vec;

pub fn groth16_verify<E: PairingEngine>(bytes: Vec<u8>) -> bool {
    let proof_result = Groth16Proof::<E>::from_bytes(bytes);
    if proof_result.is_err() {
        return false;
    }

    let (pvk, proof, public_inputs) = proof_result.unwrap().destruct();

    groth16_verify_proof(&pvk, &proof, &public_inputs).unwrap_or(false)
}

pub fn bulletproofs_verify() -> bool {
    true
}

pub struct Groth16Proof<E: PairingEngine> {
    pvk: PreparedVerifyingKey<E>,
    proof: Proof<E>,
    vk: Vec<E::Fr>,
}

impl<E: PairingEngine> Groth16Proof<E> {
    fn from_bytes(bytes: Vec<u8>) -> Result<Groth16Proof<E>, ()> {
        Err(())
    }

    fn to_bytes(&self) -> Vec<u8> {
        vec![]
    }

    fn destruct(self) -> (PreparedVerifyingKey<E>, Proof<E>, Vec<E::Fr>) {
        (self.pvk, self.proof, self.vk)
    }
}
