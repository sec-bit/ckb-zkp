use math::PairingEngine;
use math::{FromBytes, ToBytes};
use scheme::groth16::verify_proof as groth16_verify_proof;
use scheme::groth16::{prepare_verifying_key, PreparedVerifyingKey, Proof, VerifyingKey};

use crate::Vec;

pub fn groth16_verify<E: PairingEngine>(bytes: Vec<u8>) -> bool {
    let proof_result = Groth16Proof::<E>::from_all_bytes(&bytes);
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
    pub fn new(pvk: PreparedVerifyingKey<E>, proof: Proof<E>, vk: Vec<E::Fr>) -> Self {
        Self { pvk, proof, vk }
    }

    pub fn from_all_bytes(mut bytes: &[u8]) -> Result<Groth16Proof<E>, ()> {
        let pvk = PreparedVerifyingKey::<E>::read(&mut bytes).unwrap();
        let proof = Proof::<E>::read(&mut bytes).unwrap();
        let vk_len = u64::read(&mut bytes).unwrap();
        let mut vk = vec![];
        for _ in 0..vk_len {
            let v = <E::Fr>::read(&mut bytes).unwrap();
            vk.push(v);
        }

        Ok(Self { pvk, proof, vk })
    }

    pub fn to_all_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        self.pvk.write(&mut bytes).unwrap();
        self.proof.write(&mut bytes).unwrap();
        (self.vk.len() as u64).write(&mut bytes).unwrap();
        for i in &self.vk {
            i.write(&mut bytes).unwrap();
        }

        bytes
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Groth16Proof<E>, ()> {
        let vk = VerifyingKey::<E>::read(&mut bytes).unwrap();
        let pvk = prepare_verifying_key(&vk);
        let proof = Proof::<E>::read(&mut bytes).unwrap();
        let vk_len = u64::read(&mut bytes).unwrap();
        let mut vk = vec![];
        for _ in 0..vk_len {
            let v = <E::Fr>::read(&mut bytes).unwrap();
            vk.push(v);
        }

        Ok(Self { pvk, proof, vk })
    }

    pub fn to_bytes(&self, vk: &VerifyingKey<E>) -> Vec<u8> {
        let mut bytes = vec![];
        vk.write(&mut bytes).unwrap();
        self.proof.write(&mut bytes).unwrap();
        (self.vk.len() as u64).write(&mut bytes).unwrap();
        for i in &self.vk {
            i.write(&mut bytes).unwrap();
        }

        bytes
    }

    pub fn destruct(self) -> (PreparedVerifyingKey<E>, Proof<E>, Vec<E::Fr>) {
        (self.pvk, self.proof, self.vk)
    }
}
