use math::PairingEngine;
use math::{FromBytes, ToBytes};
use scheme::groth16::{
    prepare_verifying_key, verify_proof, PreparedVerifyingKey, Proof, VerifyingKey,
};

use crate::Vec;

pub fn groth16_verify<E: PairingEngine>(bytes: &[u8]) -> bool {
    let verify_groth16_proof = Groth16Proof::<E>::from_bytes(&bytes);

    if verify_groth16_proof.is_err() {
        return false;
    }
    let (pvk, proof, public_inputs) = verify_groth16_proof.unwrap().destruct();

    verify_proof(&pvk, &proof, &public_inputs).unwrap_or(false)
}

pub struct Groth16Proof<E: PairingEngine> {
    pvk: PreparedVerifyingKey<E>,
    proof: Proof<E>,
    public_inputs: Vec<E::Fr>,
}

impl<E: PairingEngine> Groth16Proof<E> {
    pub fn new(pvk: PreparedVerifyingKey<E>, proof: Proof<E>, public_inputs: Vec<E::Fr>) -> Self {
        Self {
            pvk,
            proof,
            public_inputs,
        }
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Groth16Proof<E>, ()> {
        let vk = VerifyingKey::<E>::read(&mut bytes).unwrap();
        let pvk = prepare_verifying_key(&vk);
        let proof = Proof::<E>::read(&mut bytes).unwrap();
        let public_inputs_len = u64::read(&mut bytes).unwrap();
        let mut public_inputs = vec![];
        for _ in 0..public_inputs_len {
            let p = <E::Fr>::read(&mut bytes).unwrap();
            public_inputs.push(p);
        }

        Ok(Self {
            pvk,
            proof,
            public_inputs,
        })
    }

    pub fn to_bytes(&self, vk: &VerifyingKey<E>) -> Vec<u8> {
        let mut bytes = vec![];
        vk.write(&mut bytes).unwrap();
        self.proof.write(&mut bytes).unwrap();
        (self.public_inputs.len() as u64).write(&mut bytes).unwrap();
        for i in &self.public_inputs {
            i.write(&mut bytes).unwrap();
        }

        bytes
    }

    pub fn destruct(self) -> (PreparedVerifyingKey<E>, Proof<E>, Vec<E::Fr>) {
        (self.pvk, self.proof, self.public_inputs)
    }
}
