//! An implementation of the [`Spartan`].
//!
//! [`Spartan`]: https://eprint.iacr.org/2019/550.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused, future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(clippy::op_ref, clippy::suspicious_op_assign_impl)]
#![cfg_attr(not(use_asm), forbid(unsafe_code))]
#![cfg_attr(use_asm, feature(llvm_asm))]
#![cfg_attr(use_asm, deny(unsafe_code))]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{collections::BTreeMap, string::String, vec::Vec};

pub mod commitments;
pub mod data_structure;
pub mod inner_product;
pub mod polynomial;
pub mod prover;
pub mod r1cs;
pub mod setup;
pub mod spark;
pub mod verify;

pub mod snark {
    use ark_serialize::*;
    use rand::Rng;
    use zkp_curve::Curve;
    use zkp_r1cs::{ConstraintSynthesizer, SynthesisError};

    use super::data_structure::{EncodeCommit, EncodeMemory, SnarkParameters};
    use super::r1cs::R1CSInstance;

    pub type Proof<G> = super::data_structure::SNARKProof<G>;

    #[derive(CanonicalSerialize, CanonicalDeserialize)]
    pub struct Parameters<G: Curve> {
        pub params: SnarkParameters<G>,
        pub r1cs: R1CSInstance<G>,
        pub encode: EncodeMemory<G>,
        pub encode_comm: EncodeCommit<G>,
    }

    #[derive(CanonicalSerialize, CanonicalDeserialize)]
    pub struct ProveKey<G: Curve> {
        pub params: SnarkParameters<G>,
        pub r1cs: R1CSInstance<G>,
        pub encode: EncodeMemory<G>,
        pub encode_comm: EncodeCommit<G>,
    }

    #[derive(CanonicalSerialize, CanonicalDeserialize)]
    pub struct VerifyKey<G: Curve> {
        pub params: SnarkParameters<G>,
        pub r1cs: R1CSInstance<G>,
        pub encode_comm: EncodeCommit<G>,
    }

    impl<G: Curve> Parameters<G> {
        pub fn keypair(self) -> (ProveKey<G>, VerifyKey<G>) {
            (
                ProveKey {
                    params: self.params.clone(),
                    r1cs: self.r1cs.clone(),
                    encode: self.encode,
                    encode_comm: self.encode_comm.clone(),
                },
                VerifyKey {
                    params: self.params,
                    r1cs: self.r1cs,
                    encode_comm: self.encode_comm,
                },
            )
        }
    }

    pub fn generate_random_parameters<G: Curve, C: ConstraintSynthesizer<G::Fr>, R: Rng>(
        c: C,
        rng: &mut R,
    ) -> Result<Parameters<G>, SynthesisError> {
        let r1cs = super::r1cs::generate_r1cs::<G, C>(c)?;

        let params = super::setup::generate_setup_snark_parameters::<G, R>(
            rng,
            r1cs.num_aux,
            r1cs.num_inputs,
            r1cs.num_constraints,
        )?;

        let (encode, encode_comm) = super::spark::encode::<G, R>(&params, &r1cs, rng)?;

        Ok(Parameters {
            params,
            r1cs,
            encode,
            encode_comm,
        })
    }

    pub fn create_random_proof<G: Curve, C: ConstraintSynthesizer<G::Fr>, R: Rng>(
        pk: &ProveKey<G>,
        c: C,
        r1cs_hash: G::Fr, 
        params_hash: G::Fr, 
        encode_hash: G::Fr,
        rng: &mut R,
    ) -> Result<Proof<G>, SynthesisError> {
        super::prover::create_snark_proof(&pk.params, &pk.r1cs, c, &pk.encode, &pk.encode_comm,r1cs_hash, params_hash, encode_hash, rng)
    }

    pub fn verify_proof<G: Curve>(
        vk: &VerifyKey<G>,
        proof: &Proof<G>,
        publics: &[G::Fr],
        r1cs_hash: G::Fr, 
        params_hash: G::Fr, 
        encode_hash: G::Fr,
    ) -> Result<bool, SynthesisError> {
        super::verify::verify_snark_proof::<G>(
            &vk.params,
            &vk.r1cs,
            publics,
            proof,
            &vk.encode_comm,
            r1cs_hash, 
            params_hash, 
            encode_hash,
        )
    }

}

pub mod nizk {
    use ark_serialize::*;
    use rand::Rng;
    use zkp_curve::Curve;
    use zkp_r1cs::{ConstraintSynthesizer, SynthesisError};

    use super::data_structure::NizkParameters;
    use super::r1cs::R1CSInstance;

    pub type Proof<G> = super::data_structure::NIZKProof<G>;

    #[derive(CanonicalSerialize, CanonicalDeserialize)]
    pub struct Parameters<G: Curve> {
        pub params: NizkParameters<G>,
        pub r1cs: R1CSInstance<G>,
    }

    #[derive(CanonicalSerialize, CanonicalDeserialize)]
    pub struct ProveKey<G: Curve> {
        pub params: NizkParameters<G>,
        pub r1cs: R1CSInstance<G>,
    }

    #[derive(CanonicalSerialize, CanonicalDeserialize)]
    pub struct VerifyKey<G: Curve> {
        pub params: NizkParameters<G>,
        pub r1cs: R1CSInstance<G>,
    }

    impl<G: Curve> Parameters<G> {
        pub fn keypair(self) -> (ProveKey<G>, VerifyKey<G>) {
            (
                ProveKey {
                    params: self.params.clone(),
                    r1cs: self.r1cs.clone(),
                },
                VerifyKey {
                    params: self.params,
                    r1cs: self.r1cs,
                },
            )
        }
    }

    pub fn generate_random_parameters<G: Curve, C: ConstraintSynthesizer<G::Fr>, R: Rng>(
        c: C,
        rng: &mut R,
    ) -> Result<Parameters<G>, SynthesisError> {
        let r1cs = super::r1cs::generate_r1cs::<G, C>(c)?;

        let params = super::setup::generate_setup_nizk_parameters::<G, R>(
            rng,
            r1cs.num_aux,
            r1cs.num_inputs,
        )?;

        Ok(Parameters { params, r1cs })
    }

    pub fn create_random_proof<G: Curve, C: ConstraintSynthesizer<G::Fr>, R: Rng>(
        pk: &ProveKey<G>,
        c: C,
        r1cs_hash: G::Fr, 
        params_hash: G::Fr,
        rng: &mut R,
    ) -> Result<Proof<G>, SynthesisError> {

        super::prover::create_nizk_proof(&pk.params, &pk.r1cs, c,r1cs_hash, params_hash, rng)
    }

    pub fn verify_proof<G: Curve>(
        vk: &VerifyKey<G>,
        proof: &Proof<G>,
        publics: &[G::Fr],
        r1cs_hash: G::Fr, 
        params_hash: G::Fr,

    ) -> Result<bool, SynthesisError> {
        super::verify::verify_nizk_proof::<G>(&vk.params, &vk.r1cs, publics, proof,r1cs_hash, params_hash)
    }
}
