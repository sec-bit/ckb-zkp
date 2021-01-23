//! An implementation of the [`Groth16`] zkSNARK.
//!
//! [`Groth16`]: https://eprint.iacr.org/2016/260.pdf
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
use alloc::{string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{string::String, vec::Vec};

use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_serialize::*;
use zkp_r1cs::{Index, LinearCombination, SynthesisError};

/// Reduce an R1CS instance to a *Quadratic Arithmetic Program* instance.
pub mod r1cs_to_qap;

/// Generate public parameters for the Groth16 zkSNARK construction.
pub mod generator;

/// Create proofs for the Groth16 zkSNARK construction.
pub mod prover;

/// Verify proofs for the Groth16 zkSNARK construction.
pub mod verifier;

/// standard interface for setup with circuit.
pub use generator::generate_random_parameters;

/// standard interface for create proof.
pub use prover::create_random_proof;

/// standard interface for verify proof.
pub use verifier::verify_proof;

/// standard interface for prepare compute verify key.
pub use verifier::prepare_verifying_key;

/// A proof in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: PairingEngine> {
    pub a: E::G1Affine,
    pub b: E::G2Affine,
    pub c: E::G1Affine,
}

/// A verification key in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyKey<E: PairingEngine> {
    pub alpha_g1: E::G1Affine,
    pub beta_g2: E::G2Affine,
    pub gamma_g2: E::G2Affine,
    pub delta_g2: E::G2Affine,
    pub gamma_abc_g1: Vec<E::G1Affine>,
}

impl<E: PairingEngine> Default for VerifyKey<E> {
    fn default() -> Self {
        Self {
            alpha_g1: E::G1Affine::default(),
            beta_g2: E::G2Affine::default(),
            gamma_g2: E::G2Affine::default(),
            delta_g2: E::G2Affine::default(),
            gamma_abc_g1: Vec::new(),
        }
    }
}

/// Full public (prover and verifier) parameters for the Groth16 zkSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<E: PairingEngine> {
    pub vk: VerifyKey<E>,
    pub beta_g1: E::G1Affine,
    pub delta_g1: E::G1Affine,
    pub a_query: Vec<E::G1Affine>,
    pub b_g1_query: Vec<E::G1Affine>,
    pub b_g2_query: Vec<E::G2Affine>,
    pub h_query: Vec<E::G1Affine>,
    pub l_query: Vec<E::G1Affine>,
}

/// Preprocessed verification key parameters that enable faster verification
/// at the expense of larger size in memory.
#[derive(Clone, Debug, PartialEq)]
pub struct PreparedVerifyingKey<E: PairingEngine> {
    pub vk: VerifyKey<E>,
    pub alpha_g1_beta_g2: E::Fqk,
    pub gamma_g2_neg_pc: E::G2Prepared,
    pub delta_g2_neg_pc: E::G2Prepared,
    pub gamma_abc_g1: Vec<E::G1Affine>,
}

impl<E: PairingEngine> From<PreparedVerifyingKey<E>> for VerifyKey<E> {
    fn from(other: PreparedVerifyingKey<E>) -> Self {
        other.vk
    }
}

impl<E: PairingEngine> From<VerifyKey<E>> for PreparedVerifyingKey<E> {
    fn from(other: VerifyKey<E>) -> Self {
        prepare_verifying_key(&other)
    }
}

impl<E: PairingEngine> Default for PreparedVerifyingKey<E> {
    fn default() -> Self {
        Self {
            vk: VerifyKey::default(),
            alpha_g1_beta_g2: E::Fqk::default(),
            gamma_g2_neg_pc: E::G2Prepared::default(),
            delta_g2_neg_pc: E::G2Prepared::default(),
            gamma_abc_g1: Vec::new(),
        }
    }
}

fn push_constraints<F: Field>(
    l: LinearCombination<F>,
    constraints: &mut [Vec<(F, Index)>],
    this_constraint: usize,
) {
    for (var, coeff) in l.as_ref() {
        match var.get_unchecked() {
            Index::Input(i) => constraints[this_constraint].push((*coeff, Index::Input(i))),
            Index::Aux(i) => constraints[this_constraint].push((*coeff, Index::Aux(i))),
        }
    }
}

impl<E: PairingEngine> Parameters<E> {
    pub fn get_vk(&self, _: usize) -> Result<VerifyKey<E>, SynthesisError> {
        Ok(self.vk.clone())
    }

    pub fn get_a_query(
        &self,
        num_inputs: usize,
    ) -> Result<(&[E::G1Affine], &[E::G1Affine]), SynthesisError> {
        Ok((&self.a_query[1..num_inputs], &self.a_query[num_inputs..]))
    }

    pub fn get_b_g1_query(
        &self,
        num_inputs: usize,
    ) -> Result<(&[E::G1Affine], &[E::G1Affine]), SynthesisError> {
        Ok((
            &self.b_g1_query[1..num_inputs],
            &self.b_g1_query[num_inputs..],
        ))
    }

    pub fn get_b_g2_query(
        &self,
        num_inputs: usize,
    ) -> Result<(&[E::G2Affine], &[E::G2Affine]), SynthesisError> {
        Ok((
            &self.b_g2_query[1..num_inputs],
            &self.b_g2_query[num_inputs..],
        ))
    }

    pub fn get_h_query(
        &self,
        num_inputs: usize,
    ) -> Result<(&[E::G1Affine], &[E::G1Affine]), SynthesisError> {
        Ok((&self.h_query[0..num_inputs], &self.h_query[num_inputs..]))
    }

    pub fn get_a_query_full(&self) -> Result<&[E::G1Affine], SynthesisError> {
        Ok(&self.a_query)
    }

    pub fn get_b_g1_query_full(&self) -> Result<&[E::G1Affine], SynthesisError> {
        Ok(&self.b_g1_query)
    }

    pub fn get_b_g2_query_full(&self) -> Result<&[E::G2Affine], SynthesisError> {
        Ok(&self.b_g2_query)
    }

    pub fn get_h_query_full(&self) -> Result<&[E::G1Affine], SynthesisError> {
        Ok(&self.h_query)
    }

    pub fn get_l_query_full(&self) -> Result<&[E::G1Affine], SynthesisError> {
        Ok(&self.l_query)
    }
}
