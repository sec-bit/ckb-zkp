//! An implementation of the [`Marlin`].
//!
//! [`Marlin`]: https://eprint.iacr.org/2019/1047.pdf
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
use alloc::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "std")]
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};

use ark_ec::PairingEngine;
use ark_ff::to_bytes;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial};
use ark_std::UniformRand;
use rand::Rng;
use zkp_r1cs::{ConstraintSynthesizer, SynthesisError};

mod pc;
use pc::{Evaluations, LabeledCommitment, PC};

mod ahp;
use ahp::AHP;

mod errors;
use errors::Error;

mod data_structures;
pub use data_structures::*;
pub use pc::UniversalParams;

/// standard verify key name.
pub type VerifyKey<E> = IndexVerifierKey<E>;

mod fs_rng;
use fs_rng::FiatShamirRng;

pub fn universal_setup<E: PairingEngine, R: Rng>(
    max_degree: usize,
    rng: &mut R,
) -> Result<UniversalParams<E>, SynthesisError> {
    let max_degree = GeneralEvaluationDomain::<E::Fr>::compute_size_of_domain(max_degree)
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let srs = PC::setup(max_degree, rng)?;
    Ok(srs)
}

pub fn index<E: PairingEngine, C: ConstraintSynthesizer<E::Fr>>(
    srs: &UniversalParams<E>,
    c: C,
) -> Result<(IndexProverKey<'_, E>, IndexVerifierKey<E>), Error> {
    let index = AHP::index(c)?;
    if srs.max_degree() < index.max_degree() {
        return Err(Error::IndexTooLarge);
    }

    let (committer_key, verifier_key) = PC::trim(srs, index.max_degree())?;
    let (index_comms, index_rands) = PC::commit(&committer_key, index.iter(), None)?;
    let index_comms = index_comms
        .into_iter()
        .map(|c| c.commitment().clone())
        .collect();
    let ivk = IndexVerifierKey {
        index_info: index.index_info,
        index_comms,
        verifier_key,
    };
    let ipk = IndexProverKey {
        index,
        index_rands,
        index_verifier_key: ivk.clone(),
        committer_key,
    };
    Ok((ipk, ivk))
}

/// standard interface for create proof.
pub fn create_random_proof<E: PairingEngine, R: Rng, C: ConstraintSynthesizer<E::Fr>>(
    ipk: &IndexProverKey<'_, E>,
    c: C,
    zk_rng: &mut R,
) -> Result<Proof<E>, SynthesisError> {
    // init
    let pstate = AHP::<E::Fr>::prover_init(&ipk.index, c)?;
    let public_input = pstate.public_input();
    let mut fs_rng =
        FiatShamirRng::from_seed(&to_bytes![&ipk.index_verifier_key, &public_input].unwrap());
    // first round
    let (pstate, first_oracles) = AHP::<E::Fr>::prover_first_round(pstate, zk_rng)?;
    let (first_comms, first_rands) =
        PC::commit(&ipk.committer_key, first_oracles.iter(), Some(zk_rng))?;

    fs_rng.absorb(&to_bytes![first_comms].unwrap());
    let (vstate, verifier_first_msg) =
        AHP::<E::Fr>::verifier_first_round(ipk.index_verifier_key.index_info, &mut fs_rng)?;
    // second_round
    let (pstate, second_oracles) = AHP::<E::Fr>::prover_second_round(pstate, &verifier_first_msg)?;
    let (second_comms, second_rands) =
        PC::commit(&ipk.committer_key, second_oracles.iter(), Some(zk_rng))?;

    fs_rng.absorb(&to_bytes![second_comms].unwrap());
    let (vstate, verifier_second_msg) = AHP::<E::Fr>::verifier_second_round(vstate, &mut fs_rng)?;
    // third_round
    let third_oracles = AHP::<E::Fr>::prover_third_round(pstate, &verifier_second_msg)?;
    let (third_comms, third_rands) =
        PC::commit(&ipk.committer_key, third_oracles.iter(), Some(zk_rng))?;

    fs_rng.absorb(&to_bytes![third_comms].unwrap());
    let vstate = AHP::<E::Fr>::verifier_third_round(vstate, &mut fs_rng)?;
    // gathering opening elements
    let polynomials: Vec<_> = ipk
        .index
        .iter()
        .chain(first_oracles.iter())
        .chain(second_oracles.iter())
        .chain(third_oracles.iter())
        .collect();

    let randomnesses: Vec<_> = ipk
        .index_rands
        .clone()
        .into_iter()
        .chain(first_rands)
        .chain(second_rands)
        .chain(third_rands)
        .collect();

    let query_set = AHP::<E::Fr>::verifier_query_set(&vstate);
    let mut evaluations = Vec::new();
    for (label, point) in &query_set {
        let p = polynomials
            .iter()
            .find(|p| p.label() == label)
            .ok_or(Error::MissingEval(label.to_string()))?;
        let eval = p.polynomial().evaluate(&point);
        evaluations.push(eval);
    }
    fs_rng.absorb(&evaluations);
    let opening_challenge = u128::rand(&mut fs_rng).into();

    let opening_proofs = PC::batch_open(
        &ipk.committer_key,
        polynomials,
        &query_set,
        opening_challenge,
        &randomnesses,
    )?;

    let commitments = vec![
        first_comms.iter().map(|p| p.commitment().clone()).collect(),
        second_comms
            .iter()
            .map(|p| p.commitment().clone())
            .collect(),
        third_comms.iter().map(|p| p.commitment().clone()).collect(),
    ];
    Ok(Proof {
        commitments,
        evaluations,
        opening_proofs,
    })
}

/// standard interface for verify proof.
pub fn verify_proof<E: PairingEngine>(
    ivk: &IndexVerifierKey<E>,
    proof: &Proof<E>,
    public_input: &[E::Fr],
) -> Result<bool, SynthesisError> {
    let mut fs_rng = FiatShamirRng::from_seed(&to_bytes![&ivk, &public_input].unwrap());

    let first_comms = &proof.commitments[0];
    fs_rng.absorb(&to_bytes![first_comms].unwrap());
    let (vstate, _) = AHP::<E::Fr>::verifier_first_round(ivk.index_info, &mut fs_rng)?;

    let second_comms = &proof.commitments[1];
    fs_rng.absorb(&to_bytes![second_comms].unwrap());
    let (vstate, _) = AHP::<E::Fr>::verifier_second_round(vstate, &mut fs_rng)?;

    let third_comms = &proof.commitments[2];
    fs_rng.absorb(&to_bytes![third_comms].unwrap());
    let vstate = AHP::<E::Fr>::verifier_third_round(vstate, &mut fs_rng)?;

    let query_set = AHP::<E::Fr>::verifier_query_set(&vstate);
    fs_rng.absorb(&proof.evaluations);
    let opening_challenge: E::Fr = u128::rand(&mut fs_rng).into();

    let degree_bounds: Vec<_> = vec![None; ivk.index_comms.len()]
        .into_iter()
        .chain(AHP::<E::Fr>::prover_first_round_degree_bounds(
            &ivk.index_info,
        ))
        .chain(AHP::<E::Fr>::prover_second_round_degree_bounds(
            &ivk.index_info,
        ))
        .chain(AHP::<E::Fr>::prover_third_round_degree_bounds(
            &ivk.index_info,
        ))
        .collect();

    let commitments: Vec<_> = ivk
        .iter()
        .chain(first_comms)
        .chain(second_comms)
        .chain(third_comms)
        .cloned()
        .zip(AHP::<E::Fr>::polynomial_labels())
        .zip(degree_bounds)
        .map(|((c, l), d)| LabeledCommitment::new(l, c, d))
        .collect();

    let evalutions: Evaluations<E::Fr> = query_set
        .iter()
        .zip(&proof.evaluations)
        .map(|((l, p), &e)| ((l.to_string(), *p), e))
        .collect();
    let result = AHP::<E::Fr>::verifier_equality_check(public_input, &evalutions, &vstate)?;
    if !result {
        return Ok(false);
    }

    let result = PC::batch_check(
        &ivk.verifier_key,
        &commitments,
        &query_set,
        &evalutions,
        &proof.opening_proofs,
        opening_challenge,
    )?;
    Ok(result)
}
