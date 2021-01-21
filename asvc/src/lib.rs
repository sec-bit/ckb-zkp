//! An implementation of the [`aSVC`].
//!
//! [`aSVC`]: https://eprint.iacr.org/2020/527
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
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use ark_ec::{
    msm::FixedBaseMSM, msm::VariableBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve,
};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    polynomial::univariate::{DenseOrSparsePolynomial, DensePolynomial},
    EvaluationDomain, GeneralEvaluationDomain, Polynomial, UVPolynomial,
};
use core::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};
use rand::Rng;
use zkp_r1cs::SynthesisError;

#[cfg(test)]
pub mod test;

#[derive(Clone, Eq, PartialEq)]
pub struct UpdateKey<E: PairingEngine> {
    pub ai: E::G1Affine,
    pub ui: E::G1Affine,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProvingKey<E: PairingEngine> {
    pub powers_of_g1: Vec<E::G1Affine>,
    pub l_of_g1: Vec<E::G1Affine>,
    pub update_keys: Vec<UpdateKey<E>>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerificationKey<E: PairingEngine> {
    pub powers_of_g1: Vec<E::G1Affine>,
    pub powers_of_g2: Vec<E::G2Affine>,
    pub a: E::G1Affine,
}

#[derive(Clone)]
pub struct Parameters<E: PairingEngine> {
    pub proving_key: ProvingKey<E>,
    pub verification_key: VerificationKey<E>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Commitment<E: PairingEngine> {
    pub commit: E::G1Affine,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Proof<E: PairingEngine> {
    pub w: E::G1Affine,
}

pub fn key_gen<E, R>(n: usize, rng: &mut R) -> Result<Parameters<E>, SynthesisError>
where
    E: PairingEngine,
    R: Rng,
{
    let tau = E::Fr::rand(rng);
    let g1 = E::G1Projective::rand(rng);
    let g2 = E::G2Projective::rand(rng);

    let domain: GeneralEvaluationDomain<E::Fr> =
        EvaluationDomain::<E::Fr>::new(n).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let max_degree = domain.size();

    let scalar_bits = E::Fr::size_in_bits();
    let g1_window = FixedBaseMSM::get_mul_window_size(max_degree + 1);
    let g1_table = FixedBaseMSM::get_window_table::<E::G1Projective>(scalar_bits, g1_window, g1);

    let g2_window = FixedBaseMSM::get_mul_window_size(max_degree + 1);
    let g2_table = FixedBaseMSM::get_window_table::<E::G2Projective>(scalar_bits, g2_window, g2);

    let mut curs = vec![E::Fr::one()];
    let mut cur = tau;
    for _ in 0..max_degree {
        curs.push(cur);
        cur.mul_assign(&tau);
    }
    let mut powers_of_g1 =
        FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(scalar_bits, g1_window, &g1_table, &curs);
    let powers_of_g1 = E::G1Projective::batch_normalization_into_affine(&mut powers_of_g1);

    let mut powers_of_g2 =
        FixedBaseMSM::multi_scalar_mul::<E::G2Projective>(scalar_bits, g2_window, &g2_table, &curs);
    let powers_of_g2 = E::G2Projective::batch_normalization_into_affine(&mut powers_of_g2);

    // A(τ) = τ^n - 1
    let a = powers_of_g1[max_degree].into_projective().sub(&g1);

    let mut update_keys: Vec<UpdateKey<E>> = Vec::new();
    let mut l_of_g1: Vec<E::G1Projective> = Vec::new();
    for i in 0..max_degree {
        // 1/(τ-ω^i)
        let tau_omega_i_divisor = E::Fr::one().div(&tau.sub(&domain.group_gen.pow(&[i as u64])));

        // ai = g_1^(A(τ)/(τ-ω^i))
        let ai = a.mul(tau_omega_i_divisor.into());

        // 1/nω^(n-i) = ω^i/n
        let a_aside_omega_i_divisor = domain
            .group_gen
            .pow(&[i as u64])
            .div(&E::Fr::from_repr((max_degree as u64).into()));

        // li = g_1^L_i(x) = g_1^(A(τ)/((x-ω^i)*A'(ω^i))) = ai^(1/A'(ω^i))
        let li = ai.mul(a_aside_omega_i_divisor);

        // ui = (li-1)/(x-ω^i)
        let mut ui = li.sub(&g1);
        ui = ui.mul(tau_omega_i_divisor.into());

        //batch_normalization_into_affine?
        let upk = UpdateKey {
            ai: ai.into_affine(),
            ui: ui.into_affine(),
        };
        update_keys.push(upk);
        l_of_g1.push(li);
    }
    let l_of_g1 = E::G1Projective::batch_normalization_into_affine(&mut l_of_g1);

    let params = Parameters::<E> {
        proving_key: ProvingKey::<E> {
            powers_of_g1: powers_of_g1.clone(),
            l_of_g1: l_of_g1,
            update_keys: update_keys,
        },
        verification_key: VerificationKey::<E> {
            powers_of_g1: powers_of_g1,
            powers_of_g2: powers_of_g2,
            a: a.into_affine(),
        },
    };
    Ok(params)
}

pub fn commit<E>(
    prk_params: &ProvingKey<E>,
    values: Vec<E::Fr>,
) -> Result<Commitment<E>, SynthesisError>
where
    E: PairingEngine,
{
    let num_coefficient = values.len();
    let num_powers = prk_params.l_of_g1.len();

    assert!(num_coefficient >= 1);
    assert!(num_coefficient <= num_powers);
    let scalars: Vec<<E::Fr as PrimeField>::BigInt> =
        values.iter().map(|v| v.into_repr()).collect();
    let commit = VariableBaseMSM::multi_scalar_mul(&prk_params.l_of_g1, &scalars);

    let c = Commitment::<E> {
        commit: commit.into_affine(),
    };
    Ok(c)
}

pub fn prove_pos<E>(
    prk_params: &ProvingKey<E>,
    values: Vec<E::Fr>,
    points: Vec<u32>,
) -> Result<Proof<E>, SynthesisError>
where
    E: PairingEngine,
{
    let mut values = values.clone();
    let domain: GeneralEvaluationDomain<E::Fr> =
        EvaluationDomain::<E::Fr>::new(prk_params.powers_of_g1.len() - 1)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    domain.ifft_in_place(&mut values);
    let polynomial = DensePolynomial::from_coefficients_vec(values);

    // ∏(x-ω^i)
    let mut divisor_polynomial = DensePolynomial::from_coefficients_vec(vec![E::Fr::one()]);
    for point in points.iter() {
        let tpoly = DensePolynomial::from_coefficients_vec(vec![
            domain.group_gen.pow(&[*point as u64]).neg(),
            E::Fr::one(),
        ]);
        divisor_polynomial = divisor_polynomial.mul(&tpoly);
    }

    // Φ(x) / A_I(x) = q(x) ... r(x)
    let dense_or_sparse_poly: DenseOrSparsePolynomial<'_, E::Fr> = polynomial.into();
    let dense_or_sparse_divisor: DenseOrSparsePolynomial<'_, E::Fr> = divisor_polynomial.into();
    let (witness_polynomial, _) = dense_or_sparse_poly
        .divide_with_q_and_r(&dense_or_sparse_divisor)
        .unwrap();

    // π = g_1^q(τ)
    let scalars: Vec<<E::Fr as PrimeField>::BigInt> =
        witness_polynomial.iter().map(|v| v.into_repr()).collect();
    let witness = VariableBaseMSM::multi_scalar_mul(&prk_params.powers_of_g1, &scalars);
    // println!("[open] evaluate the coeffieients for witness...OK. witness = {}", witness);

    let proof = Proof::<E> {
        w: witness.into_affine(),
    };

    Ok(proof)
}

pub fn verify_pos<E>(
    vrk_params: &VerificationKey<E>,
    commit: &Commitment<E>,
    point_values: Vec<E::Fr>,
    points: Vec<u32>,
    proof: &Proof<E>,
    omega: E::Fr,
) -> Result<bool, SynthesisError>
where
    E: PairingEngine,
{
    // A_I(x) = ∏(x - ω^i)
    let mut a_polynomial = DensePolynomial::from_coefficients_vec(vec![E::Fr::one()]);
    for point in points.iter() {
        let tpoly = DensePolynomial::from_coefficients_vec(vec![
            omega.pow(&[*point as u64]).neg(),
            E::Fr::one(),
        ]);
        a_polynomial = a_polynomial.mul(&tpoly);
    }

    // r(x) = ∑（l_i * v_i） = ∑（A_I(x) * v_i）/(A_I'(ω^i)(x - ω_i))
    let mut r_polynomial = DensePolynomial::from_coefficients_vec(vec![E::Fr::zero()]);
    for (point, value) in points.iter().zip(point_values.iter()) {
        // x - ω_i
        let tpoly = DensePolynomial::from_coefficients_vec(vec![
            omega.pow(&[*point as u64]).neg(),
            E::Fr::one(),
        ]);
        // A_I(x)/(x - ω_i)
        let mut l_polynomial = a_polynomial.div(&tpoly);
        // A_I'(ω^i)
        let b_aside = l_polynomial.evaluate(&omega.pow(&[*point as u64]));

        // v_i/A_I'(ω^i)
        let bpoly = DensePolynomial::from_coefficients_vec(vec![value.div(&b_aside)]);

        // (A_I(x) /(x - ω_i)) * (v_i/(A_I'(ω^i))
        l_polynomial = l_polynomial.mul(&bpoly);

        r_polynomial = r_polynomial.add(l_polynomial);
    }
    let scalars: Vec<<E::Fr as PrimeField>::BigInt> =
        r_polynomial.iter().map(|v| v.into_repr()).collect();
    let r_value = VariableBaseMSM::multi_scalar_mul(&vrk_params.powers_of_g1, &scalars);

    let mut inner = commit.commit.into_projective();
    inner.sub_assign(&r_value); // inner.sub_assign(&r_value);
    let lhs = E::pairing(inner, vrk_params.powers_of_g2[0]);

    // A_I(τ) = ∏(τ - ω^i)
    let a_scalars: Vec<<E::Fr as PrimeField>::BigInt> =
        a_polynomial.iter().map(|v| v.into_repr()).collect();
    let a_value = VariableBaseMSM::multi_scalar_mul(&vrk_params.powers_of_g2, &a_scalars);

    let rhs = E::pairing(proof.w, a_value);

    Ok(lhs == rhs)
}

pub fn verify_upk<E>(
    vrk_params: &VerificationKey<E>,
    point: u32,
    upk: &UpdateKey<E>,
    omega: E::Fr,
) -> Result<bool, SynthesisError>
where
    E: PairingEngine,
{
    let n = vrk_params.powers_of_g1.len() - 1;
    // e(a_i, g^i/g^(w^i)) = e(a,g)
    // ω^i
    let omega_i = omega.pow(&[point as u64]);

    // g^τ / g^(ω^i)
    let inner = vrk_params.powers_of_g2[1].into_projective().sub(
        &vrk_params.powers_of_g2[0]
            .into_projective()
            .mul(omega_i.into()),
    );
    let lhs = E::pairing(upk.ai, inner);
    // println!("[verify_upk] evaluate lhs...ok");

    // println!("[verify_upk] start to evaluate rhs...");
    let rhs = E::pairing(vrk_params.a, vrk_params.powers_of_g2[0]);
    // println!("[verify_upk] evaluate rhs...ok");

    // e(a_i, g^τ / g^(ω^i)) = e(a, g), a_i^(τ - ω^i) = a
    let rs1 = lhs == rhs;
    // println!("[verify_upk] verify e(a_i, g^i/g^(w^i)) = e(a,g)...result = {}", rs1);

    // println!("[verify_upk] start to verify e(l_i/g, g) = e(u_i,g^τ/g^(ω^i))...");
    // println!("[verify_upk] start to evaluate lhs...");
    //a_i^(1/A'(ω^i))
    let a_aside_omega_i_divisor = omega
        .pow(&[point as u64])
        .div(&E::Fr::from_repr((n as u64).into()).unwrap());
    let l_value = upk.ai.mul(a_aside_omega_i_divisor);

    let inner2 = l_value.sub(&vrk_params.powers_of_g1[0].into_projective());
    let lhs = E::pairing(inner2, vrk_params.powers_of_g2[0]);
    // println!("[verify_upk] evaluate lhs...ok");

    // println!("[verify_upk] start to evaluate rhs...");
    let rhs = E::pairing(upk.ui, inner);
    // println!("[verify_upk] evaluate rhs...ok");
    let rs2 = lhs == rhs;
    // println!("[verify] verify e(l_i/g, g) = e(u_i,g^τ/g^(ω^i))...result = {}", rs2);

    Ok(rs1 && rs2)
}

pub fn update_commit<E>(
    commit: &Commitment<E>,
    delta: E::Fr,
    point: u32,
    upk: &UpdateKey<E>,
    omega: E::Fr,
    n: usize,
) -> Result<Commitment<E>, SynthesisError>
where
    E: PairingEngine,
{
    let a_aside_omega_i_divisor = omega
        .pow(&[point as u64])
        .div(&E::Fr::from_repr((n as u64).into()).unwrap());
    let l_value = upk.ai.mul(a_aside_omega_i_divisor);

    let new_commit = commit
        .commit
        .into_projective()
        .add(&(l_value.mul(delta.into())));
    let c = Commitment::<E> {
        commit: new_commit.into_affine(),
    };
    Ok(c)
}

pub fn update_proof<E>(
    proof: &Proof<E>,
    delta: E::Fr,
    point_i: u32,
    point_j: u32,
    upk_i: &UpdateKey<E>,
    upk_j: &UpdateKey<E>,
    omega: E::Fr,
    n: usize,
) -> Result<Proof<E>, SynthesisError>
where
    E: PairingEngine,
{
    let mut new_witness = proof.w.into_projective();
    // println!("[update_proof] start to update proof...i={}, j = {}", point_i, point_j);
    if point_i == point_j {
        new_witness.add_assign(&upk_i.ui.mul(delta));
    } else {
        //c_1 = 1/(ω_j - ω_i), c_2 = 1/(ω_i - ω_j)
        let omega_i = omega.pow(&[point_i as u64]);
        let omega_j = omega.pow(&[point_j as u64]);
        let c1 = E::Fr::one().div(&(omega_j.sub(&omega_i)));
        let c2 = E::Fr::one().div(&(omega_i.sub(&omega_j)));
        // w_ij = a_j^c_1 * a_i^c2
        let w_ij = upk_j.ai.mul(c1).add(&upk_i.ai.mul(c2));

        // u_ij = w_ij ^ (1/A'(w^j))
        let a_aside_omega_i_divisor = omega
            .pow(&[point_j as u64])
            .div(&E::Fr::from_repr((n as u64).into()).unwrap());
        let u_ij = w_ij.mul(a_aside_omega_i_divisor.into());
        new_witness.add_assign(&u_ij.mul(delta.into()));
    }

    let proof = Proof::<E> {
        w: new_witness.into_affine(),
    };
    Ok(proof)
}

pub fn aggregate_proofs<E>(
    points: Vec<u32>,
    proofs: Vec<Proof<E>>,
    omega: E::Fr,
) -> Result<Proof<E>, SynthesisError>
where
    E: PairingEngine,
{
    // A(x) = ∏(x-ω^i)
    let mut a_polynomial = DensePolynomial::from_coefficients_vec(vec![E::Fr::one()]);
    for point in points.iter() {
        let tpoly = DensePolynomial::from_coefficients_vec(vec![
            omega.pow(&[*point as u64]).neg(),
            E::Fr::one(),
        ]);
        a_polynomial = a_polynomial.mul(&tpoly);
    }

    let mut aggregate_witness = E::G1Projective::zero();
    for (point, proof) in points.iter().zip(proofs.iter()) {
        let divisor_polynomial = DensePolynomial::from_coefficients_vec(vec![
            omega.pow(&[*point as u64]).neg(),
            E::Fr::one(),
        ]);
        let a_aside_polynomial = a_polynomial.div(&divisor_polynomial);
        let c = E::Fr::one().div(&a_aside_polynomial.evaluate(&omega.pow(&[*point as u64])));
        aggregate_witness.add_assign(&proof.w.mul(c));
    }

    let proof = Proof::<E> {
        w: aggregate_witness.into_affine(),
    };

    Ok(proof)
}
