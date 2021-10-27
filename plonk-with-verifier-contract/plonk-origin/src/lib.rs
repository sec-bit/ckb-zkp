//! An implementation of the [`PlonK`].
//!
//! [`PlonK`]: https://eprint.iacr.org/2019/953.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(clippy::op_ref, clippy::suspicious_op_assign_impl)]
#![cfg_attr(not(use_asm), forbid(unsafe_code))]
#![cfg_attr(use_asm, feature(llvm_asm))]
#![cfg_attr(use_asm, deny(unsafe_code))]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as Map;

#[cfg(feature = "std")]
use std::collections::HashMap as Map;
use ark_ec::{ PairingEngine};

use ark_ff::{FftField as Field, ToBytes};
use ark_poly::EvaluationDomain;
use ark_poly::univariate::DensePolynomial;

use ark_std::{marker::PhantomData,  vec, vec::Vec};
// use digest::Digest;
// use rand_core::RngCore;

mod error;
use error::Error;

mod data_structures;
pub use crate::data_structures::*;

mod composer;
pub use crate::composer::Composer;

mod ahp;
use ahp::{AHPForPLONK };
use crate::pc::PCKey;

// mod rng;
use crate::transcript::TranscriptLibrary;
use crate::utils::{evaluate_first_lagrange_poly, generator};

mod utils;
mod transcript;
mod pc;


pub type LabeledPolynomial<F> = ark_poly_commit::LabeledPolynomial<F, DensePolynomial<F>>;

pub struct Plonk<E: PairingEngine> {
    _field: PhantomData<E::Fr>,
}

impl<E: PairingEngine> Plonk<E> {
    pub const PROTOCOL_NAME: &'static [u8] = b"PLONK";

    #[allow(clippy::type_complexity)]
    pub fn keygen(
        pckey: &mut PCKey<E>,
        cs: &Composer<E::Fr>,
        ks: [E::Fr; 4],
    ) -> Result<(ProverKey<E>, VerifierKey<E>), Error> {
        let index = AHPForPLONK::index(cs, ks)?;
        if pckey.max_degree < index.size() {
            return Err(Error::CircuitTooLarge);
        }

        //q0123 qm qc sigma0123
        let new_comms = pckey.commit_vec(index.iter());

        let vk = VerifierKey {
            comms: new_comms,
            info: index.info.clone(),
        };
        let pk = ProverKey {
            vk: vk.clone(),
            index,
        };

        Ok((pk, vk))
    }

    pub fn prove(
        pckey: &mut PCKey<E>,
        pk: &ProverKey<E>,
        cs: &Composer<E::Fr>,
    ) -> Result<Proof<E>, Error>
    {
        let public_inputs = cs.public_inputs();
        let mut transcript = TranscriptLibrary::new();
        for public_input in public_inputs {
            transcript.update_with_fr(public_input);
        }

        let ps = AHPForPLONK::prover_init(cs, &pk.index)?;
        let vs = AHPForPLONK::verifier_init(&pk.vk.info)?;

        let (ps, first_oracles) = AHPForPLONK::prover_first_round(ps, &cs)?;

        let first_comms = pckey.commit_vec(first_oracles.iter());

        //65 Preventing border crossing
        let mut bytes = [0u8; 65];
        for i in 1..4 {
            first_comms[i].write(bytes.as_mut())?;
            let mut x = [0u8; 32];
            for j in 0..32 {
                x[32-j-1] = bytes[j];
            }
            transcript.update_with_u256(x);
            let mut y = [0u8; 32];
            for j in 32..64 {
                y[64-j-1] = bytes[j];
            }
            transcript.update_with_u256(y);
        }
        let x = [0u8; 32];
        transcript.update_with_u256(x);
        let y = [0u8; 32];
        transcript.update_with_u256(y);

        let beta: E::Fr = transcript.generate_challenge();
        let gamma: E::Fr = transcript.generate_challenge();


        let (vs, first_msg) = AHPForPLONK::verifier_first_round(vs, beta, gamma)?;

        let (ps, second_oracles) =
            AHPForPLONK::prover_second_round(ps, &first_msg, &pk.vk.info.ks)?;

        let second_comms = pckey.commit_vec(second_oracles.iter());

        let mut bytes = [0u8; 65];
        second_comms[0].write(bytes.as_mut())?;
            let mut x = [0u8; 32];
            for j in 0..32 {
                x[32-j-1] = bytes[j];
            }
            transcript.update_with_u256(x);
            let mut y = [0u8; 32];
            for j in 32..64 {
                y[64-j-1] = bytes[j];
            }
            transcript.update_with_u256(y);

        let alpha: E::Fr = transcript.generate_challenge();

        let (vs, second_msg) = AHPForPLONK::verifier_second_round(vs,  alpha)?;

        let third_oracles = AHPForPLONK::prover_third_round(ps, &second_msg, &pk.vk.info.ks)?;

        let third_comms = pckey.commit_vec(third_oracles.iter());

        let mut bytes = [0u8; 65];
        for i in 0..third_comms.len() {
            third_comms[i].write(bytes.as_mut())?;
            let mut x = [0u8; 32];
            for j in 0..32 {
                x[32-j-1] = bytes[j];
            }
            transcript.update_with_u256(x);
            let mut y = [0u8; 32];
            for j in 32..64 {
                y[64-j-1] = bytes[j];
            }
            transcript.update_with_u256(y);
        }

        let zeta: E::Fr = transcript.generate_challenge();


        let (vs, third_msg) = AHPForPLONK::verifier_third_round(vs,  zeta)?;

        let polynomials_pre: Vec<_> = pk
            .index
            .iter().collect();

        let polynomials_trans: Vec<_> = first_oracles.iter()
        .chain(second_oracles.iter())
        .chain(third_oracles.iter())
        .collect();

        // [w0123] [z] [t1234]
        let commitments = vec![
            first_comms.clone(),
            second_comms.clone(),
            third_comms.clone(),
        ];

        let comms = pk
            .vk
            .comms.iter().cloned()
            .chain(first_comms.iter().cloned())
            .chain(second_comms.iter().cloned())
            .chain(third_comms.iter().cloned())
            .collect();

        //q0 q1 q2 q3 qm qc sigma_0 1 2 3, w0123, z, t1234, full_t, z^
        let mut evals = PCKey::<E>::compute_opening_evaluations(polynomials_pre.clone(), zeta);
        let mut tmp_evals = PCKey::<E>::compute_opening_evaluations(polynomials_trans.clone(), zeta);
        evals.append(&mut tmp_evals);
        //full_t
        let poly_t: LabeledPolynomial<E::Fr> = PCKey::<E>::compute_full_t(third_oracles.iter());
        let value = poly_t.evaluate(&zeta);
        evals.push(value);
        //compute z^
        let g = generator(vs.info.domain_n);
        let zvalue = second_oracles.z.evaluate(&(zeta * g));
        evals.push(zvalue);

        let l1_zeta = evaluate_first_lagrange_poly(vs.info.domain_n, zeta);
        let (comm_r, eval_r) = PCKey::<E>::compute_comm_eval_of_r(comms, evals.clone(), beta, gamma, alpha, zeta, &pk.vk.info.ks, l1_zeta);
        let domain_size = vs.info.domain_n.size();
        let polys_tmp: Vec<_> = polynomials_pre.iter().cloned()
            .chain(second_oracles.iter())
            .collect();
        let poly_r: LabeledPolynomial<E::Fr> = PCKey::<E>::compute_full_r(domain_size, polys_tmp, evals.clone(), beta, gamma, alpha, zeta, &pk.vk.info.ks, l1_zeta);

        //evals:q0 q1 q2 q3 qm qc sigma_0 1 2 3, w0123, z, t1234, full_t, z^
        for i in 11..14 {
            transcript.update_with_fr(&evals[i]);
        }
        transcript.update_with_fr(&evals[10]);
        for i in 7..10 {
            transcript.update_with_fr(&evals[i]);
        }
        transcript.update_with_fr(&evals[20]);
        transcript.update_with_fr(&evals[19]);
        transcript.update_with_fr(&eval_r);

        let v: E::Fr = transcript.generate_challenge();

        let mut polys_tmp: Vec<_> = polynomials_pre.iter().cloned()
            .chain(polynomials_trans.iter().cloned())
            .collect();
        polys_tmp.push(&poly_r);
        let pi_w = pckey.compute_opening_proof_comm_w(polys_tmp, zeta, v, domain_size);
        let (pi_wz,_) = pckey.open_one(&second_oracles.z, zeta * g);

        // let mut bytes = [0u8; 65];
        // pi_w.write(bytes.as_mut())?;
        //     let mut x = [0u8; 32];
        //     for j in 0..32 {
        //         x[32-j-1] = bytes[j];
        //     }
        //     transcript.update_with_u256(x);
        //     let mut y = [0u8; 32];
        //     for j in 32..64 {
        //         y[64-j-1] = bytes[j];
        //     }
        //     transcript.update_with_u256(y);
        //
        // let mut bytes = [0u8; 65];
        // pi_wz.write(bytes.as_mut())?;
        // let mut x = [0u8; 32];
        // for j in 0..32 {
        //     x[32-j-1] = bytes[j];
        // }
        // transcript.update_with_u256(x);
        // let mut y = [0u8; 32];
        // for j in 32..64 {
        //     y[64-j-1] = bytes[j];
        // }
        // transcript.update_with_u256(y);
        //
        // let u: E::Fr = transcript.generate_challenge();

        //w123 0, sigma_1 2 3, z^, t,  r
        let mut evaluations = Vec::new();
        evaluations.push(evals[11]);
        evaluations.push(evals[12]);
        evaluations.push(evals[13]);
        evaluations.push(evals[10]);
        evaluations.push(evals[7]);
        evaluations.push(evals[8]);
        evaluations.push(evals[9]);
        evaluations.push(evals[20]);
        evaluations.push(evals[19]);
        evaluations.push(eval_r);

        let proof = Proof {
            commitments,
            evaluations,
            pi_w,
            pi_wz,
        };
        Ok(proof)
    }

    pub fn verify(
        vk: &VerifierKey<E>,
        public_inputs: &[E::Fr],
        proof: &Proof<E>,
        pckey: &mut PCKey<E>,
    ) -> Result<bool, Error> {
        let vs = AHPForPLONK::verifier_init(&vk.info).unwrap();

        let mut transcript = TranscriptLibrary::new();
        for public_input in public_inputs {
            transcript.update_with_fr(public_input);
        }

        let first_comms = proof.commitments[0].clone();

        let mut bytes = [0u8; 65];
        for i in 1..4 {
            first_comms[i].write(bytes.as_mut())?;
            let mut x = [0u8; 32];
            for j in 0..32 {
                x[32-j-1] = bytes[j];
            }
            transcript.update_with_u256(x);
            let mut y = [0u8; 32];
            for j in 32..64 {
                y[64-j-1] = bytes[j];
            }
            transcript.update_with_u256(y);
        }
        let x = [0u8; 32];
        transcript.update_with_u256(x);
        let y = [0u8; 32];
        transcript.update_with_u256(y);

        let beta: E::Fr = transcript.generate_challenge();
        let gamma: E::Fr = transcript.generate_challenge();

        let (vs, first_msg) = AHPForPLONK::verifier_first_round(vs,  beta, gamma).unwrap();

        let second_comms = proof.commitments[1].clone();

        let mut bytes = [0u8; 65];
        second_comms[0].write(bytes.as_mut())?;
        let mut x = [0u8; 32];
        for j in 0..32 {
            x[32-j-1] = bytes[j];
        }
        transcript.update_with_u256(x);
        let mut y = [0u8; 32];
        for j in 32..64 {
            y[64-j-1] = bytes[j];
        }
        transcript.update_with_u256(y);

        let alpha: E::Fr = transcript.generate_challenge();

        let (vs, second_msg) = AHPForPLONK::verifier_second_round(vs,  alpha).unwrap();

        let third_comms = proof.commitments[2].clone();

        let mut bytes = [0u8; 65];
        for i in 0..third_comms.len() {
            third_comms[i].write(bytes.as_mut())?;
            let mut x = [0u8; 32];
            for j in 0..32 {
                x[32-j-1] = bytes[j];
            }
            transcript.update_with_u256(x);
            let mut y = [0u8; 32];
            for j in 32..64 {
                y[64-j-1] = bytes[j];
            }
            transcript.update_with_u256(y);
        }

        let zeta: E::Fr = transcript.generate_challenge();

        let (vs, third_msg) = AHPForPLONK::verifier_third_round(vs,  zeta).unwrap();

        //w123 0, sigma_1 2 3, z^, t,  r
        let evals = proof.evaluations.clone();
        for eval in &evals {
            transcript.update_with_fr(eval);
        }
        let v: E::Fr = transcript.generate_challenge();

        let mut bytes = [0u8; 65];
        proof.pi_w.write(bytes.as_mut())?;
        let mut x = [0u8; 32];
        for j in 0..32 {
            x[32-j-1] = bytes[j];
        }
        transcript.update_with_u256(x);
        let mut y = [0u8; 32];
        for j in 32..64 {
            y[64-j-1] = bytes[j];
        }
        transcript.update_with_u256(y);

        let mut bytes = [0u8; 65];
        proof.pi_wz.write(bytes.as_mut())?;
        let mut x = [0u8; 32];
        for j in 0..32 {
            x[32-j-1] = bytes[j];
        }
        transcript.update_with_u256(x);
        let mut y = [0u8; 32];
        for j in 32..64 {
            y[64-j-1] = bytes[j];
        }
        transcript.update_with_u256(y);

        let u: E::Fr = transcript.generate_challenge();

        let result = PCKey::<E>::verifier_equality_check(&vs, evals, public_inputs);
        assert!(result);

        let result = pckey.verify_pc(&vs, vk, proof, v, u);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::BigInteger256;
    use ark_ff::ToBytes;
    use ark_ff::BigInteger;
    use ark_ff::PrimeField;
    // use ark_ff::FftField as Field;
    // use ark_poly::univariate::DensePolynomial;
    use ark_poly::EvaluationDomain;
    use std::fs::File;
    //use ark_bls12_381::{Bls12_381, Fr};
    use ark_bn254::{Bn254};
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};
    use ark_std::test_rng;

    //use blake2::Blake2s;
    // use sha3::{Keccak256};

    use crate::composer::Composer;

    use super::*;
    // use std::io;

    // type PC = MarlinKZG10<Bn254, DensePolynomial<Fr>>;
    type PlonkInst = Plonk<Bn254>;

    pub fn ks() -> [Fr; 4] {
        [
            Fr::one(),
            Fr::from(7_u64 as u128),
            Fr::from(13_u64 as u128),
            Fr::from(17_u64 as u128),
        ]
    }

    pub fn circuit() -> Composer<Fr> {
        let mut cs = Composer::new();
        let one = Fr::one();
        let two = one + one;
        let three = two + one;
        let four = two + two;
        let six = two + four;
        let var_one = cs.alloc_and_assign(one);
        let var_two = cs.alloc_and_assign(two);
        let var_three = cs.alloc_and_assign(three);
        let var_four = cs.alloc_and_assign(four);
        let var_six = cs.alloc_and_assign(six);
        cs.create_add_gate(
            (var_one, one),
            (var_two, one),
            var_three,
            None,
            Fr::zero(),
            Fr::zero(),
        );
        cs.create_add_gate(
            (var_one, one),
            (var_three, one),
            var_four,
            None,
            Fr::zero(),
            Fr::zero(),
        );
        cs.create_mul_gate(
            var_two,
            var_two,
            var_four,
            None,
            Fr::one(),
            Fr::zero(),
            Fr::zero(),
        );
        cs.create_mul_gate(var_one, var_two, var_six, None, two, two, Fr::zero());
        cs.constrain_to_constant(var_six, six, Fr::zero());

        cs
    }

    #[test]
    fn test_plonk() -> Result<(), Error>
    {
        let rng = &mut test_rng();

        // compose
        let cs = circuit();
        let ks = ks();
        println!("size of the circuit: {}", cs.size());

        let mut pckey = PCKey::setup(64, rng);
        println!("g2\n{}", pckey.vk.h);
        println!("g1\n{}", pckey.vk.g);

        let (pk, vk) = PlonkInst::keygen(&mut pckey, &cs, ks)?;

        let proof = PlonkInst::prove(&mut pckey, &pk, &cs)?;

        println!("h\n{}", pckey.vk.h.x.c0);
        println!("{}", pckey.vk.h.x.c1);
        println!("{}", pckey.vk.h.y.c0);
        println!("{}", pckey.vk.h.y.c1);

        //Serialization: we need verificationKey for test (public_inputs are all 0 at present)
        //verificationKey:
        // domain-n
        // num_inputs
        // omega
        // selector_commitments
        // permutation_commitments
        // permutation_non_residues (ks[1],ks[2],ks[3]
        // g2*x（beta_h
        //
        //proof:
        // wire_commitments: [w_1],[w_2],[w_3],[w_0]
        // grand_product_commitment: [z]
        // quotient_poly_commitments: [t_1][t_2][t_3][t_4]
        // wire_values_at_z: w1,w2,w3,w0
        // grand_product_at_z_omega: z^
        // quotient_polynomial_at_z: t
        // linearization_polynomial_at_z: r
        // permutation_polynomials_at_z: sigma1,sigma2,sigma3
        // opening_at_z_proof: [W]
        // opening_at_z_omega_proof: [Wz]

        let mut buffer = File::create("foo").unwrap();


        // domain-n
        let domain_size = BigInteger256::from((vk.info.n) as u64);
        domain_size.to_bytes_be().write(&mut buffer)?;
        // num_inputs
        BigInteger256::from(cs.size() as u64).to_bytes_be().write(&mut buffer)?;
        // omega
        let g = vk.info.domain_n.element(1);
        println!("omega g\n{}", g);
        g.into_repr().to_bytes_be().write(&mut buffer)?;

        // selector_commitments
        for i in 1..4 {
            if vk.comms[i].0.is_zero() {
                //we need (0, 0) in contracts. but here Y != 0
                vk.comms[i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
                vk.comms[i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            } else {
                vk.comms[i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
                vk.comms[i].0.y.into_repr().to_bytes_be().write(&mut buffer)?;
            }
        }
        if vk.comms[0].0.is_zero() {
            vk.comms[0].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            vk.comms[0].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
        } else {
            vk.comms[0].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            vk.comms[0].0.y.into_repr().to_bytes_be().write(&mut buffer)?;
        }
        for i in 4..6 {
            if vk.comms[i].0.is_zero() {
                vk.comms[i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
                vk.comms[i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            } else {
                vk.comms[i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
                vk.comms[i].0.y.into_repr().to_bytes_be().write(&mut buffer)?;
            }
        }
        // permutation_commitments
        for i in 7..10 {
            if vk.comms[i].0.is_zero() {
                vk.comms[i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
                vk.comms[i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            } else {
                vk.comms[i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
                vk.comms[i].0.y.into_repr().to_bytes_be().write(&mut buffer)?;
            }
        }
        if vk.comms[6].0.is_zero() {
            vk.comms[6].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            vk.comms[6].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
        } else {
            vk.comms[6].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            vk.comms[6].0.y.into_repr().to_bytes_be().write(&mut buffer)?;
        }
        // permutation_non_residues (ks[1],ks[2],ks[3]
        vk.info.ks[1].into_repr().to_bytes_be().write(&mut buffer)?;
        vk.info.ks[2].into_repr().to_bytes_be().write(&mut buffer)?;
        vk.info.ks[3].into_repr().to_bytes_be().write(&mut buffer)?;
        // g2*x（beta_h
        pckey.vk.beta_h.x.c0.into_repr().to_bytes_be().write(&mut buffer)?;
        pckey.vk.beta_h.x.c1.into_repr().to_bytes_be().write(&mut buffer)?;
        pckey.vk.beta_h.y.c0.into_repr().to_bytes_be().write(&mut buffer)?;
        pckey.vk.beta_h.y.c1.into_repr().to_bytes_be().write(&mut buffer)?;


        //proof:
        // wire_commitments: [w_1],[w_2],[w_3],[w_0]
        for i in 1..4 {
            if proof.commitments[0][i].0.is_zero() {
                proof.commitments[0][i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
                proof.commitments[0][i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            } else {
                proof.commitments[0][i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
                proof.commitments[0][i].0.y.into_repr().to_bytes_be().write(&mut buffer)?;
            }
        }
        if proof.commitments[0][0].0.is_zero() {
            proof.commitments[0][0].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            proof.commitments[0][0].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
        } else {
            proof.commitments[0][0].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            proof.commitments[0][0].0.y.into_repr().to_bytes_be().write(&mut buffer)?;
        }
        // grand_product_commitment: [z]
        if proof.commitments[1][0].0.is_zero() {
            proof.commitments[1][0].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            proof.commitments[1][0].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
        } else {
            proof.commitments[1][0].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            proof.commitments[1][0].0.y.into_repr().to_bytes_be().write(&mut buffer)?;
        }
        // quotient_poly_commitments: [t_1][t_2][t_3][t_4]
        for i in 0..4 {
            if proof.commitments[2][i].0.is_zero() {
                proof.commitments[2][i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
                proof.commitments[2][i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            } else {
                proof.commitments[2][i].0.x.into_repr().to_bytes_be().write(&mut buffer)?;
                proof.commitments[2][i].0.y.into_repr().to_bytes_be().write(&mut buffer)?;
            }
        }
        // wire_values_at_z: w1,w2,w3,w0
        for i in 0..4 {
            proof.evaluations[i].into_repr().to_bytes_be().write(&mut buffer)?;
        }
        // grand_product_at_z_omega: z^
        // quotient_polynomial_at_z: t
        // linearization_polynomial_at_z: r
        for i in 7..10 {
            proof.evaluations[i].into_repr().to_bytes_be().write(&mut buffer)?;
        }
        // permutation_polynomials_at_z: sigma1,sigma2,sigma3
        for i in 4..7 {
            proof.evaluations[i].into_repr().to_bytes_be().write(&mut buffer)?;
        }
        // opening_at_z_proof: [W]
        if proof.pi_w.0.is_zero() {
            proof.pi_w.0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            proof.pi_w.0.x.into_repr().to_bytes_be().write(&mut buffer)?;
        } else {
            proof.pi_w.0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            proof.pi_w.0.y.into_repr().to_bytes_be().write(&mut buffer)?;
        }
        // opening_at_z_omega_proof: [Wz]
        if proof.pi_wz.0.is_zero() {
            proof.pi_wz.0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            proof.pi_wz.0.x.into_repr().to_bytes_be().write(&mut buffer)?;
        } else {
            proof.pi_wz.0.x.into_repr().to_bytes_be().write(&mut buffer)?;
            proof.pi_wz.0.y.into_repr().to_bytes_be().write(&mut buffer)?;
        }

        let result = PlonkInst::verify(&vk, cs.public_inputs(), &proof, &mut pckey);
        match result {
            Ok(res) => assert!(res),
            Err(error) => {
                panic!("Problem of IO: {:?}", error)
                // println!("IO err")
            },
        };

        Ok(())
    }
}
