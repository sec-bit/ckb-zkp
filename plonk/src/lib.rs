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

use ark_ff::{to_bytes, FftField as Field};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{
    Evaluations, LabeledCommitment, PCUniversalParams, PolynomialCommitment,
};

use ark_std::{marker::PhantomData, vec, vec::Vec};
use digest::Digest;
use rand_core::RngCore;

mod errors;
use errors::Error;

mod data_structures;
use crate::data_structures::*;

mod composer;
use crate::composer::Composer;

mod ahp;
use ahp::{AHPForPLONK, EvaluationsProvider};

mod rng;
use crate::rng::FiatShamirRng;

mod utils;

pub struct Plonk<
    F: Field,
    D: Digest,
    PC: PolynomialCommitment<F, DensePolynomial<F>>,
> {
    _field: PhantomData<F>,
    _digest: PhantomData<D>,
    _pc: PhantomData<PC>,
}

impl<F: Field, D: Digest, PC: PolynomialCommitment<F, DensePolynomial<F>>>
    Plonk<F, D, PC>
{
    pub const PROTOCOL_NAME: &'static [u8] = b"PLONK";

    pub fn setup<R: RngCore>(
        max_degree: usize,
        rng: &mut R,
    ) -> Result<UniversalParams<F, PC>, Error<PC::Error>> {
        PC::setup(max_degree, None, rng).map_err(Error::from_pc_err)
    }

    #[allow(clippy::type_complexity)]
    pub fn keygen(
        srs: &UniversalParams<F, PC>,
        cs: &Composer<F>,
        ks: [F; 4],
    ) -> Result<(ProverKey<F, PC>, VerifierKey<F, PC>), Error<PC::Error>> {
        let index = AHPForPLONK::index(cs, ks)?;
        if srs.max_degree() < index.size() {
            return Err(Error::CircuitTooLarge);
        }

        let (ck, vk) =
            PC::trim(srs, index.size(), 0, None).map_err(Error::from_pc_err)?;
        let (comms, rands) =
            PC::commit(&ck, index.iter(), None).map_err(Error::from_pc_err)?;
        let labels = comms.iter().map(|c| c.label().clone()).collect();
        let comms = comms.iter().map(|c| c.commitment().clone()).collect();

        let vk = VerifierKey {
            comms,
            labels,
            rk: vk,
            info: index.info.clone(),
        };
        let pk = ProverKey {
            vk: vk.clone(),
            index,
            rands,
            ck,
        };

        Ok((pk, vk))
    }

    pub fn prove(
        pk: &ProverKey<F, PC>,
        cs: &Composer<F>,
        zk_rng: &mut dyn RngCore,
    ) -> Result<Proof<F, PC>, Error<PC::Error>> {
        let public_inputs = cs.public_inputs();

        let mut fs_rng = FiatShamirRng::<D>::from_seed(
            &to_bytes![&Self::PROTOCOL_NAME, public_inputs].unwrap(),
        );

        let ps = AHPForPLONK::prover_init(cs, &pk.index)?;
        let vs = AHPForPLONK::verifier_init(&pk.vk.info)?;

        let (ps, first_oracles) = AHPForPLONK::prover_first_round(ps, &cs)?;
        let (first_comms, first_rands) =
            PC::commit(&pk.ck, first_oracles.iter(), Some(zk_rng))
                .map_err(Error::from_pc_err)?;
        fs_rng.absorb(&to_bytes![first_comms].unwrap());
        let (vs, first_msg) =
            AHPForPLONK::verifier_first_round(vs, &mut fs_rng)?;

        let (ps, second_oracles) =
            AHPForPLONK::prover_second_round(ps, &first_msg, &pk.vk.info.ks)?;
        let (second_comms, second_rands) =
            PC::commit(&pk.ck, second_oracles.iter(), Some(zk_rng))
                .map_err(Error::from_pc_err)?;
        fs_rng.absorb(&to_bytes![second_comms].unwrap());
        let (vs, second_msg) =
            AHPForPLONK::verifier_second_round(vs, &mut fs_rng)?;

        let third_oracles =
            AHPForPLONK::prover_third_round(ps, &second_msg, &pk.vk.info.ks)?;
        let (third_comms, third_rands) =
            PC::commit(&pk.ck, third_oracles.iter(), Some(zk_rng))
                .map_err(Error::from_pc_err)?;
        fs_rng.absorb(&to_bytes![third_comms].unwrap());
        let (vs, third_msg) =
            AHPForPLONK::verifier_third_round(vs, &mut fs_rng)?;

        let polynomials: Vec<_> = pk
            .index
            .iter()
            .chain(first_oracles.iter())
            .chain(second_oracles.iter())
            .chain(third_oracles.iter())
            .collect();

        let commitments = vec![
            first_comms.iter().map(|c| c.commitment().clone()).collect(),
            second_comms
                .iter()
                .map(|c| c.commitment().clone())
                .collect(),
            third_comms.iter().map(|c| c.commitment().clone()).collect(),
        ];

        let labeled_commitments: Vec<_> = pk
            .vk
            .comms
            .iter()
            .cloned()
            .zip(pk.vk.labels.iter())
            .map(|(c, l)| LabeledCommitment::new(l.to_string(), c, None))
            .chain(first_comms.iter().cloned())
            .chain(second_comms.iter().cloned())
            .chain(third_comms.iter().cloned())
            .collect();

        let randomnesses: Vec<_> = pk
            .rands
            .iter()
            .chain(first_rands.iter())
            .chain(second_rands.iter())
            .chain(third_rands.iter())
            .collect();

        let qs = AHPForPLONK::verifier_query_set(&vs);
        let lcs = AHPForPLONK::construct_linear_combinations(
            &pk.vk.info,
            &first_msg,
            &second_msg,
            &third_msg,
            &polynomials,
        )?;

        let evaluations: Vec<_> = {
            let mut evals = Vec::new();
            for (label, (_, point)) in &qs {
                let lc = lcs.iter().find(|lc| &lc.label == label).ok_or_else(
                    || Error::MissingEvaluation(label.to_string()),
                )?;
                let eval = polynomials.get_lc_eval(&lc, *point)?;
                evals.push((label.to_string(), eval));
            }
            evals.sort_by(|a, b| a.0.cmp(&b.0));
            evals.into_iter().map(|x| x.1).collect()
        };
        fs_rng.absorb(&evaluations);
        let epsilon = F::rand(&mut fs_rng);

        let pc_proof = PC::open_combinations(
            &pk.ck,
            &lcs,
            polynomials,
            &labeled_commitments,
            &qs,
            epsilon,
            randomnesses,
            Some(zk_rng),
        )
        .map_err(Error::from_pc_err)?;
        let proof = Proof {
            commitments,
            evaluations,
            pc_proof,
        };
        Ok(proof)
    }

    pub fn verify<R: RngCore>(
        vk: &VerifierKey<F, PC>,
        public_inputs: &[F],
        proof: Proof<F, PC>,
        rng: &mut R,
    ) -> Result<bool, Error<PC::Error>> {
        let vs = AHPForPLONK::verifier_init(&vk.info)?;
        let mut fs_rng = FiatShamirRng::<D>::from_seed(
            &to_bytes![&Self::PROTOCOL_NAME, public_inputs].unwrap(),
        );

        let first_comms = &proof.commitments[0];
        fs_rng.absorb(&to_bytes![first_comms].unwrap());
        let (vs, first_msg) =
            AHPForPLONK::verifier_first_round(vs, &mut fs_rng)?;

        let second_comms = &proof.commitments[1];
        fs_rng.absorb(&to_bytes![second_comms].unwrap());
        let (vs, second_msg) =
            AHPForPLONK::verifier_second_round(vs, &mut fs_rng)?;

        let third_comms = &proof.commitments[2];
        fs_rng.absorb(&to_bytes![third_comms].unwrap());
        let (vs, third_msg) =
            AHPForPLONK::verifier_third_round(vs, &mut fs_rng)?;

        let query_set = AHPForPLONK::verifier_query_set(&vs);
        fs_rng.absorb(&proof.evaluations);
        let epsilon = F::rand(&mut fs_rng);

        let evaluations = {
            let mut evaluation_labels: Vec<_> = query_set
                .iter()
                .cloned()
                .map(|(l, (_, p))| (l, p))
                .collect();
            evaluation_labels.sort_by(|a, b| a.0.cmp(&b.0));

            let mut evaluations = Evaluations::new();
            for (q, eval) in
                evaluation_labels.into_iter().zip(&proof.evaluations)
            {
                evaluations.insert(q, *eval);
            }
            evaluations
        };

        if !AHPForPLONK::verifier_equality_check(
            &vs,
            &evaluations,
            public_inputs,
        )? {
            return Ok(false);
        };

        let pc_check = {
            let labels: Vec<_> = vk
                .labels
                .iter()
                .cloned()
                .chain(AHPForPLONK::<F>::LABELS.iter().map(|l| l.to_string()))
                .collect();

            let labeled_commitments: Vec<_> = vk
                .comms
                .iter()
                .cloned()
                .chain(first_comms.iter().cloned())
                .chain(second_comms.iter().cloned())
                .chain(third_comms.iter().cloned())
                .zip(labels.iter())
                .map(|(c, l)| LabeledCommitment::new(l.to_string(), c, None))
                .collect();

            let lcs = AHPForPLONK::construct_linear_combinations(
                &vk.info,
                &first_msg,
                &second_msg,
                &third_msg,
                &evaluations,
            )?;

            PC::check_combinations(
                &vk.rk,
                &lcs,
                &labeled_commitments,
                &query_set,
                &evaluations,
                &proof.pc_proof,
                epsilon,
                rng,
            )
            .map_err(Error::from_pc_err)?
        };
        Ok(pc_check)
    }
}

// #[cfg(test)]
// mod test {
//     use ark_bls12_381::Fr;
//     use ark_ff::{One, Zero};
//     use ark_std::test_rng;

//     use crate::composer::Composer;
//     use crate::Error;

//     use super::prover::Prover;
//     use super::verifier::Verifier;

//     fn run() -> Result<bool, Error> {
//         let ks = [
//             Fr::one(),
//             Fr::from(7_u64),
//             Fr::from(13_u64),
//             Fr::from(17_u64),
//         ];
//         let rng = &mut test_rng();

//         // compose
//         let mut cs = Composer::new();
//         let one = Fr::one();
//         let two = one + one;
//         let three = two + one;
//         let four = two + two;
//         let var_one = cs.alloc_and_assign(one);
//         let var_two = cs.alloc_and_assign(two);
//         let var_three = cs.alloc_and_assign(three);
//         let var_four = cs.alloc_and_assign(four);

//         cs.create_add_gate(
//             (var_one, one),
//             (var_three, one),
//             var_four,
//             None,
//             Fr::zero(),
//             Fr::zero(),
//         );
//         cs.create_add_gate(
//             (var_one, one),
//             (var_two, one),
//             var_three,
//             None,
//             Fr::zero(),
//             Fr::zero(),
//         );
//         cs.constrain_to_constant(var_four, Fr::zero(), -four);
//         println!("size of the circuit: {}", cs.size());

//         // init
//         print!("initializing prover...");
//         let mut p = Prover::init(&cs, ks)?;
//         println!("done");

//         print!("initializing verifier...");
//         let mut v = Verifier::init(&cs)?;
//         println!("done");
//         // first round
//         print!("prover: first round...");
//         let first_oracles = p.first_round(&cs)?;
//         println!("done");

//         print!("verifier: first round...");
//         let first_msg = v.first_round(rng)?;
//         println!("done");

//         // second round
//         print!("prover: second round...");
//         let second_oracles = p.second_round(&first_msg)?;
//         println!("done");

//         print!("verifier: second round...");
//         let second_msg = v.second_round(rng)?;
//         println!("done");

//         // third round
//         print!("prover: third round...");
//         let third_oracles = p.third_round(&second_msg)?;
//         println!("done");

//         print!("verifier: third round...");
//         let third_msg = v.third_round(rng)?;
//         println!("done");

//         // finalize
//         print!("prover: evaluating...");
//         let evals = p.evaluate(
//             &third_msg,
//             &first_oracles,
//             &second_oracles,
//             &third_oracles,
//         );
//         println!("done");

//         print!("verifier: equality checking...");
//         let is_equal = v.check_equality(&evals);
//         println!("done");

//         is_equal
//     }

//     #[test]
//     fn test() {
//         let result = run().unwrap();
//         assert!(result);
//     }
// }

// pub fn evaluate<'a>(
//     &self,
//     third_msg: &ThirdMsg<F>,
//     first_oracles: &FirstOracles<F>,
//     second_oracles: &SecondOracles<F>,
//     third_oracles: &ThirdOracles<F>,
// ) -> Evaluations<F> {
//     let ThirdMsg { zeta } = third_msg;

//     let mut evals = Evaluations::new();
//     // evaluation of [w_0, ..., w_3]
//     let w_zeta: Vec<_> =
//         first_oracles.iter().map(|w| w.evaluate(zeta)).collect();

//     // evaluation of z_shifted
//     let gen = get_generator(self.pk.domain_n());
//     let z_shifted_zeta = second_oracles.z.evaluate(&(gen * zeta));

//     // evaluation of t
//     let t_zeta: F = {
//         let zeta_n = zeta.pow(&[self.size() as u64]);
//         let zeta_2n = zeta_n.square();

//         third_oracles
//             .iter()
//             .zip(vec![F::one(), zeta_n, zeta_2n, zeta_n * zeta_2n])
//             .map(|(p, z)| p.evaluate(zeta) * z)
//             .sum()
//     };

//     let (q_arith_zeta, sigma_0_zeta, sigma_1_zeta, sigma_2_zeta, r_zeta) = {
//         let alpha = &self.alpha.unwrap();
//         let beta = &self.beta.unwrap();
//         let gamma = &self.gamma.unwrap();

//         let arithmetic_key = self.pk.arithmetic_key();
//         let (q_arith_zeta, arith_lin) = arithmetic_key
//             .compute_linearisation(
//                 &w_zeta[0], &w_zeta[1], &w_zeta[2], &w_zeta[3], zeta,
//             );

//         let permutation_key = self.pk.permutation_key();
//         let (sigma_0_zeta, sigma_1_zeta, sigma_2_zeta, perm_lin) =
//             permutation_key.compute_linearisation(
//                 (&w_zeta[0], &w_zeta[1], &w_zeta[2], &w_zeta[3]),
//                 &z_shifted_zeta,
//                 &second_oracles.z.polynomial(),
//                 beta,
//                 gamma,
//                 zeta,
//                 alpha,
//             );

//         (
//             q_arith_zeta,
//             sigma_0_zeta,
//             sigma_1_zeta,
//             sigma_2_zeta,
//             (arith_lin + perm_lin).evaluate(zeta),
//         )
//     };

//     evals.insert("w_0".into(), w_zeta[0]);
//     evals.insert("w_1".into(), w_zeta[1]);
//     evals.insert("w_2".into(), w_zeta[2]);
//     evals.insert("w_3".into(), w_zeta[3]);
//     evals.insert("z_shifted".into(), z_shifted_zeta);
//     evals.insert("q_arith".into(), q_arith_zeta);
//     evals.insert("sigma_0".into(), sigma_0_zeta);
//     evals.insert("sigma_1".into(), sigma_1_zeta);
//     evals.insert("sigma_2".into(), sigma_2_zeta);
//     evals.insert("t".into(), t_zeta);
//     evals.insert("r".into(), r_zeta);

//     evals
// }
