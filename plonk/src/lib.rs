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
use ark_poly_commit::{Evaluations, LabeledCommitment, PCUniversalParams, PolynomialCommitment};

use ark_std::{marker::PhantomData, string::ToString, vec, vec::Vec};
use digest::Digest;
use rand_core::RngCore;

mod error;
use error::Error;

mod data_structures;
pub use crate::data_structures::*;

mod composer;
pub use crate::composer::Composer;

mod ahp;
use ahp::{AHPForPLONK, EvaluationsProvider};

mod rng;
use crate::rng::FiatShamirRng;

mod utils;

pub struct Plonk<F: Field, D: Digest, PC: PolynomialCommitment<F, DensePolynomial<F>>> {
    _field: PhantomData<F>,
    _digest: PhantomData<D>,
    _pc: PhantomData<PC>,
}

impl<F: Field, D: Digest, PC: PolynomialCommitment<F, DensePolynomial<F>>> Plonk<F, D, PC> {
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

        let (ck, vk) = PC::trim(srs, index.size(), 0, None).map_err(Error::from_pc_err)?;
        let (comms, rands) = PC::commit(&ck, index.iter(), None).map_err(Error::from_pc_err)?;
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

        let mut fs_rng =
            FiatShamirRng::<D>::from_seed(&to_bytes![&Self::PROTOCOL_NAME, public_inputs].unwrap());

        let ps = AHPForPLONK::prover_init(cs, &pk.index)?;
        let vs = AHPForPLONK::verifier_init(&pk.vk.info)?;

        let (ps, first_oracles) = AHPForPLONK::prover_first_round(ps, &cs)?;
        let (first_comms, first_rands) =
            PC::commit(&pk.ck, first_oracles.iter(), Some(zk_rng)).map_err(Error::from_pc_err)?;
        fs_rng.absorb(&to_bytes![first_comms].unwrap());
        let (vs, first_msg) = AHPForPLONK::verifier_first_round(vs, &mut fs_rng)?;

        let (ps, second_oracles) =
            AHPForPLONK::prover_second_round(ps, &first_msg, &pk.vk.info.ks)?;
        let (second_comms, second_rands) =
            PC::commit(&pk.ck, second_oracles.iter(), Some(zk_rng)).map_err(Error::from_pc_err)?;
        fs_rng.absorb(&to_bytes![second_comms].unwrap());
        let (vs, second_msg) = AHPForPLONK::verifier_second_round(vs, &mut fs_rng)?;

        let third_oracles = AHPForPLONK::prover_third_round(ps, &second_msg, &pk.vk.info.ks)?;
        let (third_comms, third_rands) =
            PC::commit(&pk.ck, third_oracles.iter(), Some(zk_rng)).map_err(Error::from_pc_err)?;
        fs_rng.absorb(&to_bytes![third_comms].unwrap());
        let (vs, third_msg) = AHPForPLONK::verifier_third_round(vs, &mut fs_rng)?;

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
                let lc = lcs
                    .iter()
                    .find(|lc| &lc.label == label)
                    .ok_or_else(|| Error::MissingEvaluation(label.to_string()))?;
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

    pub fn verify(
        vk: &VerifierKey<F, PC>,
        public_inputs: &[F],
        proof: Proof<F, PC>,
    ) -> Result<bool, Error<PC::Error>> {
        let vs = AHPForPLONK::verifier_init(&vk.info)?;
        let mut fs_rng =
            FiatShamirRng::<D>::from_seed(&to_bytes![&Self::PROTOCOL_NAME, public_inputs].unwrap());

        let first_comms = &proof.commitments[0];
        fs_rng.absorb(&to_bytes![first_comms].unwrap());
        let (vs, first_msg) = AHPForPLONK::verifier_first_round(vs, &mut fs_rng)?;

        let second_comms = &proof.commitments[1];
        fs_rng.absorb(&to_bytes![second_comms].unwrap());
        let (vs, second_msg) = AHPForPLONK::verifier_second_round(vs, &mut fs_rng)?;

        let third_comms = &proof.commitments[2];
        fs_rng.absorb(&to_bytes![third_comms].unwrap());
        let (vs, third_msg) = AHPForPLONK::verifier_third_round(vs, &mut fs_rng)?;

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
            for (q, eval) in evaluation_labels.into_iter().zip(&proof.evaluations) {
                evaluations.insert(q, *eval);
            }
            evaluations
        };

        if !AHPForPLONK::verifier_equality_check(&vs, &evaluations, public_inputs)? {
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
                &mut ark_std::test_rng(), // we now impl default rng (not use)
            )
            .map_err(Error::from_pc_err)?
        };
        Ok(pc_check)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::{One, Zero};
    use ark_poly_commit::{marlin_pc::MarlinKZG10, Error as PCError};
    use ark_std::test_rng;

    use blake2::Blake2s;

    use crate::composer::Composer;

    use super::*;

    type PC = MarlinKZG10<Bls12_381, DensePolynomial<Fr>>;
    type PlonkInst = Plonk<Fr, Blake2s, PC>;

    pub fn ks() -> [Fr; 4] {
        [
            Fr::one(),
            Fr::from(7_u64),
            Fr::from(13_u64),
            Fr::from(17_u64),
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

        let var_zero = cs.alloc_and_assign(Fr::zero());
        cs.boolean_gate(var_zero, Fr::zero());
        cs.boolean_gate(var_one, Fr::zero());
        // cs.boolean_gate(var_two, Fr::zero()); // error: when not boolean.

        cs.range_gate(var_zero, 2, Fr::zero()); // 0 in [0, 4)
        cs.range_gate(var_one, 2, Fr::zero()); // 1 in [0, 4)
        cs.range_gate(var_two, 2, Fr::zero()); // 2 in [0, 4)
        cs.range_gate(var_three, 2, Fr::zero()); // 3 in [0, 4)

        // cs.range_gate(var_four, 2, Fr::zero()); // error: four not in [0, 4)
        // cs.range_gate(var_six, 3, Fr::zero()); //error: 3 is not even number.
        cs.range_gate(var_six, 4, Fr::zero()); // six in [0, 16)

        // logic
        let witness_a = cs.alloc_and_assign(Fr::from(500u64));
        let witness_b = cs.alloc_and_assign(Fr::from(357u64));
        let xor_res = cs.xor_gate(witness_a, witness_b, 10);
        cs.constrain_to_constant(xor_res, Fr::from(500u64 ^ 357u64), Fr::zero());

        let witness_a2 = cs.alloc_and_assign(Fr::from(469u64));
        let witness_b2 = cs.alloc_and_assign(Fr::from(321u64));
        let xor_res = cs.and_gate(witness_a2, witness_b2, 10);
        cs.constrain_to_constant(xor_res, Fr::from(469u64 & 321u64), Fr::zero());

        cs
    }

    #[test]
    fn test_plonk() -> Result<(), Error<PCError>> {
        let rng = &mut test_rng();

        // compose
        let cs = circuit();
        let ks = ks();
        println!("size of the circuit: {}", cs.size());

        let srs = PlonkInst::setup(64, rng)?;
        let (pk, vk) = PlonkInst::keygen(&srs, &cs, ks)?;
        let proof = PlonkInst::prove(&pk, &cs, rng)?;
        let result = PlonkInst::verify(&vk, cs.public_inputs(), proof)?;
        assert!(result);
        Ok(())
    }
}
