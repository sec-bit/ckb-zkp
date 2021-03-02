use ark_ec::{
    msm::{FixedBaseMSM, VariableBaseMSM},
    PairingEngine, ProjectiveCurve,
};
use ark_ff::{One, PrimeField, Zero};
use ark_poly::Polynomial;
use ark_std::{cfg_iter, vec::Vec, UniformRand};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use core::marker::PhantomData;
use rand::RngCore;

mod data_structures;
pub use data_structures::*;

pub struct KZG10<E: PairingEngine> {
    _engine: PhantomData<E>,
}

impl<E: PairingEngine> KZG10<E> {
    pub fn setup<R: RngCore>(
        max_degree: usize,
        rng: &mut R,
    ) -> Result<UniversalParams<E>, Error> {
        let powers_of_beta = {
            let beta = E::Fr::rand(rng);
            let mut cur = E::Fr::one();
            let mut powers_of_beta = Vec::with_capacity(max_degree + 1);
            for _ in 0..=max_degree {
                powers_of_beta.push(cur);
                cur *= &beta;
            }
            powers_of_beta
        };

        let window_size =
            FixedBaseMSM::get_mul_window_size(max_degree + 1);
        let scalar_bits = E::Fr::size_in_bits();

        let g = E::G1Projective::rand(rng);
        let powers_of_g = {
            let g_table = FixedBaseMSM::get_window_table(
                scalar_bits,
                window_size,
                g,
            );
            let powers_of_p = FixedBaseMSM::multi_scalar_mul(
                scalar_bits,
                window_size,
                &g_table,
                &powers_of_beta,
            );
            E::G1Projective::batch_normalization_into_affine(&powers_of_p)
        };

        Ok(UniversalParams { powers_of_g })
    }

    pub fn trim(
        pp: &UniversalParams<E>,
        degree: usize,
    ) -> Result<CommitterKey<E>, Error> {
        if degree < pp.max_degree() {
            return Err(Error::TrimmingDegreeTooLarge);
        }
        let powers_of_g = pp.powers_of_g[..=degree].to_vec();
        assert_eq!(powers_of_g.len(), degree + 1);

        Ok(CommitterKey { powers_of_g })
    }

    pub fn commit(
        ck: &CommitterKey<E>,
        p: &LabeledPolynomial<E::Fr>,
    ) -> Result<LabeledCommitment<E>, Error> {
        if p.degree() >= ck.degree() {
            return Err(Error::PolynomialDegreeTooLarge);
        }

        let coeffs: Vec<_> = cfg_iter!(p.polynoimal().coeffs)
            .map(|c| c.into_repr())
            .collect();
        let comm =
            VariableBaseMSM::multi_scalar_mul(&ck.powers_of_g, &coeffs);
        Ok(LabeledCommitment {
            label: p.label().into(),
            commitment: Commitment(comm.into()),
        })
    }
}
