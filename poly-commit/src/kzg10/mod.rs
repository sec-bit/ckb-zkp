use ark_ec::{
    msm::{FixedBaseMSM, VariableBaseMSM},
    AffineCurve, PairingEngine, ProjectiveCurve,
};
use ark_ff::{One, PrimeField};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
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
        let beta = E::Fr::rand(rng);

        let powers_of_beta = {
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

        let h = E::G2Projective::rand(rng);
        let beta_h = h.mul(beta.into());

        Ok(UniversalParams {
            powers_of_g,
            h: h.into_affine(),
            beta_h: beta_h.into_affine(),
        })
    }

    pub fn keygen(
        pp: &UniversalParams<E>,
        degree: usize,
    ) -> Result<(CommitterKey<E>, VerifierKey<E>), Error> {
        if degree < pp.max_degree() {
            return Err(Error::TrimmingDegreeTooLarge);
        }
        let powers_of_g = pp.powers_of_g[..=degree].to_vec();
        assert_eq!(powers_of_g.len(), degree + 1);

        let ck = CommitterKey { powers_of_g };
        let vk = VerifierKey {
            g: pp.powers_of_g[0],
            h: pp.h,
            beta_h: pp.beta_h,
            degree,
        };
        Ok((ck, vk))
    }

    pub fn commit(
        ck: &CommitterKey<E>,
        poly: &DensePolynomial<E::Fr>,
    ) -> Result<Commitment<E>, Error> {
        if poly.degree() > ck.degree() {
            return Err(Error::PolynomialDegreeTooLarge);
        }

        let comm = Self::compute_commitment(ck, poly);
        Ok(Commitment(comm))
    }

    // batch open multiple polynomials at one point
    pub fn open(
        ck: &CommitterKey<E>,
        poly: &DensePolynomial<E::Fr>,
        point: &E::Fr,
    ) -> Result<Proof<E>, Error> {
        if poly.degree() > ck.degree() {
            return Err(Error::PolynomialDegreeTooLarge);
        }
        let w_poly = Self::compute_witness_polynomial(poly, *point);
        let w = Self::compute_commitment(ck, &w_poly);
        Ok(Proof { w })
    }

    pub fn check(
        vk: &VerifierKey<E>,
        comm: &Commitment<E>,
        value: &E::Fr,
        point: &E::Fr,
        proof: &Proof<E>,
    ) -> Result<bool, Error> {
        let u = comm.0.into_projective() - vk.g.mul(*value);
        let v = vk.beta_h.into_projective() - vk.h.mul(*point);
        let lhs = E::pairing(u, vk.h);
        let rhs = E::pairing(proof.w, v);

        Ok(lhs == rhs)
    }

    fn compute_commitment(
        ck: &CommitterKey<E>,
        p: &DensePolynomial<E::Fr>,
    ) -> E::G1Affine {
        let coeffs: Vec<_> =
            cfg_iter!(p.coeffs).map(|c| c.into_repr()).collect();
        let comm =
            VariableBaseMSM::multi_scalar_mul(&ck.powers_of_g, &coeffs);
        comm.into()
    }

    fn compute_witness_polynomial(
        poly: &DensePolynomial<E::Fr>,
        point: E::Fr,
    ) -> DensePolynomial<E::Fr> {
        let divisor = DensePolynomial::from_coefficients_vec(vec![
            -point,
            E::Fr::one(),
        ]);
        poly / &divisor
    }
}
