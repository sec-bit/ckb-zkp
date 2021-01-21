use ark_ec::{
    msm::{FixedBaseMSM, VariableBaseMSM},
    AffineCurve, PairingEngine, ProjectiveCurve,
};
use ark_ff::{One, PrimeField};
use ark_poly::polynomial::univariate::DensePolynomial as Polynomial;
use ark_std::{cfg_iter, UniformRand};
use core::marker::PhantomData;
use rand::RngCore;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::pc::data_structures::*;
use crate::Vec;

/// KZG10 implements KZG10 polynomial commitment scheme,
/// which optionally enables hiding following Marlin's specification
pub struct KZG10<E: PairingEngine> {
    _engine: PhantomData<E>,
}

impl<E: PairingEngine> KZG10<E> {
    pub fn setup<R: RngCore>(max_degree: usize, rng: &mut R) -> Result<UniversalParams<E>, Error> {
        let beta = E::Fr::rand(rng);
        let g = E::G1Projective::rand(rng);
        let gamma_g = E::G1Projective::rand(rng);
        let h = E::G2Projective::rand(rng);

        let mut powers_of_beta = vec![E::Fr::one()];
        let mut cur = beta;
        for _ in 0..max_degree {
            powers_of_beta.push(cur);
            cur *= &beta;
        }

        let window_size = FixedBaseMSM::get_mul_window_size(max_degree + 1);
        let scalar_bits = E::Fr::size_in_bits();
        let g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, g);
        let powers_of_g =
            FixedBaseMSM::multi_scalar_mul(scalar_bits, window_size, &g_table, &powers_of_beta);

        let gamma_g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, gamma_g);
        let powers_of_gamma_g = FixedBaseMSM::multi_scalar_mul(
            scalar_bits,
            window_size,
            &gamma_g_table,
            &powers_of_beta,
        );

        let powers_of_g = E::G1Projective::batch_normalization_into_affine(&powers_of_g);
        let powers_of_gamma_g =
            E::G1Projective::batch_normalization_into_affine(&powers_of_gamma_g);

        let beta_h = h.mul(beta).into_affine();
        let h = h.into_affine();
        let prepared_h = h.into();
        let prepared_beta_h = beta_h.into();

        let pp = UniversalParams {
            powers_of_g,
            powers_of_gamma_g,
            h,
            beta_h,
            prepared_h,
            prepared_beta_h,
        };
        Ok(pp)
    }

    pub fn trim(
        pp: &UniversalParams<E>,
        supported_degree: usize,
    ) -> Result<(CommitterKey<E>, VerifierKey<E>), Error> {
        let max_degree = pp.max_degree();
        if supported_degree > max_degree {
            return Err(Error::TrimmingDegreeTooLarge);
        }
        let powers_of_g = pp.powers_of_g[..=supported_degree].to_vec();
        let powers_of_gamma_g = pp.powers_of_gamma_g[..=supported_degree].to_vec();
        let vk = VerifierKey::<E> {
            g: powers_of_g[0],
            gamma_g: powers_of_gamma_g[0],
            h: pp.h,
            beta_h: pp.beta_h,
            supported_degree,
        };

        let ck = CommitterKey::<E> {
            powers_of_g,
            powers_of_gamma_g,
            supported_degree,
        };
        Ok((ck, vk))
    }

    pub fn commit<R: RngCore>(
        ck: &Powers<E>,
        p: &Polynomial<E::Fr>,
        hiding_bound: Option<usize>,
        rng: Option<&mut R>,
    ) -> Result<(Comm<E>, Rand<E::Fr>), Error> {
        Self::check_degree_is_within_bounds(p.degree(), ck.supported_degree())?;
        let (num_leading_zeros, coeffs) = Self::skip_leading_zeros_and_convert_to_bigints(p);
        let mut comm =
            VariableBaseMSM::multi_scalar_mul(&ck.powers_of_g[num_leading_zeros..], &coeffs);

        let mut rand = Rand::<E::Fr>::empty();
        if let Some(hiding_degree) = hiding_bound {
            let mut rng = rng.ok_or(Error::MissingRng)?;
            Self::check_hiding_bound(hiding_degree, ck.size())?;
            rand = Rand::rand(hiding_degree, &mut rng);
            let rand_coeffs = Self::convert_to_bigints(&rand.blinding_polynomial.coeffs);
            let rand_commitment =
                VariableBaseMSM::multi_scalar_mul(&ck.powers_of_gamma_g, &rand_coeffs)
                    .into_affine();
            comm.add_assign_mixed(&rand_commitment);
        }
        Ok((Comm(comm.into()), rand))
    }

    pub fn open(
        ck: &Powers<E>,
        p: &Polynomial<E::Fr>,
        point: E::Fr,
        rand: &Rand<E::Fr>,
    ) -> Result<Proof<E>, Error> {
        let max_degree = ck.powers_of_g.len();
        Self::check_degree_is_within_bounds(p.degree(), max_degree)?;

        let (poly, rand_poly) = Self::compute_witness_polynomial(p, point, rand);
        let (num_leading_zeros, witness_coeffs) =
            Self::skip_leading_zeros_and_convert_to_bigints(&poly);
        let mut w = VariableBaseMSM::multi_scalar_mul(
            &ck.powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        );

        let rand_v = if let Some(rand_poly) = rand_poly {
            let blinding_evaluation = rand.blinding_polynomial.evaluate(point);
            let blinding_witness_coeffs = Self::convert_to_bigints(&rand_poly.coeffs);
            w +=
                &VariableBaseMSM::multi_scalar_mul(&ck.powers_of_gamma_g, &blinding_witness_coeffs);
            Some(blinding_evaluation)
        } else {
            None
        };

        Ok(Proof {
            w: w.into_affine(),
            rand_v,
        })
    }

    pub fn check(
        vk: &VerifierKey<E>,
        comm: &Comm<E>,
        point: E::Fr,
        value: E::Fr,
        proof: &Proof<E>,
    ) -> Result<bool, Error> {
        let mut u = comm.0.into_projective() - &(vk.g).mul(value);
        if let Some(rand_v) = proof.rand_v {
            u -= &vk.gamma_g.mul(rand_v);
        }
        let v = vk.beta_h.into_projective() - &(vk.h).mul(point);
        let lhs = E::pairing(u, vk.h);
        let rhs = E::pairing(proof.w, v);
        Ok(lhs == rhs)
    }

    fn check_degree_is_within_bounds(degree: usize, powers: usize) -> Result<(), Error> {
        if degree < 1 {
            Err(Error::DegreeIsZero)
        } else if degree > powers {
            Err(Error::DegreeOutOfBound)
        } else {
            Ok(())
        }
    }

    fn skip_leading_zeros_and_convert_to_bigints<F: PrimeField>(
        p: &Polynomial<F>,
    ) -> (usize, Vec<F::BigInt>) {
        let mut num_leading_zeros = 0;
        while p.coeffs[num_leading_zeros].is_zero() && num_leading_zeros < p.coeffs.len() {
            num_leading_zeros += 1;
        }
        let coeffs = Self::convert_to_bigints(&p.coeffs[num_leading_zeros..]);
        (num_leading_zeros, coeffs)
    }

    fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
        let coeffs = cfg_iter!(p).map(|s| s.into_repr()).collect();
        coeffs
    }

    fn check_hiding_bound(hiding_bound: usize, hiding_powers: usize) -> Result<(), Error> {
        if hiding_bound == 0 {
            Err(Error::HidingBoundIsZero)
        } else if hiding_bound > hiding_powers {
            Err(Error::HidingBoundTooLarge)
        } else {
            Ok(())
        }
    }

    fn compute_witness_polynomial(
        p: &Polynomial<E::Fr>,
        point: E::Fr,
        rand: &Rand<E::Fr>,
    ) -> (Polynomial<E::Fr>, Option<Polynomial<E::Fr>>) {
        let divisor = Polynomial::from_coefficients_vec(vec![-point, E::Fr::one()]);
        let witness_polynomial = p / &divisor;

        let hiding_witness_polynomial = if rand.is_hiding() {
            let rand_p = &rand.blinding_polynomial / &divisor;
            Some(rand_p)
        } else {
            None
        };
        (witness_polynomial, hiding_witness_polynomial)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    fn kzg10_template<E: PairingEngine>() -> Result<(), Error> {
        let rng = &mut test_rng();

        let degree = loop {
            let degree = usize::rand(rng) % 20;
            if degree >= 2 {
                break degree;
            }
        };

        let pp = KZG10::<E>::setup(degree, rng)?;
        let (ck, vk) = KZG10::<E>::trim(&pp, degree / 2)?;
        let p = loop {
            let p = Polynomial::rand(degree / 2, rng);
            if p.degree() > 0 {
                break p;
            }
        };
        let hiding_bound = Some(1);
        let powers = ck.powers();
        let (c, r) = KZG10::<E>::commit(&powers, &p, hiding_bound, Some(rng))?;
        let point = E::Fr::rand(rng);
        let value = p.evaluate(point);
        let proof = KZG10::<E>::open(&powers, &p, point, &r)?;
        assert!(KZG10::<E>::check(&vk, &c, point, value, &proof)?);

        Ok(())
    }

    #[test]
    fn kzg10_test() {
        for _ in 0..20 {
            kzg10_template::<Bls12_381>().expect("test failed for Bls12_381");
        }
    }
}
