use ark_ec::{msm::VariableBaseMSM, AffineCurve, ProjectiveCurve};
use ark_ff::{to_bytes, One, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial};
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut, log2, vec::Vec};
use zkp_curve::Curve;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use core::marker::PhantomData;
use digest::Digest;
use rand::RngCore;

mod data_structures;
pub use data_structures::*;

pub struct IPA<C: Curve, D: Digest> {
    _digest: PhantomData<D>,
    _curve: PhantomData<C>,
}

impl<C: Curve, D: Digest> IPA<C, D> {
    pub fn setup<R: RngCore>(
        max_degree: usize,
        _: &mut R,
    ) -> Result<UniversalParams<C>, Error> {
        let max_degree = (max_degree + 1).next_power_of_two() - 1;
        let mut generators = Self::sample_generators(max_degree + 2);
        let u = generators.pop().unwrap();

        Ok(UniversalParams { generators, u })
    }

    pub fn keygen(
        pp: &UniversalParams<C>,
        degree: usize,
    ) -> Result<(CommitterKey<C>, VerifierKey<C>), Error> {
        let degree = (degree + 1).next_power_of_two() - 1;
        if degree < pp.max_degree() {
            return Err(Error::TrimmingDegreeTooLarge);
        }

        let ck = CommitterKey::<C> {
            generators: pp.generators[0..=degree].to_vec(),
            u: pp.u,
        };
        let vk = VerifierKey::<C> {
            generators: pp.generators[0..=degree].to_vec(),
            u: pp.u,
        };
        vk.degree();
        Ok((ck, vk))
    }

    pub fn commit(
        ck: &CommitterKey<C>,
        poly: &DensePolynomial<C::Fr>,
    ) -> Result<Commitment<C>, Error> {
        if poly.degree() > ck.degree() {
            return Err(Error::PolynomialDegreeTooLarge);
        }
        let comm = Self::compute_commitment(&ck.generators, &poly.coeffs);
        Ok(Commitment(comm))
    }

    pub fn open(
        ck: &CommitterKey<C>,
        poly: &DensePolynomial<C::Fr>,
        point: &C::Fr,
        rng: Option<&mut RngCore>,
    ) -> Result<Proof<C>, Error> {
        if poly.degree() > ck.degree() {
            return Err(Error::PolynomialDegreeTooLarge);
        }

        let mut coeffs = {
            let mut coeffs = poly.coeffs.to_vec();
            let diff = ck.degree() - poly.degree();
            coeffs.extend(vec![C::Fr::zero(); diff]);
            coeffs
        };
        let mut coeffs = coeffs.as_mut_slice();

        let mut points: Vec<_> = {
            let mut curr = C::Fr::one();
            (0..=coeffs.len())
                .map(|_| {
                    let tmp = curr;
                    curr *= point;
                    tmp
                })
                .collect()
        };
        let mut points = points.as_mut_slice();
        let mut gens = ck.generators.clone();
        let u = &ck.u;

        let mut n = coeffs.len();
        let log_n = log2(n) as usize;
        let mut vec_l = Vec::with_capacity(log_n);
        let mut vec_r = Vec::with_capacity(log_n);

        while n > 1 {
            n /= 2;
            let (coeffs_l, coeffs_r) = coeffs.split_at_mut(n);
            let (points_l, points_r) = points.split_at_mut(n);
            let (gens_l, gens_r) = gens.split_at_mut(n);
            let l = Self::compute_commitment(gens_r, coeffs_l)
                + u.mul(Self::compute_inner_product(points_r, coeffs_l))
                    .into();
            let r = Self::compute_commitment(gens_l, coeffs_r)
                + u.mul(Self::compute_inner_product(points_l, coeffs_r))
                    .into();
            vec_l.push(l);
            vec_r.push(r);

            coeffs = {
                cfg_iter_mut!(coeffs_l)
                    .zip(coeffs_r)
                    .for_each(|(l, r)| *l += *r);
                coeffs_l
            };
            points = {
                cfg_iter_mut!(points_l)
                    .zip(points_r)
                    .for_each(|(l, r)| *l += *r);
                points_l
            }
        }
        Err(Error::Other)
    }

    fn compute_commitment(g: &[C::Affine], f: &[C::Fr]) -> C::Affine {
        let f: Vec<_> = cfg_iter!(f).map(|f| f.into_repr()).collect();
        let comm = VariableBaseMSM::multi_scalar_mul(g, &f);
        comm.into()
    }

    fn sample_generators(num: usize) -> Vec<C::Affine> {
        let generators: Vec<_> = cfg_into_iter!(0..num)
            .map(|i| {
                let i = i as u64;
                let mut seed = D::digest(&to_bytes![i].unwrap());

                let mut g = C::Affine::from_random_bytes(&seed);
                let mut j = 0u64;
                while g.is_none() {
                    seed = D::digest(&to_bytes![i, j].unwrap());
                    g = C::Affine::from_random_bytes(&seed);
                    j += 1;
                }
                let generator = g.unwrap();
                generator.mul_by_cofactor_to_projective()
            })
            .collect();

        C::Projective::batch_normalization_into_affine(&generators)
    }

    fn compute_inner_product(l: &[C::Fr], r: &[C::Fr]) -> C::Fr {
        assert!(l.len() == r.len());
        cfg_iter!(l).zip(r).map(|(l, r)| *l * r).sum()
    }
}
