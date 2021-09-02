use ark_ff::FftField as Field;
use ark_poly::{EvaluationDomain, Evaluations as EvaluationsOnDomain, GeneralEvaluationDomain};
use ark_serialize::*;
use ark_std::{cfg_into_iter, io, vec, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::ahp::{AHPForPLONK, Error};
use crate::composer::{Composer, Error as CSError, Selectors};
use crate::data_structures::LabeledPolynomial;
use crate::utils::{first_lagrange_poly, to_labeled, vanishing_poly};

mod arithmetic;
pub use arithmetic::ArithmeticKey;
mod permutation;
mod mimc;
pub use mimc::MimcKey;

pub use permutation::PermutationKey;
use ark_poly_commit::LinearCombination;
//use crate::ahp::indexer::mimc::MimcKey;

pub struct Index<F: Field> {
    pub info: IndexInfo<F>,

    arithmetic: ArithmeticKey<F>,
    permutation: PermutationKey<F>,

    domain_4n: GeneralEvaluationDomain<F>,
    v_4n_inversed: Vec<F>,

    q_range_key: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    mimc: MimcKey<F>,
}

#[derive(Debug, Clone)]
pub struct IndexInfo<F: Field> {
    pub n: usize,
    pub ks: [F; 4],
    pub domain_n: GeneralEvaluationDomain<F>,
}

impl<F: Field> CanonicalSerialize for IndexInfo<F> {
    #[inline]
    fn serialize<W: io::Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.n.serialize(&mut writer)?;
        self.ks[0].serialize(&mut writer)?;
        self.ks[1].serialize(&mut writer)?;
        self.ks[2].serialize(&mut writer)?;
        self.ks[3].serialize(&mut writer)?;
        self.domain_n.serialize(&mut writer)
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        self.n.serialized_size()
            + self.ks[0].serialized_size() * 4
            + self.domain_n.serialized_size()
    }

    #[inline]
    fn serialize_uncompressed<W: io::Write>(
        &self,
        mut writer: W,
    ) -> Result<(), SerializationError> {
        self.n.serialize_uncompressed(&mut writer)?;
        self.ks[0].serialize_uncompressed(&mut writer)?;
        self.ks[1].serialize_uncompressed(&mut writer)?;
        self.ks[2].serialize_uncompressed(&mut writer)?;
        self.ks[3].serialize_uncompressed(&mut writer)?;
        self.domain_n.serialize_uncompressed(&mut writer)
    }

    #[inline]
    fn serialize_unchecked<W: io::Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.n.serialize_unchecked(&mut writer)?;
        self.ks[0].serialize_unchecked(&mut writer)?;
        self.ks[1].serialize_unchecked(&mut writer)?;
        self.ks[2].serialize_unchecked(&mut writer)?;
        self.ks[3].serialize_unchecked(&mut writer)?;
        self.domain_n.serialize_unchecked(&mut writer)
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        self.n.uncompressed_size()
            + self.ks[0].uncompressed_size() * 4
            + self.domain_n.uncompressed_size()
    }
}

impl<F: Field> CanonicalDeserialize for IndexInfo<F> {
    #[inline]
    fn deserialize<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let n = usize::deserialize(&mut reader)?;

        let mut ks = [F::zero(); 4];
        let mut vks: Vec<F> = vec![];
        vks.push(F::deserialize(&mut reader)?);
        vks.push(F::deserialize(&mut reader)?);
        vks.push(F::deserialize(&mut reader)?);
        vks.push(F::deserialize(&mut reader)?);
        ks.copy_from_slice(&vks[..]);

        let domain_n = GeneralEvaluationDomain::<F>::deserialize(&mut reader)?;

        Ok(IndexInfo { n, ks, domain_n })
    }

    #[inline]
    fn deserialize_uncompressed<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let n = usize::deserialize_uncompressed(&mut reader)?;

        let mut ks = [F::zero(); 4];
        let mut vks: Vec<F> = vec![];
        vks.push(F::deserialize_uncompressed(&mut reader)?);
        vks.push(F::deserialize_uncompressed(&mut reader)?);
        vks.push(F::deserialize_uncompressed(&mut reader)?);
        vks.push(F::deserialize_uncompressed(&mut reader)?);
        ks.copy_from_slice(&vks[..]);

        let domain_n = GeneralEvaluationDomain::<F>::deserialize_uncompressed(&mut reader)?;

        Ok(IndexInfo { n, ks, domain_n })
    }

    #[inline]
    fn deserialize_unchecked<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let n = usize::deserialize_unchecked(&mut reader)?;

        let mut ks = [F::zero(); 4];
        let mut vks: Vec<F> = vec![];
        vks.push(F::deserialize_unchecked(&mut reader)?);
        vks.push(F::deserialize_unchecked(&mut reader)?);
        vks.push(F::deserialize_unchecked(&mut reader)?);
        vks.push(F::deserialize_unchecked(&mut reader)?);
        ks.copy_from_slice(&vks[..]);

        let domain_n = GeneralEvaluationDomain::<F>::deserialize_unchecked(&mut reader)?;

        Ok(IndexInfo { n, ks, domain_n })
    }
}

impl<F: Field> AHPForPLONK<F> {
    pub fn index(cs: &Composer<F>, ks: [F; 4]) -> Result<Index<F>, Error> {
        let selectors = cs.compose(&ks)?;
        let n = selectors.size();
        selectors.iter().for_each(|s| assert_eq!(s.len(), n));

        let Selectors {
            q_0,
            q_1,
            q_2,
            q_3,
            q_m,
            q_c,
            q_arith,
            sigma_0,
            sigma_1,
            sigma_2,
            sigma_3,
            q_range,
            q_mimc,
            //q_mimc_c,
            ..
        } = selectors;

        let domain_n =
            GeneralEvaluationDomain::<F>::new(n).ok_or(CSError::PolynomialDegreeTooLarge)?;
        let domain_4n =
            GeneralEvaluationDomain::<F>::new(4 * n).ok_or(CSError::PolynomialDegreeTooLarge)?;

        let q_0_poly = to_labeled(
            "q_0",
            EvaluationsOnDomain::from_vec_and_domain(q_0.clone(), domain_n).interpolate(),
        );
        let q_1_poly = to_labeled(
            "q_1",
            EvaluationsOnDomain::from_vec_and_domain(q_1.clone(), domain_n).interpolate(),
        );
        let q_2_poly = to_labeled(
            "q_2",
            EvaluationsOnDomain::from_vec_and_domain(q_2.clone(), domain_n).interpolate(),
        );
        let q_3_poly = to_labeled(
            "q_3",
            EvaluationsOnDomain::from_vec_and_domain(q_3.clone(), domain_n).interpolate(),
        );
        let q_m_poly = to_labeled(
            "q_m",
            EvaluationsOnDomain::from_vec_and_domain(q_m.clone(), domain_n).interpolate(),
        );
        let q_c_poly = to_labeled(
            "q_c",
            EvaluationsOnDomain::from_vec_and_domain(q_c.clone(), domain_n).interpolate(),
        );
        let q_arith_poly = to_labeled(
            "q_arith",
            EvaluationsOnDomain::from_vec_and_domain(q_arith.clone(), domain_n).interpolate(),
        );

        let sigma_0_poly = to_labeled(
            "sigma_0",
            EvaluationsOnDomain::from_vec_and_domain(sigma_0.clone(), domain_n).interpolate(),
        );
        let sigma_1_poly = to_labeled(
            "sigma_1",
            EvaluationsOnDomain::from_vec_and_domain(sigma_1.clone(), domain_n).interpolate(),
        );
        let sigma_2_poly = to_labeled(
            "sigma_2",
            EvaluationsOnDomain::from_vec_and_domain(sigma_2.clone(), domain_n).interpolate(),
        );
        let sigma_3_poly = to_labeled(
            "sigma_3",
            EvaluationsOnDomain::from_vec_and_domain(sigma_3.clone(), domain_n).interpolate(),
        );
        let q_range_poly = to_labeled(
            "q_range",
            EvaluationsOnDomain::from_vec_and_domain(q_range.clone(), domain_n).interpolate(),
        );
        let q_mimc_poly = to_labeled(
            "q_mimc",
            EvaluationsOnDomain::from_vec_and_domain(q_mimc.clone(), domain_n).interpolate(),
        );
        // let q_mimc_c_poly = to_labeled(
        //     "q_mimc_c",
        //     EvaluationsOnDomain::from_vec_and_domain(q_mimc_c.clone(), domain_n).interpolate(),
        // );

        let q_0_4n = domain_4n.coset_fft(&q_0_poly);
        let q_1_4n = domain_4n.coset_fft(&q_1_poly);
        let q_2_4n = domain_4n.coset_fft(&q_2_poly);
        let q_3_4n = domain_4n.coset_fft(&q_3_poly);
        let q_m_4n = domain_4n.coset_fft(&q_m_poly);
        let q_c_4n = domain_4n.coset_fft(&q_c_poly);
        let q_arith_4n = domain_4n.coset_fft(&q_arith_poly);

        let sigma_0_4n = domain_4n.coset_fft(&sigma_0_poly);
        let sigma_1_4n = domain_4n.coset_fft(&sigma_1_poly);
        let sigma_2_4n = domain_4n.coset_fft(&sigma_2_poly);
        let sigma_3_4n = domain_4n.coset_fft(&sigma_3_poly);

        let q_range_4n = domain_4n.coset_fft(&q_range_poly);
        let q_mimc_4n = domain_4n.coset_fft(&q_mimc_poly);
        //let q_mimc_c_4n = domain_4n.coset_fft(&q_mimc_c_poly);

        let v_poly = vanishing_poly(domain_n);
        let v_4n = domain_4n.coset_fft(&v_poly);
        let v_4n_inversed: Vec<_> = cfg_into_iter!(v_4n).map(|v| v.inverse().unwrap()).collect();

        let l1_poly = first_lagrange_poly(domain_n);
        let l1_4n = domain_4n.coset_fft(&l1_poly);

        Ok(Index {
            info: IndexInfo { n, ks, domain_n },

            domain_4n,

            v_4n_inversed,

            arithmetic: ArithmeticKey {
                q_0: (q_0_poly, q_0, q_0_4n),
                q_1: (q_1_poly, q_1, q_1_4n),
                q_2: (q_2_poly, q_2, q_2_4n),
                q_3: (q_3_poly, q_3, q_3_4n),

                q_m: (q_m_poly, q_m, q_m_4n),
                q_c: (q_c_poly, q_c, q_c_4n),

                q_arith: (q_arith_poly, q_arith, q_arith_4n),
            },
            permutation: PermutationKey {
                sigma_0: (sigma_0_poly, sigma_0, sigma_0_4n),
                sigma_1: (sigma_1_poly, sigma_1, sigma_1_4n),
                sigma_2: (sigma_2_poly, sigma_2, sigma_2_4n),
                sigma_3: (sigma_3_poly, sigma_3, sigma_3_4n),
                l1_4n,
            },
            q_range_key: (q_range_poly, q_range, q_range_4n),
            mimc: MimcKey {
                q_mimc: (q_mimc_poly, q_mimc, q_mimc_4n),
                //q_mimc_c: (q_mimc_c_poly, q_mimc_c, q_mimc_c_4n),
            },
        })
    }
}

impl<F: Field> Index<F> {
    //加上range,mimc到末尾
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        self.arithmetic.iter()
            .chain(self.permutation.iter())
            .chain(vec![&self.q_range_key.0].into_iter())
            .chain(self.mimc.iter())
    }

    pub fn size(&self) -> usize {
        self.info.n
    }

    pub fn domain_n(&self) -> impl EvaluationDomain<F> {
        self.info.domain_n
    }

    pub(super) fn domain_4n(&self) -> impl EvaluationDomain<F> {
        self.domain_4n
    }

    pub(super) fn v_4n_inversed(&self) -> &[F] {
        &self.v_4n_inversed
    }

    pub fn arithmetic_key(&self) -> &ArithmeticKey<F> {
        &self.arithmetic
    }

    pub fn permutation_key(&self) -> &PermutationKey<F> {
        &self.permutation
    }

    pub fn mimc_key(&self) -> &MimcKey<F> {
        &self.mimc
    }

    pub fn q_range_key(&self) -> &(LabeledPolynomial<F>, Vec<F>, Vec<F>) {
        &self.q_range_key
    }

    //range放后面，也就是alpha从 3次方开始，到6次方
    //t的一部分
    pub fn compute_quotient_q_range(
        &self,
        domain_4n: impl EvaluationDomain<F> + Sync,
        w_4n: (&[F], &[F], &[F], &[F]),
        alpha: &F,
    ) -> Vec<F> {
        let alpha_2 = alpha.square();
        let alpha_3: F = alpha_2 * alpha;
        let alpha_4 = alpha_2.square();

        let (w_0_4n, w_1_4n, w_2_4n, w_3_4n) = w_4n;
        let size = domain_4n.size();
        let q_range_2 = &self.q_range_key.2;
        let two: F = F::one() + F::one();
        let three: F = two + F::one();
        let four: F = two + two;

        cfg_into_iter!((0..size))
            .map(|i| {
                let next = if i / 4 == (size / 4 - 1) {
                    i % 4
                } else {
                    i + 4
                };
                if q_range_2[i].is_zero() {
                    F::zero()
                } else {
                    q_range_2[i] * alpha_2 * (
                        *alpha * (w_0_4n[next] - four * w_3_4n[i]) * (w_0_4n[next] - four * w_3_4n[i] - F::one()) * (w_0_4n[next] - four * w_3_4n[i] - two) * (w_0_4n[next] - four * w_3_4n[i] - three)
                      + alpha_2 * (w_3_4n[i] - four * w_2_4n[i]) * (w_3_4n[i] - four * w_2_4n[i] - F::one()) * (w_3_4n[i] - four * w_2_4n[i] - two) * (w_3_4n[i] - four * w_2_4n[i] - three)
                      + alpha_3 * (w_2_4n[i] - four * w_1_4n[i]) * (w_2_4n[i] - four * w_1_4n[i] - F::one()) * (w_2_4n[i] - four * w_1_4n[i] - two) * (w_2_4n[i] - four * w_1_4n[i] - three)
                      + alpha_4 * (w_1_4n[i] - four * w_0_4n[i]) * (w_1_4n[i] - four * w_0_4n[i] - F::one()) * (w_1_4n[i] - four * w_0_4n[i] - two) * (w_1_4n[i] - four * w_0_4n[i] - three)
                    )
                }
            })
            .collect()
    }

    pub(crate) fn construct_linear_combination_q_range(
        w_zeta: (F, F, F, F),
        w_0_shifted_zeta: F,
        alpha: F,
    ) -> LinearCombination<F> {
        let (w_0, w_1, w_2, w_3) = w_zeta;

        let two: F = F::one() + F::one();
        let three: F = two + F::one();
        let four: F = two + two;

        let D_1: F = (w_0_shifted_zeta - four * w_3)
            * (w_0_shifted_zeta - four * w_3 - F::one())
            * (w_0_shifted_zeta - four * w_3 - two)
            * (w_0_shifted_zeta - four * w_3 - three);
        let D_2: F = (w_3 - four * w_2)
            * (w_3 - four * w_2 - F::one())
            * (w_3 - four * w_2 - two)
            * (w_3 - four * w_2 - three);
        let D_3: F = (w_2 - four * w_1)
            * (w_2 - four * w_1 - F::one())
            * (w_2 - four * w_1 - two)
            * (w_2 - four * w_1 - three);
        let D_4: F = (w_1 - four * w_0)
            * (w_1 - four * w_0 - F::one())
            * (w_1 - four * w_0 - two)
            * (w_1 - four * w_0 - three);


        let alpha_2 = alpha.square();
        let alpha_3: F = alpha_2 * alpha;
        let alpha_4 = alpha_2.square();
        LinearCombination::new(
            "range",
            vec![
                ((alpha * D_1 + alpha_2 * D_2 + alpha_3 * D_3 + alpha_4 * D_4) * alpha_2,
                 "q_range"),
            ],
        )
    }

}
