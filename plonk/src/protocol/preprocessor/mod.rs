use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial as Polynomial, EvaluationDomain, Evaluations,
    GeneralEvaluationDomain, UVPolynomial,
};
use ark_std::cfg_into_iter;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::composer::{Composer, Error as CSError, Selectors};
use crate::data_structures::LabeledPolynomial;
use crate::protocol::Error;

mod arithmetic;
pub use arithmetic::ArithmeticKey;
mod permutation;
pub use permutation::PermutationKey;

pub struct PreprocessorKeys<F: Field> {
    pub info: PreprocessorInfo<F>,

    domain_4n: GeneralEvaluationDomain<F>,
    v_4n_inversed: Vec<F>,

    arithmetic: ArithmeticKey<F>,
    permutation: PermutationKey<F>,
}

#[derive(Debug, Clone)]
pub struct PreprocessorInfo<F: Field> {
    pub n: usize,
    pub k: [F; 4],
    pub domain_n: GeneralEvaluationDomain<F>,
}

impl<F: Field> PreprocessorKeys<F> {
    pub fn generate(
        cs: &Composer<F>,
        k: [F; 4],
    ) -> Result<PreprocessorKeys<F>, Error> {
        let selectors = cs.process(&k)?;
        let n = selectors.size();
        selectors.iter().for_each(|s| assert_eq!(s.len(), n));
        println!("selector size: {}", n);

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
            ..
        } = selectors;

        let domain_n = GeneralEvaluationDomain::<F>::new(n)
            .ok_or(CSError::PolynomialDegreeTooLarge)?;
        let domain_4n = GeneralEvaluationDomain::<F>::new(4 * n)
            .ok_or(CSError::PolynomialDegreeTooLarge)?;

        let q_0_poly = LabeledPolynomial::new(
            "q_0".into(),
            Evaluations::from_vec_and_domain(q_0.clone(), domain_n)
                .interpolate(),
            None,
            None,
        );
        let q_1_poly = LabeledPolynomial::new(
            "q_1".into(),
            Evaluations::from_vec_and_domain(q_1.clone(), domain_n)
                .interpolate(),
            None,
            None,
        );
        let q_2_poly = LabeledPolynomial::new(
            "q_2".into(),
            Evaluations::from_vec_and_domain(q_2.clone(), domain_n)
                .interpolate(),
            None,
            None,
        );
        let q_3_poly = LabeledPolynomial::new(
            "q_3".into(),
            Evaluations::from_vec_and_domain(q_3.clone(), domain_n)
                .interpolate(),
            None,
            None,
        );
        let q_m_poly = LabeledPolynomial::new(
            "q_m".into(),
            Evaluations::from_vec_and_domain(q_m.clone(), domain_n)
                .interpolate(),
            None,
            None,
        );
        let q_c_poly = LabeledPolynomial::new(
            "q_c".into(),
            Evaluations::from_vec_and_domain(q_c.clone(), domain_n)
                .interpolate(),
            None,
            None,
        );
        let q_arith_poly = LabeledPolynomial::new(
            "q_arith".into(),
            Evaluations::from_vec_and_domain(q_arith.clone(), domain_n)
                .interpolate(),
            None,
            None,
        );

        let sigma_0_poly = LabeledPolynomial::new(
            "sigma_0".into(),
            Evaluations::from_vec_and_domain(sigma_0.clone(), domain_n)
                .interpolate(),
            None,
            None,
        );
        let sigma_1_poly = LabeledPolynomial::new(
            "sigma_1".into(),
            Evaluations::from_vec_and_domain(sigma_1.clone(), domain_n)
                .interpolate(),
            None,
            None,
        );
        let sigma_2_poly = LabeledPolynomial::new(
            "sigma_2".into(),
            Evaluations::from_vec_and_domain(sigma_2.clone(), domain_n)
                .interpolate(),
            None,
            None,
        );
        let sigma_3_poly = LabeledPolynomial::new(
            "sigma_3".into(),
            Evaluations::from_vec_and_domain(sigma_3.clone(), domain_n)
                .interpolate(),
            None,
            None,
        );

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

        let v_poly = vanishing_poly(domain_n);
        let v_4n = domain_4n.coset_fft(&v_poly);
        let v_4n_inversed: Vec<_> =
            cfg_into_iter!(v_4n).map(|v| v.inverse().unwrap()).collect();

        Ok(PreprocessorKeys {
            info: PreprocessorInfo { n, k, domain_n },

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
            },
        })
    }
}

impl<F: Field> PreprocessorKeys<F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        self.arithmetic.iter().chain(self.permutation.iter())
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
}

fn vanishing_poly<F: Field>(domain: impl EvaluationDomain<F>) -> Polynomial<F> {
    let size = domain.size();
    let mut coeffs = vec![F::zero(); size + 1];
    coeffs[0] = -F::one();
    coeffs[size] = F::one();
    Polynomial::from_coefficients_vec(coeffs)
}
