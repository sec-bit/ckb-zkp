use ark_ff::FftField as Field;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};

use crate::composer::Composer;
use crate::Error;

mod arithmetic;
mod permutation;

pub struct ProverKey<F: Field> {
    n: usize,

    arithmetic: arithmetic::ProverKey<F>,
    permutation: permutation::ProverKey<F>,

    domain_n: GeneralEvaluationDomain<F>,
    domain_4n: GeneralEvaluationDomain<F>,
}

impl<F: Field> Composer<F> {
    pub fn generate_prover_key(&self) -> Result<ProverKey<F>, Error> {
        let (n, selectors) = self.preprocess()?;
        let domain_n = GeneralEvaluationDomain::<F>::new(n)
            .ok_or(Error::PolynomialDegreeTooLarge)?;
        let domain_4n = GeneralEvaluationDomain::<F>::new(4 * n)
            .ok_or(Error::PolynomialDegreeTooLarge)?;

        let q_0_poly = Evaluations::from_vec_and_domain(
            selectors.q_0.clone(),
            domain_n,
        )
        .interpolate();
        let q_1_poly = Evaluations::from_vec_and_domain(
            selectors.q_1.clone(),
            domain_n,
        )
        .interpolate();
        let q_2_poly = Evaluations::from_vec_and_domain(
            selectors.q_2.clone(),
            domain_n,
        )
        .interpolate();
        let q_3_poly = Evaluations::from_vec_and_domain(
            selectors.q_3.clone(),
            domain_n,
        )
        .interpolate();

        let q_m_poly = Evaluations::from_vec_and_domain(
            selectors.q_m.clone(),
            domain_n,
        )
        .interpolate();
        let q_c_poly = Evaluations::from_vec_and_domain(
            selectors.q_c.clone(),
            domain_n,
        )
        .interpolate();

        let q_arith_poly = Evaluations::from_vec_and_domain(
            selectors.q_arith.clone(),
            domain_n,
        )
        .interpolate();

        let sigma_0_poly = Evaluations::from_vec_and_domain(
            selectors.sigma_0.clone(),
            domain_n,
        )
        .interpolate();
        let sigma_1_poly = Evaluations::from_vec_and_domain(
            selectors.sigma_1.clone(),
            domain_n,
        )
        .interpolate();
        let sigma_2_poly = Evaluations::from_vec_and_domain(
            selectors.sigma_2.clone(),
            domain_n,
        )
        .interpolate();
        let sigma_3_poly = Evaluations::from_vec_and_domain(
            selectors.sigma_3.clone(),
            domain_n,
        )
        .interpolate();

        let q_0_evals_ext = domain_4n.fft(&q_0_poly);
        let q_1_evals_ext = domain_4n.fft(&q_1_poly);
        let q_2_evals_ext = domain_4n.fft(&q_2_poly);
        let q_3_evals_ext = domain_4n.fft(&q_3_poly);

        let q_m_evals_ext = domain_4n.fft(&q_m_poly);
        let q_c_evals_ext = domain_4n.fft(&q_c_poly);

        let q_arith_evals_ext = domain_4n.fft(&q_arith_poly);

        let sigma_0_evals_ext = domain_4n.fft(&sigma_0_poly);
        let sigma_1_evals_ext = domain_4n.fft(&sigma_1_poly);
        let sigma_2_evals_ext = domain_4n.fft(&sigma_2_poly);
        let sigma_3_evals_ext = domain_4n.fft(&sigma_3_poly);

        Ok(ProverKey {
            n,
            arithmetic: arithmetic::ProverKey {
                q_0: (q_0_poly, selectors.q_0, q_0_evals_ext),
                q_1: (q_1_poly, selectors.q_1, q_1_evals_ext),
                q_2: (q_2_poly, selectors.q_2, q_2_evals_ext),
                q_3: (q_3_poly, selectors.q_3, q_3_evals_ext),

                q_m: (q_m_poly, selectors.q_m, q_m_evals_ext),
                q_c: (q_c_poly, selectors.q_c, q_c_evals_ext),

                q_arith: (
                    q_arith_poly,
                    selectors.q_arith,
                    q_arith_evals_ext,
                ),
            },
            permutation: permutation::ProverKey {
                sigma_0: (
                    sigma_0_poly,
                    selectors.sigma_0,
                    sigma_0_evals_ext,
                ),
                sigma_1: (
                    sigma_1_poly,
                    selectors.sigma_1,
                    sigma_1_evals_ext,
                ),
                sigma_2: (
                    sigma_2_poly,
                    selectors.sigma_2,
                    sigma_2_evals_ext,
                ),
                sigma_3: (
                    sigma_3_poly,
                    selectors.sigma_3,
                    sigma_3_evals_ext,
                ),
            },
            domain_n,
            domain_4n,
        })
    }
}

impl<F: Field> ProverKey<F> {
    pub fn size(&self) -> usize {
        self.n
    }

    pub fn get_arithmetic_key(&self) -> &arithmetic::ProverKey<F> {
        &self.arithmetic
    }

    pub fn get_permutation_key(&self) -> &permutation::ProverKey<F> {
        &self.permutation
    }
}
