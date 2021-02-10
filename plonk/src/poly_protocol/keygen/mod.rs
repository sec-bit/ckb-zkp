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
}

impl<F: Field> Composer<F> {
    pub fn generate_prover_key(&self) -> Result<ProverKey<F>, Error> {
        let (n, selectors) = self.preprocess()?;

        let domain_4n = GeneralEvaluationDomain::<F>::new(4 * n)
            .ok_or(Error::PolynomialDegreeTooLarge)?;
        let q_0_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&selectors.q_0),
            domain_4n,
        );
        let q_1_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&selectors.q_1),
            domain_4n,
        );
        let q_2_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&selectors.q_2),
            domain_4n,
        );
        let q_3_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&selectors.q_3),
            domain_4n,
        );

        let q_m_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&selectors.q_m),
            domain_4n,
        );
        let q_c_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&selectors.q_c),
            domain_4n,
        );

        let q_arith_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&selectors.q_arith),
            domain_4n,
        );

        let sigma_0_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&selectors.sigma_0),
            domain_4n,
        );
        let sigma_1_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&selectors.sigma_1),
            domain_4n,
        );
        let sigma_2_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&selectors.sigma_2),
            domain_4n,
        );
        let sigma_3_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&selectors.sigma_3),
            domain_4n,
        );

        Ok(ProverKey {
            n,
            arithmetic: arithmetic::ProverKey {
                q_0: (selectors.q_0, q_0_evals),
                q_1: (selectors.q_1, q_1_evals),
                q_2: (selectors.q_2, q_2_evals),
                q_3: (selectors.q_3, q_3_evals),

                q_m: (selectors.q_m, q_m_evals),
                q_c: (selectors.q_c, q_c_evals),

                q_arith: (selectors.q_arith, q_arith_evals),
            },
            permutation: permutation::ProverKey {
                sigma_0: (selectors.sigma_0, sigma_0_evals),
                sigma_1: (selectors.sigma_1, sigma_1_evals),
                sigma_2: (selectors.sigma_2, sigma_2_evals),
                sigma_3: (selectors.sigma_3, sigma_3_evals),
            },
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
