use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial as Polynomial, EvaluationDomain,
    Evaluations, GeneralEvaluationDomain,
};

use crate::Vec;

pub struct ProverKey<F: Field> {
    pub sigma_0: (Polynomial<F>, Vec<F>, Vec<F>),
    pub sigma_1: (Polynomial<F>, Vec<F>, Vec<F>),
    pub sigma_2: (Polynomial<F>, Vec<F>, Vec<F>),
    pub sigma_3: (Polynomial<F>, Vec<F>, Vec<F>),

    pub domain_n: GeneralEvaluationDomain<F>,
    pub domain_4n: GeneralEvaluationDomain<F>,
}

impl<F: Field> ProverKey<F> {
    pub(crate) fn compute_z_poly(
        &self,
        domain: impl EvaluationDomain<F>,
        w_0: Vec<F>,
        w_1: Vec<F>,
        w_2: Vec<F>,
        w_3: Vec<F>,
    ) {
    }

    pub(crate) fn numerator_factor(
        w: &F,
        root: &F,
        k: &F,
        beta: &F,
        gamma: &F,
    ) -> F {
        *w + *k * beta * root + gamma
    }

    pub(crate) fn denumerator_factor(
        w: &F,
        sigma: &F,
        beta: &F,
        gamma: &F,
    ) -> F {
        *w + *beta * sigma + gamma
    }

    pub(crate) fn compute_copy_ext_i(
        &self,
        index: usize,
        w_0_i: &F,
        w_1_i: &F,
        w_2_i: &F,
        w_3_i: &F,
        z_i: &F,
        beta: &F,
        gamma: &F,
    ) -> F {
        let sigma_0_i = &self.sigma_0.1[index];
        let sigma_1_i = &self.sigma_1.1[index];
        let sigma_2_i = &self.sigma_2.1[index];
        let sigma_3_i = &self.sigma_3.1[index];

        F::zero()
    }
}
