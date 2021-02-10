use ark_ff::FftField as Field;
use ark_poly::{univariate::DensePolynomial as Polynomial, Evaluations};

pub struct ProverKey<F: Field> {
    pub sigma_0: (Polynomial<F>, Evaluations<F>),
    pub sigma_1: (Polynomial<F>, Evaluations<F>),
    pub sigma_2: (Polynomial<F>, Evaluations<F>),
    pub sigma_3: (Polynomial<F>, Evaluations<F>),
}

impl<F: Field> ProverKey<F> {
    pub fn compute_copy_ext_i(
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
