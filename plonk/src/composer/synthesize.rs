use crate::{Map, Vec};
use ark_poly::{
    univariate::DensePolynomial as Polynomial, EvaluationDomain,
    Evaluations, GeneralEvaluationDomain,
};

use crate::composer::{Composer, Field};
use crate::Error;

pub struct Selectors<F: Field> {
    pub q_0: Polynomial<F>,
    pub q_1: Polynomial<F>,
    pub q_2: Polynomial<F>,
    pub q_3: Polynomial<F>,

    pub q_m: Polynomial<F>,
    pub q_c: Polynomial<F>,

    pub q_arith: Polynomial<F>,

    pub sigma_0: Polynomial<F>,
    pub sigma_1: Polynomial<F>,
    pub sigma_2: Polynomial<F>,
    pub sigma_3: Polynomial<F>,
}

impl<F: Field> Composer<F> {
    // selectors: q_0(X), q_1(X), q_2(X), q_3(X), q_m(X), q_c(X), q_arith(X)
    pub fn preprocess(&self) -> Result<(usize, Selectors<F>), Error> {
        let domain = GeneralEvaluationDomain::<F>::new(self.size())
            .ok_or(Error::PolynomialDegreeTooLarge)?;

        let diff = domain.size() - self.size();

        let zeros = vec![F::zero(); diff];

        let mut q_0 = self.q_1.clone();
        q_0.extend(zeros.iter());
        let mut q_1 = self.q_1.clone();
        q_1.extend(zeros.iter());
        let mut q_2 = self.q_2.clone();
        q_2.extend(zeros.iter());
        let mut q_3 = self.q_3.clone();
        q_3.extend(zeros.iter());

        let mut q_m = self.q_m.clone();
        q_m.extend(zeros.iter());
        let mut q_c = self.q_c.clone();
        q_c.extend(zeros.iter());

        let mut q_arith = self.q_arith.clone();
        q_arith.extend(zeros.iter());

        let q_0_poly =
            Evaluations::from_vec_and_domain(q_0, domain).interpolate();
        let q_1_poly =
            Evaluations::from_vec_and_domain(q_1, domain).interpolate();
        let q_2_poly =
            Evaluations::from_vec_and_domain(q_2, domain).interpolate();
        let q_3_poly =
            Evaluations::from_vec_and_domain(q_3, domain).interpolate();

        let q_m_poly =
            Evaluations::from_vec_and_domain(q_m, domain).interpolate();
        let q_c_poly =
            Evaluations::from_vec_and_domain(q_c, domain).interpolate();

        let q_arith_poly =
            Evaluations::from_vec_and_domain(q_arith, domain)
                .interpolate();

        let (sigma_0, sigma_1, sigma_2, sigma_3) =
            self.permutation.compute_sigmas(domain.size())?;
        let sigma_0_poly =
            Evaluations::from_vec_and_domain(sigma_0.clone(), domain)
                .interpolate();
        let sigma_1_poly =
            Evaluations::from_vec_and_domain(sigma_1.clone(), domain)
                .interpolate();
        let sigma_2_poly =
            Evaluations::from_vec_and_domain(sigma_2.clone(), domain)
                .interpolate();
        let sigma_3_poly =
            Evaluations::from_vec_and_domain(sigma_3.clone(), domain)
                .interpolate();

        Ok((
            self.size(),
            Selectors {
                q_0: q_0_poly,
                q_1: q_1_poly,
                q_2: q_2_poly,
                q_3: q_3_poly,

                q_m: q_m_poly,
                q_c: q_c_poly,

                q_arith: q_arith_poly,

                sigma_0: sigma_0_poly,
                sigma_1: sigma_1_poly,
                sigma_2: sigma_2_poly,
                sigma_3: sigma_3_poly,
            },
        ))
    }

    // witness polynomials: w_0(X), w_1(X), w_2(X), w_3(X)
    pub fn synthesize(
        &self,
    ) -> Result<
        (Polynomial<F>, Polynomial<F>, Polynomial<F>, Polynomial<F>),
        Error,
    > {
        let domain = GeneralEvaluationDomain::<F>::new(self.size())
            .ok_or(Error::PolynomialDegreeTooLarge)?;

        let assign = |&v| self.assignment[&v];
        let mut w_0: Vec<_> = self.w_0.iter().map(assign).collect();
        let mut w_1: Vec<_> = self.w_1.iter().map(assign).collect();
        let mut w_2: Vec<_> = self.w_2.iter().map(assign).collect();
        let mut w_3: Vec<_> = self.w_3.iter().map(assign).collect();

        let diff = domain.size() - self.size();
        let zeros = vec![F::zero(); diff];
        w_0.extend(zeros.iter());
        w_1.extend(zeros.iter());
        w_2.extend(zeros.iter());
        w_3.extend(zeros.iter());

        let w_0 =
            Evaluations::from_vec_and_domain(w_0, domain).interpolate();
        let w_1 =
            Evaluations::from_vec_and_domain(w_1, domain).interpolate();
        let w_2 =
            Evaluations::from_vec_and_domain(w_2, domain).interpolate();
        let w_3 =
            Evaluations::from_vec_and_domain(w_3, domain).interpolate();

        Ok((w_0, w_1, w_2, w_3))
    }
}
