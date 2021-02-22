use ark_poly::{
    univariate::DensePolynomial as Polynomial, EvaluationDomain,
    Evaluations, GeneralEvaluationDomain,
};
use ark_std::{cfg_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::composer::{Composer, Field};
use crate::{Error, Map};

pub struct Selectors<F: Field> {
    pub q_0: Vec<F>,
    pub q_1: Vec<F>,
    pub q_2: Vec<F>,
    pub q_3: Vec<F>,

    pub q_m: Vec<F>,
    pub q_c: Vec<F>,

    pub q_arith: Vec<F>,

    pub sigma_0: Vec<F>,
    pub sigma_1: Vec<F>,
    pub sigma_2: Vec<F>,
    pub sigma_3: Vec<F>,
}

impl<F: Field> Composer<F> {
    // selectors
    pub fn preprocess(&self) -> Result<(usize, Selectors<F>), Error> {
        let domain = GeneralEvaluationDomain::<F>::new(self.size())
            .ok_or(Error::PolynomialDegreeTooLarge)?;

        let diff = domain.size() - self.size();
        let zeros = vec![F::zero(); diff];

        let mut q_0 = self.q_0.clone();
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

        let (sigma_0, sigma_1, sigma_2, sigma_3) =
            self.permutation.compute_sigmas(domain.size())?;

        Ok((
            self.size(),
            Selectors {
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
            },
        ))
    }

    // witness vectors
    pub fn synthesize(
        &self,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, Vec<F>), Error> {
        let domain = GeneralEvaluationDomain::<F>::new(self.size())
            .ok_or(Error::PolynomialDegreeTooLarge)?;

        let assign = |&v| self.assignment[&v];
        let mut w_0: Vec<_> = cfg_iter!(self.w_0).map(assign).collect();
        let mut w_1: Vec<_> = cfg_iter!(self.w_1).map(assign).collect();
        let mut w_2: Vec<_> = cfg_iter!(self.w_2).map(assign).collect();
        let mut w_3: Vec<_> = cfg_iter!(self.w_3).map(assign).collect();

        let diff = domain.size() - self.size();
        let zeros = vec![F::zero(); diff];
        w_0.extend(zeros.iter());
        w_1.extend(zeros.iter());
        w_2.extend(zeros.iter());
        w_3.extend(zeros.iter());

        Ok((w_0, w_1, w_2, w_3))
    }
}
