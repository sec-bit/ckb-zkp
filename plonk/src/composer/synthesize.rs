use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{cfg_iter, vec, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::composer::{Composer, Field};

#[derive(Debug)]
pub enum Error {
    PolynomialDegreeTooLarge,
}

pub struct Selectors<F: Field> {
    n: usize,
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

pub struct Witnesses<F: Field> {
    pub w_0: Vec<F>,
    pub w_1: Vec<F>,
    pub w_2: Vec<F>,
    pub w_3: Vec<F>,
}

impl<F: Field> Witnesses<F> {
    pub fn iter(&self) -> impl Iterator<Item = &Vec<F>> {
        vec![&self.w_0, &self.w_1, &self.w_2, &self.w_3].into_iter()
    }
}

impl<F: Field> Selectors<F> {
    pub fn size(&self) -> usize {
        self.n
    }

    pub fn iter(&self) -> impl Iterator<Item = &Vec<F>> {
        vec![
            &self.q_0,
            &self.q_1,
            &self.q_2,
            &self.q_3,
            &self.q_m,
            &self.q_c,
            &self.q_arith,
            &self.sigma_0,
            &self.sigma_1,
            &self.sigma_2,
            &self.sigma_3,
        ]
        .into_iter()
    }
}

impl<F: Field> Composer<F> {
    // selectors
    pub fn compose(&self, ks: &[F; 4]) -> Result<Selectors<F>, Error> {
        let domain_n = GeneralEvaluationDomain::<F>::new(self.n)
            .ok_or(Error::PolynomialDegreeTooLarge)?;
        let n = domain_n.size();

        let (sigma_0, sigma_1, sigma_2, sigma_3) =
            self.permutation.compute_sigmas(domain_n, &ks);

        assert_eq!(sigma_0.len(), n);
        assert_eq!(sigma_1.len(), n);
        assert_eq!(sigma_2.len(), n);
        assert_eq!(sigma_3.len(), n);

        let diff = n - self.n;
        let zeros = vec![F::zero(); diff];
        let pad = |mut v: Vec<F>| {
            v.extend(zeros.iter());
            v
        };

        Ok(Selectors {
            n,
            q_0: pad(self.q_0.clone()),
            q_1: pad(self.q_1.clone()),
            q_2: pad(self.q_2.clone()),
            q_3: pad(self.q_3.clone()),
            q_m: pad(self.q_m.clone()),
            q_c: pad(self.q_c.clone()),
            q_arith: pad(self.q_arith.clone()),

            sigma_0,
            sigma_1,
            sigma_2,
            sigma_3,
        })
    }

    pub fn public_inputs(&self) -> &[F] {
        &self.pi
    }

    // synthesize witness vectors
    pub fn synthesize(&self) -> Result<Witnesses<F>, Error> {
        let domain_n = GeneralEvaluationDomain::<F>::new(self.n)
            .ok_or(Error::PolynomialDegreeTooLarge)?;
        let n = domain_n.size();

        let assign = |&v| self.assignment[&v];
        let mut w_0: Vec<_> = cfg_iter!(self.w_0).map(assign).collect();
        let mut w_1: Vec<_> = cfg_iter!(self.w_1).map(assign).collect();
        let mut w_2: Vec<_> = cfg_iter!(self.w_2).map(assign).collect();
        let mut w_3: Vec<_> = cfg_iter!(self.w_3).map(assign).collect();

        let diff = n - self.n;
        let zeros = vec![F::zero(); diff];
        w_0.extend(zeros.iter());
        w_1.extend(zeros.iter());
        w_2.extend(zeros.iter());
        w_3.extend(zeros.iter());

        let mut pi = self.pi.clone();
        pi.extend(zeros.iter());

        Ok(Witnesses { w_0, w_1, w_2, w_3 })
    }
}
