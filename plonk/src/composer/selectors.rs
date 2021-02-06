use ark_poly::univariate::DensePolynomial as Polynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};

use crate::composer::{Composer, Error, Field};

pub struct Selectors<F: Field> {
    q_0: Polynomial<F>,
    q_1: Polynomial<F>,
    q_2: Polynomial<F>,
    q_3: Polynomial<F>,

    q_m: Polynomial<F>,
    q_c: Polynomial<F>,
    pi: Polynomial<F>,

    q_arith: Polynomial<F>,

    sigma_0: Polynomial<F>,
    sigma_1: Polynomial<F>,
    sigma_2: Polynomial<F>,
    sigma_3: Polynomial<F>,
}

impl<F: Field> Composer<F> {
    pub fn to_selectors(mut self) -> Result<Selectors<F>, Error> {
        let domain_h = GeneralEvaluationDomain::<F>::new(self.n)
            .ok_or(Error::PolynomialDegreeTooLarge)?;

        let diff = domain_h.size() - self.n;
        self.pad(diff);

        let (sigma_0, sigma_1, sigma_2, sigma_3) =
            self.permutation.compute_sigmas(self.n)?;

        Ok(Selectors {
            q_0: Evaluations::from_vec_and_domain(self.q_0, domain_h)
                .interpolate(),
            q_1: Evaluations::from_vec_and_domain(self.q_1, domain_h)
                .interpolate(),
            q_2: Evaluations::from_vec_and_domain(self.q_2, domain_h)
                .interpolate(),
            q_3: Evaluations::from_vec_and_domain(self.q_3, domain_h)
                .interpolate(),

            q_m: Evaluations::from_vec_and_domain(self.q_m, domain_h)
                .interpolate(),
            q_c: Evaluations::from_vec_and_domain(self.q_c, domain_h)
                .interpolate(),
            pi: Evaluations::from_vec_and_domain(self.pi, domain_h)
                .interpolate(),

            q_arith: Evaluations::from_vec_and_domain(
                self.q_arith,
                domain_h,
            )
            .interpolate(),

            sigma_0: Evaluations::from_vec_and_domain(sigma_0, domain_h)
                .interpolate(),
            sigma_1: Evaluations::from_vec_and_domain(sigma_1, domain_h)
                .interpolate(),
            sigma_2: Evaluations::from_vec_and_domain(sigma_2, domain_h)
                .interpolate(),
            sigma_3: Evaluations::from_vec_and_domain(sigma_3, domain_h)
                .interpolate(),
        })
    }

    fn pad(&mut self, diff: usize) {
        let zeros = vec![F::zero(); diff];

        self.q_0.extend(zeros.iter());
        self.q_1.extend(zeros.iter());
        self.q_2.extend(zeros.iter());
        self.q_3.extend(zeros.iter());

        self.q_m.extend(zeros.iter());
        self.q_c.extend(zeros.iter());
        self.pi.extend(zeros.iter());

        self.q_arith.extend(zeros.iter());

        self.n += diff;
    }
}
