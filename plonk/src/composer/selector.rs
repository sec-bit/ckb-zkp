use ark_poly::{
    univariate::DensePolynomial as Polynomial, EvaluationDomain,
    Evaluations, GeneralEvaluationDomain,
};

use crate::composer::{Composer, Error, Field};

pub struct Selector<F: Field> {
    pub q_0: (Polynomial<F>, Evaluations<F>),
    pub q_1: (Polynomial<F>, Evaluations<F>),
    pub q_2: (Polynomial<F>, Evaluations<F>),
    pub q_3: (Polynomial<F>, Evaluations<F>),

    pub q_m: (Polynomial<F>, Evaluations<F>),
    pub q_c: (Polynomial<F>, Evaluations<F>),
    pub pi: (Polynomial<F>, Evaluations<F>),

    pub q_arith: (Polynomial<F>, Evaluations<F>),

    pub sigma_0: (Polynomial<F>, Evaluations<F>),
    pub sigma_1: (Polynomial<F>, Evaluations<F>),
    pub sigma_2: (Polynomial<F>, Evaluations<F>),
    pub sigma_3: (Polynomial<F>, Evaluations<F>),
}

impl<F: Field> Composer<F> {
    // convert composor to collection of selectors
    pub fn compute_selectors(
        mut self,
    ) -> Result<(usize, Selector<F>), Error> {
        let domain_n = GeneralEvaluationDomain::<F>::new(self.size())
            .ok_or(Error::PolynomialDegreeTooLarge)?;

        let diff = domain_n.size() - self.size();
        self.pad(diff);
        // size after padding
        let n = self.size();

        let (sigma_0, sigma_1, sigma_2, sigma_3) =
            self.permutation.compute_sigmas(n)?;

        let domain_4n = GeneralEvaluationDomain::<F>::new(4 * self.size())
            .ok_or(Error::PolynomialDegreeTooLarge)?;

        let q_0 = Evaluations::from_vec_and_domain(self.q_0, domain_n)
            .interpolate();
        let q_0_evals_4n = Evaluations::from_vec_and_domain(
            domain_4n.fft(&q_0),
            domain_4n,
        );
        let q_1 = Evaluations::from_vec_and_domain(self.q_1, domain_n)
            .interpolate();
        let q_1_evals_4n = Evaluations::from_vec_and_domain(
            domain_4n.fft(&q_1),
            domain_4n,
        );
        let q_2 = Evaluations::from_vec_and_domain(self.q_2, domain_n)
            .interpolate();
        let q_2_evals_4n = Evaluations::from_vec_and_domain(
            domain_4n.fft(&q_2),
            domain_4n,
        );
        let q_3 = Evaluations::from_vec_and_domain(self.q_3, domain_n)
            .interpolate();
        let q_3_evals_4n = Evaluations::from_vec_and_domain(
            domain_4n.fft(&q_3),
            domain_4n,
        );

        let q_m = Evaluations::from_vec_and_domain(self.q_m, domain_n)
            .interpolate();
        let q_m_evals_4n = Evaluations::from_vec_and_domain(
            domain_4n.fft(&q_m),
            domain_4n,
        );
        let q_c = Evaluations::from_vec_and_domain(self.q_c, domain_n)
            .interpolate();
        let q_c_evals_4n = Evaluations::from_vec_and_domain(
            domain_4n.fft(&q_c),
            domain_4n,
        );
        let pi = Evaluations::from_vec_and_domain(self.pi, domain_n)
            .interpolate();
        let pi_evals_4n = Evaluations::from_vec_and_domain(
            domain_4n.fft(&pi),
            domain_4n,
        );

        let q_arith =
            Evaluations::from_vec_and_domain(self.q_arith, domain_n)
                .interpolate();
        let q_arith_evals_4n = Evaluations::from_vec_and_domain(
            domain_4n.fft(&q_arith),
            domain_4n,
        );

        let sigma_0 = Evaluations::from_vec_and_domain(sigma_0, domain_n)
            .interpolate();
        let sigma_0_evals_4n = Evaluations::from_vec_and_domain(
            domain_4n.fft(&sigma_0),
            domain_4n,
        );
        let sigma_1 = Evaluations::from_vec_and_domain(sigma_1, domain_n)
            .interpolate();
        let sigma_1_evals_4n = Evaluations::from_vec_and_domain(
            domain_4n.fft(&sigma_1),
            domain_4n,
        );
        let sigma_2 = Evaluations::from_vec_and_domain(sigma_2, domain_n)
            .interpolate();
        let sigma_2_evals_4n = Evaluations::from_vec_and_domain(
            domain_4n.fft(&sigma_2),
            domain_4n,
        );
        let sigma_3 = Evaluations::from_vec_and_domain(sigma_3, domain_n)
            .interpolate();
        let sigma_3_evals_4n = Evaluations::from_vec_and_domain(
            domain_4n.fft(&sigma_3),
            domain_4n,
        );

        Ok((
            n,
            Selector {
                q_0: (q_0, q_0_evals_4n),
                q_1: (q_1, q_1_evals_4n),
                q_2: (q_2, q_2_evals_4n),
                q_3: (q_3, q_3_evals_4n),

                q_m: (q_m, q_m_evals_4n),
                q_c: (q_c, q_c_evals_4n),
                pi: (pi, pi_evals_4n),

                q_arith: (q_arith, q_arith_evals_4n),

                sigma_0: (sigma_0, sigma_0_evals_4n),
                sigma_1: (sigma_1, sigma_1_evals_4n),
                sigma_2: (sigma_2, sigma_2_evals_4n),
                sigma_3: (sigma_3, sigma_3_evals_4n),
            },
        ))
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
