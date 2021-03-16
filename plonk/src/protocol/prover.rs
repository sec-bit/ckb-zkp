use ark_ff::{FftField as Field, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain,
    Evaluations as EvaluationsOnDomain, Polynomial, UVPolynomial,
};
use ark_std::{cfg_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::composer::Composer;
use crate::data_structures::LabeledPolynomial;
use crate::protocol::preprocessor::PreprocessorKeys;
use crate::protocol::verifier::{FirstMsg, SecondMsg};
use crate::protocol::Error;
use crate::utils::get_domain_generator;

pub struct Prover<'a, F: Field> {
    keys: &'a PreprocessorKeys<F>,
    pi: (DensePolynomial<F>, Vec<F>, Vec<F>),

    w_0: Option<(Vec<F>, Vec<F>)>,
    w_1: Option<(Vec<F>, Vec<F>)>,
    w_2: Option<(Vec<F>, Vec<F>)>,
    w_3: Option<(Vec<F>, Vec<F>)>,

    z: Option<(Vec<F>, Vec<F>)>,

    alpha: Option<F>,
    beta: Option<F>,
    gamma: Option<F>,
}

pub struct FirstOracles<F: Field> {
    pub w_0: LabeledPolynomial<F>,
    pub w_1: LabeledPolynomial<F>,
    pub w_2: LabeledPolynomial<F>,
    pub w_3: LabeledPolynomial<F>,
}

impl<F: Field> FirstOracles<F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        ark_std::vec![&self.w_0, &self.w_1, &self.w_2, &self.w_3]
            .into_iter()
    }
}

pub struct SecondOracles<F: Field> {
    pub z: LabeledPolynomial<F>,
}

impl<F: Field> SecondOracles<F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        ark_std::vec![&self.z].into_iter()
    }
}

pub struct ThirdOracles<F: Field> {
    pub t_0: LabeledPolynomial<F>,
    pub t_1: LabeledPolynomial<F>,
    pub t_2: LabeledPolynomial<F>,
    pub t_3: LabeledPolynomial<F>,
}

impl<F: Field> ThirdOracles<F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        ark_std::vec![&self.t_0, &self.t_1, &self.t_2, &self.t_3]
            .into_iter()
    }
}

impl<'a, F: Field> Prover<'a, F> {
    pub fn size(&self) -> usize {
        self.keys.size()
    }
}

impl<'a, F: Field> Prover<'a, F> {
    pub fn init(
        cs: &Composer<F>,
        keys: &'a PreprocessorKeys<F>,
    ) -> Result<Prover<'a, F>, Error> {
        let domain_n = keys.domain_n();
        let domain_4n = keys.domain_4n();

        let pi = cs.public_input();
        let pi_n = cs.public_inputs_with_padding(domain_n.size());
        let pi_poly =
            EvaluationsOnDomain::from_vec_and_domain(pi_n, domain_n)
                .interpolate();
        let pi_4n = domain_4n.coset_fft(&pi_poly);

        Ok(Prover {
            keys,
            pi: (pi_poly, pi, pi_4n),

            w_0: None,
            w_1: None,
            w_2: None,
            w_3: None,

            z: None,

            alpha: None,
            beta: None,
            gamma: None,
        })
    }

    pub fn public_input(&self) -> Vec<F> {
        self.pi.1
    }

    pub fn first_round(
        &mut self,
        cs: &Composer<F>,
    ) -> Result<FirstOracles<F>, Error> {
        let (w_0, w_1, w_2, w_3) = cs.synthesize()?;

        let domain_n = self.keys.domain_n();
        let w_0_poly = EvaluationsOnDomain::from_vec_and_domain(
            w_0.clone(),
            domain_n,
        )
        .interpolate();
        let w_1_poly = EvaluationsOnDomain::from_vec_and_domain(
            w_1.clone(),
            domain_n,
        )
        .interpolate();
        let w_2_poly = EvaluationsOnDomain::from_vec_and_domain(
            w_2.clone(),
            domain_n,
        )
        .interpolate();
        let w_3_poly = EvaluationsOnDomain::from_vec_and_domain(
            w_3.clone(),
            domain_n,
        )
        .interpolate();
        let pi = cs.public_inputs_with_padding(domain_n.size());
        let pi_poly =
            EvaluationsOnDomain::from_vec_and_domain(pi.clone(), domain_n)
                .interpolate();

        let domain_4n = self.keys.domain_4n();
        let w_0_4n = domain_4n.coset_fft(&w_0_poly);
        let w_1_4n = domain_4n.coset_fft(&w_1_poly);
        let w_2_4n = domain_4n.coset_fft(&w_2_poly);
        let w_3_4n = domain_4n.coset_fft(&w_3_poly);

        let first_oracles = FirstOracles {
            w_0: LabeledPolynomial::new(
                "w_0".to_string(),
                w_0_poly,
                None,
                None,
            ),
            w_1: LabeledPolynomial::new(
                "w_1".to_string(),
                w_1_poly,
                None,
                None,
            ),
            w_2: LabeledPolynomial::new(
                "w_2".to_string(),
                w_2_poly,
                None,
                None,
            ),
            w_3: LabeledPolynomial::new(
                "w_3".to_string(),
                w_3_poly,
                None,
                None,
            ),
        };

        self.w_0 = Some((w_0, w_0_4n));
        self.w_1 = Some((w_1, w_1_4n));
        self.w_2 = Some((w_2, w_2_4n));
        self.w_3 = Some((w_3, w_3_4n));

        Ok(first_oracles)
    }

    pub fn second_round(
        &mut self,
        msg: &FirstMsg<F>,
    ) -> Result<SecondOracles<F>, Error> {
        let w_0 = &self.w_0.as_ref().unwrap().0;
        let w_1 = &self.w_1.as_ref().unwrap().0;
        let w_2 = &self.w_2.as_ref().unwrap().0;
        let w_3 = &self.w_3.as_ref().unwrap().0;
        let FirstMsg { beta, gamma } = msg;

        let permutation_key = self.keys.permutation_key();
        let (z_poly, z, z_4n) = permutation_key.compute_z(
            self.keys.domain_n(),
            self.keys.domain_4n(),
            (w_0, w_1, w_2, w_3),
            beta,
            gamma,
        );

        let second_oracles = SecondOracles {
            z: LabeledPolynomial::new("z".to_string(), z_poly, None, None),
        };

        self.z = Some((z, z_4n));
        self.beta = Some(*beta);
        self.gamma = Some(*gamma);

        Ok(second_oracles)
    }

    pub fn third_round(
        &mut self,
        msg: &SecondMsg<F>,
    ) -> Result<ThirdOracles<F>, Error> {
        let domain_n = self.keys.domain_n();
        let domain_4n = self.keys.domain_4n();

        let w_0_4n = &self.w_0.as_ref().unwrap().1;
        let w_1_4n = &self.w_1.as_ref().unwrap().1;
        let w_2_4n = &self.w_2.as_ref().unwrap().1;
        let w_3_4n = &self.w_3.as_ref().unwrap().1;
        let pi_4n = &self.pi.1;
        let z_4n = &self.z.as_ref().unwrap().1;

        let SecondMsg { alpha } = msg;
        self.alpha = Some(*alpha);

        let arithmetic_key = self.keys.arithmetic_key();
        let p_arith = arithmetic_key.compute_quotient(
            domain_4n, w_0_4n, w_1_4n, w_2_4n, w_3_4n, pi_4n,
        );

        let permutation_key = self.keys.permutation_key();
        let p_perm = permutation_key.compute_quotient(
            domain_4n,
            (w_0_4n, w_1_4n, w_2_4n, w_3_4n),
            z_4n,
            &self.beta.unwrap(),
            &self.gamma.unwrap(),
            alpha,
        );

        let t: Vec<_> = cfg_iter!(p_arith)
            .zip(&p_perm)
            .zip(self.keys.v_4n_inversed())
            .map(|((p_arith, p_perm), vi)| (*p_arith + p_perm) * vi)
            .collect();

        let t_poly = DensePolynomial::from_coefficients_vec(
            domain_4n.coset_ifft(&t),
        );

        let t_polys = Self::quad_split(domain_n.size(), t_poly);

        let third_oracles = ThirdOracles {
            t_0: LabeledPolynomial::new(
                "t_0".into(),
                t_polys.0,
                None,
                None,
            ),
            t_1: LabeledPolynomial::new(
                "t_1".into(),
                t_polys.1,
                None,
                None,
            ),
            t_2: LabeledPolynomial::new(
                "t_2".into(),
                t_polys.2,
                None,
                None,
            ),
            t_3: LabeledPolynomial::new(
                "t_3".into(),
                t_polys.3,
                None,
                None,
            ),
        };

        Ok(third_oracles)
    }

    // for redundant checks
    fn check_evaluation(
        &self,
        point: &F,
        first_oracles: &FirstOracles<F>,
        second_oracles: &SecondOracles<F>,
        third_oracles: &ThirdOracles<F>,
    ) {
        let gen = get_domain_generator(self.keys.domain_n());
        let alpha = self.alpha.unwrap();
        let beta = self.beta.unwrap();
        let gamma = self.gamma.unwrap();

        let w_evals: Vec<_> =
            first_oracles.iter().map(|w| w.evaluate(point)).collect();
        let z_eval = second_oracles.z.evaluate(point);
        let z_shifted_eval = second_oracles.z.evaluate(&(gen * point));

        let t_eval: F = {
            let point_n = point.pow(&[self.size() as u64]);
            let point_2n = point_n.square();

            third_oracles
                .iter()
                .zip(ark_std::vec![
                    F::one(),
                    point_n,
                    point_2n,
                    point_n * point_2n
                ])
                .map(|(p, z)| p.evaluate(point) * z)
                .sum()
        };
        let v_eval =
            self.keys.domain_n().evaluate_vanishing_polynomial(*point);
        let pi_eval = self.pi.0.evaluate(point);

        let arithmetic_key = self.keys.arithmetic_key();
        let q_0_eval = arithmetic_key.q_0.0.evaluate(point);
        let q_1_eval = arithmetic_key.q_1.0.evaluate(point);
        let q_2_eval = arithmetic_key.q_2.0.evaluate(point);
        let q_3_eval = arithmetic_key.q_3.0.evaluate(point);
        let q_m_eval = arithmetic_key.q_m.0.evaluate(point);
        let q_c_eval = arithmetic_key.q_c.0.evaluate(point);
        let q_arith_eval = arithmetic_key.q_arith.0.evaluate(point);

        let permutation_key = self.keys.permutation_key();
        let ks = permutation_key.ks;
        let sigma_0_eval = permutation_key.sigma_0.0.evaluate(point);
        let sigma_1_eval = permutation_key.sigma_1.0.evaluate(point);
        let sigma_2_eval = permutation_key.sigma_2.0.evaluate(point);
        let sigma_3_eval = permutation_key.sigma_3.0.evaluate(point);

        let lhs = t_eval * v_eval;
        let rhs = q_arith_eval
            * (q_0_eval * w_evals[0]
                + q_1_eval * w_evals[1]
                + q_2_eval * w_evals[2]
                + q_3_eval * w_evals[3]
                + q_m_eval * w_evals[1] * w_evals[2]
                + q_c_eval
                + pi_eval)
            + alpha
                * (z_eval
                    * (w_evals[0] + ks[0] * beta * point + gamma)
                    * (w_evals[1] + ks[1] * beta * point + gamma)
                    * (w_evals[2] + ks[2] * beta * point + gamma)
                    * (w_evals[3] + ks[3] * beta * point + gamma)
                    - z_shifted_eval
                        * (w_evals[0] + beta * sigma_0_eval + gamma)
                        * (w_evals[1] + beta * sigma_1_eval + gamma)
                        * (w_evals[2] + beta * sigma_2_eval + gamma)
                        * (w_evals[3] + beta * sigma_3_eval + gamma));
        assert_eq!(lhs, rhs);
    }

    fn quad_split(
        n: usize,
        poly: DensePolynomial<F>,
    ) -> (
        DensePolynomial<F>,
        DensePolynomial<F>,
        DensePolynomial<F>,
        DensePolynomial<F>,
    ) {
        let mut poly_0 = DensePolynomial::zero();
        let mut poly_1 = DensePolynomial::zero();
        let mut poly_2 = DensePolynomial::zero();
        let mut poly_3 = DensePolynomial::zero();

        let mut coeffs = poly.coeffs.into_iter().peekable();
        if coeffs.peek().is_some() {
            let chunk: Vec<_> = coeffs.by_ref().take(n).collect();
            poly_0 =
                DensePolynomial::from_coefficients_vec(chunk.to_vec());
        }
        if coeffs.peek().is_some() {
            let chunk: Vec<_> = coeffs.by_ref().take(n).collect();
            poly_1 =
                DensePolynomial::from_coefficients_vec(chunk.to_vec());
        }
        if coeffs.peek().is_some() {
            let chunk: Vec<_> = coeffs.by_ref().take(n).collect();
            poly_2 =
                DensePolynomial::from_coefficients_vec(chunk.to_vec());
        }
        if coeffs.peek().is_some() {
            let chunk: Vec<_> = coeffs.by_ref().take(n).collect();
            poly_3 =
                DensePolynomial::from_coefficients_vec(chunk.to_vec());
        }

        (poly_0, poly_1, poly_2, poly_3)
    }
}
