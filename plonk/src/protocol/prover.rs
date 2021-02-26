use ark_ff::{FftField as Field, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations,
    Polynomial, UVPolynomial,
};
use ark_std::{cfg_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::composer::Composer;
use crate::protocol::keygen::{generate_prover_key, ProverKey};
use crate::protocol::verifier::{FirstMsg, SecondMsg, ThirdMsg};
use crate::{utils::get_generator, Error, Evals, LabeledPolynomial};

pub struct Prover<F: Field> {
    pk: ProverKey<F>,
    pi: (DensePolynomial<F>, Vec<F>),

    w_0: Option<(Vec<F>, Vec<F>)>,
    w_1: Option<(Vec<F>, Vec<F>)>,
    w_2: Option<(Vec<F>, Vec<F>)>,
    w_3: Option<(Vec<F>, Vec<F>)>,

    z: Option<(Vec<F>, Vec<F>)>,

    alpha: Option<F>,
    beta: Option<F>,
    gamma: Option<F>,
}

pub struct FirstOracles<'a, F: Field> {
    pub w_0: LabeledPolynomial<'a, F>,
    pub w_1: LabeledPolynomial<'a, F>,
    pub w_2: LabeledPolynomial<'a, F>,
    pub w_3: LabeledPolynomial<'a, F>,
}

impl<'a, F: Field> FirstOracles<'a, F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<'a, F>> {
        vec![&self.w_0, &self.w_1, &self.w_2, &self.w_3].into_iter()
    }
}

pub struct SecondOracles<'a, F: Field> {
    pub z: LabeledPolynomial<'a, F>,
}

pub struct ThirdOracles<'a, F: Field> {
    pub t_0: LabeledPolynomial<'a, F>,
    pub t_1: LabeledPolynomial<'a, F>,
    pub t_2: LabeledPolynomial<'a, F>,
    pub t_3: LabeledPolynomial<'a, F>,
}

impl<'a, F: Field> ThirdOracles<'a, F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<'a, F>> {
        vec![&self.t_0, &self.t_1, &self.t_2, &self.t_3].into_iter()
    }
}

impl<F: Field> Prover<F> {
    pub fn size(&self) -> usize {
        self.pk.size()
    }
}

impl<F: Field> Prover<F> {
    pub fn init(cs: &Composer<F>, ks: [F; 4]) -> Result<Prover<F>, Error> {
        let pk = generate_prover_key(cs, ks)?;
        let domain_n = pk.domain_n();
        let domain_4n = pk.domain_4n();

        let pi = cs.public_inputs_with_padding(domain_n.size());
        let pi_poly =
            Evaluations::from_vec_and_domain(pi, domain_n).interpolate();
        let pi_4n = domain_4n.coset_fft(&pi_poly);

        Ok(Prover {
            pk,
            pi: (pi_poly, pi_4n),

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

    pub fn first_round<'a>(
        &mut self,
        cs: &Composer<F>,
    ) -> Result<FirstOracles<'a, F>, Error> {
        let (w_0, w_1, w_2, w_3) = cs.synthesize()?;

        let domain_n = self.pk.domain_n();
        let w_0_poly =
            Evaluations::from_vec_and_domain(w_0.clone(), domain_n)
                .interpolate();
        let w_1_poly =
            Evaluations::from_vec_and_domain(w_1.clone(), domain_n)
                .interpolate();
        let w_2_poly =
            Evaluations::from_vec_and_domain(w_2.clone(), domain_n)
                .interpolate();
        let w_3_poly =
            Evaluations::from_vec_and_domain(w_3.clone(), domain_n)
                .interpolate();
        let pi = cs.public_inputs_with_padding(domain_n.size());
        let pi_poly =
            Evaluations::from_vec_and_domain(pi.clone(), domain_n)
                .interpolate();

        let domain_4n = self.pk.domain_4n();
        let w_0_4n = domain_4n.coset_fft(&w_0_poly);
        let w_1_4n = domain_4n.coset_fft(&w_1_poly);
        let w_2_4n = domain_4n.coset_fft(&w_2_poly);
        let w_3_4n = domain_4n.coset_fft(&w_3_poly);

        let first_oracles = FirstOracles {
            w_0: LabeledPolynomial::new_owned("w_0".to_string(), w_0_poly),
            w_1: LabeledPolynomial::new_owned("w_1".to_string(), w_1_poly),
            w_2: LabeledPolynomial::new_owned("w_2".to_string(), w_2_poly),
            w_3: LabeledPolynomial::new_owned("w_3".to_string(), w_3_poly),
        };

        self.w_0 = Some((w_0, w_0_4n));
        self.w_1 = Some((w_1, w_1_4n));
        self.w_2 = Some((w_2, w_2_4n));
        self.w_3 = Some((w_3, w_3_4n));

        Ok(first_oracles)
    }

    pub fn second_round<'a>(
        &mut self,
        msg: &FirstMsg<F>,
    ) -> Result<SecondOracles<'a, F>, Error> {
        let w_0 = &self.w_0.as_ref().unwrap().0;
        let w_1 = &self.w_1.as_ref().unwrap().0;
        let w_2 = &self.w_2.as_ref().unwrap().0;
        let w_3 = &self.w_3.as_ref().unwrap().0;
        let FirstMsg { beta, gamma } = msg;

        let permutation_key = self.pk.permutation_key();
        let (z_poly, z, z_4n) = permutation_key.compute_z(
            self.pk.domain_n(),
            self.pk.domain_4n(),
            (w_0, w_1, w_2, w_3),
            beta,
            gamma,
        );

        let second_oracles = SecondOracles {
            z: LabeledPolynomial::new_owned("z".to_string(), z_poly),
        };

        self.z = Some((z, z_4n));
        self.beta = Some(*beta);
        self.gamma = Some(*gamma);

        Ok(second_oracles)
    }

    pub fn third_round<'a>(
        &mut self,
        msg: &SecondMsg<F>,
    ) -> Result<ThirdOracles<'a, F>, Error> {
        let domain_n = self.pk.domain_n();
        let domain_4n = self.pk.domain_4n();

        let w_0_4n = &self.w_0.as_ref().unwrap().1;
        let w_1_4n = &self.w_1.as_ref().unwrap().1;
        let w_2_4n = &self.w_2.as_ref().unwrap().1;
        let w_3_4n = &self.w_3.as_ref().unwrap().1;
        let pi_4n = &self.pi.1;
        let z_4n = &self.z.as_ref().unwrap().1;

        let SecondMsg { alpha } = msg;
        self.alpha = Some(*alpha);

        let arithmetic_key = self.pk.arithmetic_key();
        let p_arith = arithmetic_key.compute_quotient(
            domain_4n, w_0_4n, w_1_4n, w_2_4n, w_3_4n, pi_4n,
        );

        let permutation_key = self.pk.permutation_key();
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
            .zip(self.pk.v_4n_inversed())
            .map(|((p_arith, p_perm), vi)| (*p_arith + p_perm) * vi)
            .collect();

        let t_poly = DensePolynomial::from_coefficients_vec(
            domain_4n.coset_ifft(&t),
        );

        // TODO: checks, remove these
        {
            print!("\n");
            let roots: Vec<_> = domain_n.elements().collect();
            let p_arith_poly = DensePolynomial::from_coefficients_vec(
                domain_4n.coset_ifft(&p_arith),
            );
            print!("- checking p_arith_poly...");
            roots.iter().for_each(|r| {
                assert_eq!(p_arith_poly.evaluate(r), F::zero())
            });
            println!("done");
            let p_arith_alpha = p_arith_poly.evaluate(alpha);

            let p_perm_poly = DensePolynomial::from_coefficients_vec(
                domain_4n.coset_ifft(&p_perm),
            );
            print!("- checking p_perm_poly...");
            roots.iter().for_each(|r| {
                assert_eq!(p_perm_poly.evaluate(r), F::zero())
            });
            println!("done");
            let p_perm_alpha = p_perm_poly.evaluate(alpha);

            let t_alpha = t_poly.evaluate(alpha);
            let v_alpha = domain_n.evaluate_vanishing_polynomial(*alpha);

            print!("- checking t_poly...");
            assert_eq!(t_alpha * v_alpha, p_arith_alpha + p_perm_alpha);
            println!("done");
        }

        let t_polys = Self::quad_split(domain_n.size(), t_poly);

        let third_oracles = ThirdOracles {
            t_0: LabeledPolynomial::new_owned("t_0".into(), t_polys.0),
            t_1: LabeledPolynomial::new_owned("t_1".into(), t_polys.1),
            t_2: LabeledPolynomial::new_owned("t_2".into(), t_polys.2),
            t_3: LabeledPolynomial::new_owned("t_3".into(), t_polys.3),
        };

        Ok(third_oracles)
    }

    // for redundant checks
    fn check_evaluation<'a>(
        &self,
        point: &F,
        first_oracles: &FirstOracles<'a, F>,
        second_oracles: &SecondOracles<'a, F>,
        third_oracles: &ThirdOracles<'a, F>,
    ) {
        let gen = get_generator(self.pk.domain_n());
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
                .zip(vec![F::one(), point_n, point_2n, point_n * point_2n])
                .map(|(p, z)| p.evaluate(point) * z)
                .sum()
        };
        let v_eval =
            self.pk.domain_n().evaluate_vanishing_polynomial(*point);
        let pi_eval = self.pi.0.evaluate(point);

        let arithmetic_key = self.pk.arithmetic_key();
        let q_0_eval = arithmetic_key.q_0.0.evaluate(point);
        let q_1_eval = arithmetic_key.q_1.0.evaluate(point);
        let q_2_eval = arithmetic_key.q_2.0.evaluate(point);
        let q_3_eval = arithmetic_key.q_3.0.evaluate(point);
        let q_m_eval = arithmetic_key.q_m.0.evaluate(point);
        let q_c_eval = arithmetic_key.q_c.0.evaluate(point);
        let q_arith_eval = arithmetic_key.q_arith.0.evaluate(point);

        let permutation_key = self.pk.permutation_key();
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
        print!("\n");
        print!("- checking evaluations...");
        assert_eq!(lhs, rhs);
        println!("done");
    }

    pub fn evaluate<'a>(
        &self,
        third_msg: &ThirdMsg<F>,
        first_oracles: &FirstOracles<'a, F>,
        second_oracles: &SecondOracles<'a, F>,
        third_oracles: &ThirdOracles<'a, F>,
    ) -> Evals<F> {
        let ThirdMsg { zeta } = third_msg;

        // TODO: checks, remove these
        self.check_evaluation(
            zeta,
            first_oracles,
            second_oracles,
            third_oracles,
        );

        let mut evals = Evals::new();
        // evaluation of [w_0, ..., w_3]
        let w_zeta: Vec<_> =
            first_oracles.iter().map(|w| w.evaluate(zeta)).collect();

        // evaluation of z_shifted
        let gen = get_generator(self.pk.domain_n());
        let z_shifted_zeta = second_oracles.z.evaluate(&(gen * zeta));

        // evaluation of t
        let t_zeta: F = {
            let zeta_n = zeta.pow(&[self.size() as u64]);
            let zeta_2n = zeta_n.square();

            third_oracles
                .iter()
                .zip(vec![F::one(), zeta_n, zeta_2n, zeta_n * zeta_2n])
                .map(|(p, z)| p.evaluate(zeta) * z)
                .sum()
        };

        let (
            q_arith_zeta,
            sigma_0_zeta,
            sigma_1_zeta,
            sigma_2_zeta,
            r_zeta,
        ) = {
            let alpha = &self.alpha.unwrap();
            let beta = &self.beta.unwrap();
            let gamma = &self.gamma.unwrap();

            let arithmetic_key = self.pk.arithmetic_key();
            let (q_arith_zeta, arith_lin) = arithmetic_key
                .compute_linearisation(
                    &w_zeta[0], &w_zeta[1], &w_zeta[2], &w_zeta[3], zeta,
                );

            let permutation_key = self.pk.permutation_key();
            let (sigma_0_zeta, sigma_1_zeta, sigma_2_zeta, perm_lin) =
                permutation_key.compute_linearisation(
                    (&w_zeta[0], &w_zeta[1], &w_zeta[2], &w_zeta[3]),
                    &z_shifted_zeta,
                    &second_oracles.z.polynomial(),
                    beta,
                    gamma,
                    zeta,
                    alpha,
                );

            (
                q_arith_zeta,
                sigma_0_zeta,
                sigma_1_zeta,
                sigma_2_zeta,
                (arith_lin + perm_lin).evaluate(zeta),
            )
        };

        evals.insert("w_0".into(), w_zeta[0]);
        evals.insert("w_1".into(), w_zeta[1]);
        evals.insert("w_2".into(), w_zeta[2]);
        evals.insert("w_3".into(), w_zeta[3]);
        evals.insert("z_shifted".into(), z_shifted_zeta);
        evals.insert("q_arith".into(), q_arith_zeta);
        evals.insert("sigma_0".into(), sigma_0_zeta);
        evals.insert("sigma_1".into(), sigma_1_zeta);
        evals.insert("sigma_2".into(), sigma_2_zeta);
        evals.insert("t".into(), t_zeta);
        evals.insert("r".into(), r_zeta);

        evals
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
