use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations,
    GeneralEvaluationDomain, Polynomial, UVPolynomial,
};
use ark_std::{cfg_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::composer::Composer;
use crate::protocol::keygen;
use crate::protocol::keygen::ProverKey;
use crate::protocol::verifier::{FirstMsg, SecondMsg, ThirdMsg};
use crate::{get_generator, Error, Evals, LabeledPolynomial};

pub struct Prover<F: Field> {
    pk: ProverKey<F>,

    w_0: Option<(Vec<F>, Vec<F>)>,
    w_1: Option<(Vec<F>, Vec<F>)>,
    w_2: Option<(Vec<F>, Vec<F>)>,
    w_3: Option<(Vec<F>, Vec<F>)>,

    z: Option<(Vec<F>, Vec<F>)>,

    alpha: Option<F>,
    beta: Option<F>,
    gamma: Option<F>,
    zeta: Option<F>,
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
        let n = cs.size();
        let domain_n = GeneralEvaluationDomain::<F>::new(n)
            .ok_or(Error::PolynomialDegreeTooLarge)?;
        let domain_4n = GeneralEvaluationDomain::<F>::new(4 * n)
            .ok_or(Error::PolynomialDegreeTooLarge)?;

        let pk = keygen::generate_prover_key(cs, ks)?;

        Ok(Prover {
            pk,

            w_0: None,
            w_1: None,
            w_2: None,
            w_3: None,

            z: None,

            alpha: None,
            beta: None,
            gamma: None,
            zeta: None,
        })
    }

    pub fn first_round<'a>(
        &mut self,
        cs: &Composer<F>,
    ) -> Result<FirstOracles<'a, F>, Error> {
        let (w_0, w_1, w_2, w_3) = cs.synthesize()?;

        let domain = self.pk.domain_n();
        let w_0_poly =
            Evaluations::from_vec_and_domain(w_0.clone(), domain)
                .interpolate();
        let w_1_poly =
            Evaluations::from_vec_and_domain(w_1.clone(), domain)
                .interpolate();
        let w_2_poly =
            Evaluations::from_vec_and_domain(w_2.clone(), domain)
                .interpolate();
        let w_3_poly =
            Evaluations::from_vec_and_domain(w_3.clone(), domain)
                .interpolate();

        let coset = self.pk.domain_4n();
        let w_0_4n = coset.coset_fft(&w_0_poly);
        let w_1_4n = coset.coset_fft(&w_1_poly);
        let w_2_4n = coset.coset_fft(&w_2_poly);
        let w_3_4n = coset.coset_fft(&w_3_poly);

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
        let w_0_4n = &self.w_0.as_ref().unwrap().1;
        let w_1_4n = &self.w_1.as_ref().unwrap().1;
        let w_2_4n = &self.w_2.as_ref().unwrap().1;
        let w_3_4n = &self.w_3.as_ref().unwrap().1;
        let z_4n = &self.z.as_ref().unwrap().1;
        let SecondMsg { alpha } = msg;

        let domain_n = self.pk.domain_n();
        let domain_4n = self.pk.domain_4n();

        let arithmetic_key = self.pk.arithmetic_key();
        let q_0 = arithmetic_key.compute_quotient(
            domain_4n, w_0_4n, w_1_4n, w_2_4n, w_3_4n, alpha,
        );

        let permutation_key = self.pk.permutation_key();
        let q_1 = permutation_key.compute_quotient(
            domain_4n,
            (w_0_4n, w_1_4n, w_2_4n, w_3_4n),
            z_4n,
            &self.beta.unwrap(),
            &self.gamma.unwrap(),
            &alpha.square(),
        );

        let t: Vec<_> = cfg_iter!(q_0)
            .zip(&q_1)
            .zip(self.pk.v_4n_inversed())
            .map(|((q_0, q_1), vi)| (*q_0 + q_1) * vi)
            .collect();

        let t_poly = DensePolynomial::from_coefficients_vec(
            domain_4n.coset_ifft(&t),
        );

        {
            // some checks
            let gen = get_generator(domain_n);
            let v_alpha = &domain_n.evaluate_vanishing_polynomial(*alpha);

            let q_0_poly = DensePolynomial::from_coefficients_vec(
                domain_4n.coset_ifft(&q_0),
            );
            {
                println!("degree of q_0: {}", q_0_poly.degree());
                print!("checking q_0...");
                assert_eq!(q_0_poly.evaluate(&gen), F::zero());
                println!("done");
            }
            let q_0_alpha = q_0_poly.evaluate(alpha);

            let q_1_poly = DensePolynomial::from_coefficients_vec(
                domain_4n.coset_ifft(&q_1),
            );
            {
                println!("degree of q_1: {}", q_1_poly.degree());
                print!("checking q_1...");
                assert_eq!(q_1_poly.evaluate(&gen), F::zero());
                println!("done");
            }
            let q_1_alpha = q_1_poly.evaluate(alpha);

            {
                let t0: Vec<_> = cfg_iter!(q_0)
                    .zip(self.pk.v_4n_inversed())
                    .map(|(q, vi)| *q * vi)
                    .collect();
                let t0_poly = DensePolynomial::from_coefficients_vec(
                    domain_4n.coset_ifft(&t0),
                );
                let t0_alpha = t0_poly.evaluate(alpha);

                println!("degree of t0_poly: {}", t0_poly.degree());
                print!("checking t_0...");
                assert_eq!(q_0_alpha, t0_alpha * v_alpha);
                println!("done");
            }

            {
                let t1: Vec<_> = cfg_iter!(q_1)
                    .zip(self.pk.v_4n_inversed())
                    .map(|(q, vi)| *q * vi)
                    .collect();
                let t1_poly = DensePolynomial::from_coefficients_vec(
                    domain_4n.coset_ifft(&t1),
                );
                println!("degree of t1_poly: {}", t1_poly.degree());
                let tt_alpha = t1_poly.evaluate(alpha);

                print!("checking t_1...");
                assert_eq!(q_1_alpha, tt_alpha * v_alpha);
                println!("done");
            }

            let t_alpha = t_poly.evaluate(alpha);
            assert_eq!(q_0_alpha + q_1_alpha, t_alpha * v_alpha);

            println!("degree of t_poly: {}", t_poly.degree());
        }

        let (t_0_poly, t_1_poly, t_2_poly, t_3_poly) =
            Self::quad_split(domain_n.size(), t_poly);

        let third_oracles = ThirdOracles {
            t_0: LabeledPolynomial::new_owned("t_0".to_string(), t_0_poly),
            t_1: LabeledPolynomial::new_owned("t_1".to_string(), t_1_poly),
            t_2: LabeledPolynomial::new_owned("t_2".to_string(), t_2_poly),
            t_3: LabeledPolynomial::new_owned("t_3".to_string(), t_3_poly),
        };

        self.alpha = Some(*alpha);

        Ok(third_oracles)
    }

    pub fn evaluate<'a>(
        &mut self,
        third_msg: &ThirdMsg<F>,
        first_oracles: &FirstOracles<'a, F>,
        second_oracles: &SecondOracles<'a, F>,
        third_oracles: &ThirdOracles<'a, F>,
    ) -> Evals<F> {
        let ThirdMsg { zeta } = third_msg;
        self.zeta = Some(*zeta);

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
            let zeta_pows =
                vec![F::one(), zeta_n, zeta_2n, zeta_n * zeta_2n];

            third_oracles
                .iter()
                .zip(zeta_pows)
                .map(|(p, z)| p.evaluate(zeta) * z)
                .sum()
        };

        let (sigma_0_zeta, sigma_1_zeta, sigma_2_zeta, r_zeta) = {
            let arithmetic_key = self.pk.arithmetic_key();
            let arith_lin = arithmetic_key.compute_linearisation(
                &w_zeta[0],
                &w_zeta[1],
                &w_zeta[2],
                &w_zeta[3],
                zeta,
                &self.alpha.unwrap(),
            );
            let permutation_key = self.pk.permutation_key();
            let (sigma_0_zeta, sigma_1_zeta, sigma_2_zeta, perm_lin) =
                permutation_key.compute_linearisation(
                    (&w_zeta[0], &w_zeta[1], &w_zeta[2], &w_zeta[3]),
                    &z_shifted_zeta,
                    &second_oracles.z.polynomial(),
                    &self.beta.unwrap(),
                    &self.gamma.unwrap(),
                    zeta,
                    &self.alpha.unwrap().square(),
                );

            (
                sigma_0_zeta,
                sigma_1_zeta,
                sigma_2_zeta,
                (arith_lin + perm_lin).evaluate(zeta),
            )
        };

        evals.insert(("w_0".into(), *zeta), w_zeta[0]);
        evals.insert(("w_1".into(), *zeta), w_zeta[1]);
        evals.insert(("w_2".into(), *zeta), w_zeta[2]);
        evals.insert(("w_3".into(), *zeta), w_zeta[3]);
        evals.insert(("z_shifted".into(), *zeta), z_shifted_zeta);
        evals.insert(("sigma_0".into(), *zeta), sigma_0_zeta);
        evals.insert(("sigma_1".into(), *zeta), sigma_1_zeta);
        evals.insert(("sigma_2".into(), *zeta), sigma_2_zeta);
        evals.insert(("t".into(), *zeta), t_zeta);
        evals.insert(("r".into(), *zeta), r_zeta);

        evals
    }

    // TODO: degree bound
    fn quad_split(
        n: usize,
        poly: DensePolynomial<F>,
    ) -> (
        DensePolynomial<F>,
        DensePolynomial<F>,
        DensePolynomial<F>,
        DensePolynomial<F>,
    ) {
        (
            DensePolynomial::from_coefficients_vec(poly[0..n].to_vec()),
            DensePolynomial::from_coefficients_vec(
                poly[n..2 * n].to_vec(),
            ),
            DensePolynomial::from_coefficients_vec(
                poly[2 * n..3 * n].to_vec(),
            ),
            DensePolynomial::from_coefficients_vec(poly[3 * n..].to_vec()),
        )
    }
}
