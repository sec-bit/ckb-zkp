use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations,
    GeneralEvaluationDomain, Polynomial, UVPolynomial,
};
use ark_std::{cfg_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::composer::Composer;
use crate::protocol::keygen::ProverKey;
use crate::protocol::verifier::{FirstMsg, SecondMsg, ThirdMsg};
use crate::{get_domain_generator, Error, Evals, LabeledPolynomial};

pub struct Prover<F: Field> {
    pk: ProverKey<F>,

    w_0_evals: Option<(Vec<F>, Vec<F>)>,
    w_1_evals: Option<(Vec<F>, Vec<F>)>,
    w_2_evals: Option<(Vec<F>, Vec<F>)>,
    w_3_evals: Option<(Vec<F>, Vec<F>)>,

    z_evals: Option<(Vec<F>, Vec<F>)>,

    ks: [F; 4],
    domain_n: GeneralEvaluationDomain<F>,
    domain_4n: GeneralEvaluationDomain<F>,

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

        let pk = cs.generate_prover_key()?;

        Ok(Prover {
            pk,

            w_0_evals: None,
            w_1_evals: None,
            w_2_evals: None,
            w_3_evals: None,

            z_evals: None,

            ks,
            domain_n,
            domain_4n,

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

        let domain_n = self.domain_n;
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

        let domain_4n = self.domain_4n;
        let w_0_ext = domain_4n.coset_fft(&w_0_poly);
        let w_1_ext = domain_4n.coset_fft(&w_1_poly);
        let w_2_ext = domain_4n.coset_fft(&w_2_poly);
        let w_3_ext = domain_4n.coset_fft(&w_3_poly);

        let first_oracles = FirstOracles {
            w_0: LabeledPolynomial::new_owned("w_0".to_string(), w_0_poly),
            w_1: LabeledPolynomial::new_owned("w_1".to_string(), w_1_poly),
            w_2: LabeledPolynomial::new_owned("w_2".to_string(), w_2_poly),
            w_3: LabeledPolynomial::new_owned("w_3".to_string(), w_3_poly),
        };

        self.w_0_evals = Some((w_0, w_0_ext));
        self.w_1_evals = Some((w_1, w_1_ext));
        self.w_2_evals = Some((w_2, w_2_ext));
        self.w_3_evals = Some((w_3, w_3_ext));

        Ok(first_oracles)
    }

    pub fn second_round<'a>(
        &mut self,
        msg: &FirstMsg<F>,
    ) -> Result<SecondOracles<'a, F>, Error> {
        let w_0 = &self.w_0_evals.as_ref().unwrap().0;
        let w_1 = &self.w_1_evals.as_ref().unwrap().0;
        let w_2 = &self.w_2_evals.as_ref().unwrap().0;
        let w_3 = &self.w_3_evals.as_ref().unwrap().0;
        let FirstMsg { beta, gamma } = msg;

        let permutation_key = self.pk.get_permutation_key();
        let (z_poly, z, z_ext) = permutation_key.compute_z(
            self.domain_n,
            self.domain_4n,
            w_0,
            w_1,
            w_2,
            w_3,
            beta,
            gamma,
            &self.ks,
        );

        let second_oracles = SecondOracles {
            z: LabeledPolynomial::new_owned("z".to_string(), z_poly),
        };

        self.z_evals = Some((z, z_ext));
        self.beta = Some(*beta);
        self.gamma = Some(*gamma);

        Ok(second_oracles)
    }

    pub fn third_round<'a>(
        &mut self,
        msg: &SecondMsg<F>,
    ) -> Result<ThirdOracles<'a, F>, Error> {
        let w_0_ext = &self.w_0_evals.as_ref().unwrap().1;
        let w_1_ext = &self.w_1_evals.as_ref().unwrap().1;
        let w_2_ext = &self.w_2_evals.as_ref().unwrap().1;
        let w_3_ext = &self.w_3_evals.as_ref().unwrap().1;
        let z_ext = &self.z_evals.as_ref().unwrap().1;
        let SecondMsg { alpha } = msg;

        let arithmetic_key = self.pk.get_arithmetic_key();
        let q_0 = arithmetic_key.compute_quotient(
            self.domain_4n,
            w_0_ext,
            w_1_ext,
            w_2_ext,
            w_3_ext,
            alpha,
        );

        let permutation_key = self.pk.get_permutation_key();
        let q_1 = permutation_key.compute_quotient(
            self.domain_4n,
            w_0_ext,
            w_1_ext,
            w_2_ext,
            w_3_ext,
            z_ext,
            &self.beta.unwrap(),
            &self.gamma.unwrap(),
            &alpha,
            &self.ks,
        );

        let t: Vec<_> = cfg_iter!(q_0)
            .zip(&q_1)
            .zip(self.pk.get_vanishing_inverse())
            .map(|((q_0, q_1), v)| (*q_0 + q_1) * v)
            .collect();
        let t_poly = DensePolynomial::from_coefficients_vec(
            self.domain_4n.coset_ifft(&t),
        );
        let (t_0_poly, t_1_poly, t_2_poly, t_3_poly) =
            Self::quad_split(self.domain_n.size(), t_poly);

        let third_oracles = ThirdOracles {
            t_0: LabeledPolynomial::new_owned("t_0".to_string(), t_0_poly),
            t_1: LabeledPolynomial::new_owned("t_1".to_string(), t_1_poly),
            t_2: LabeledPolynomial::new_owned("t_2".to_string(), t_2_poly),
            t_3: LabeledPolynomial::new_owned("t_3".to_string(), t_3_poly),
        };

        self.alpha = Some(*alpha);

        Ok(third_oracles)
    }

    pub fn fourth_round<'a>(
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
        let z_shifted_zeta = second_oracles
            .z
            .evaluate(&(get_domain_generator(self.domain_n) * zeta));
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
            let arithmetic_key = self.pk.get_arithmetic_key();
            let arith_lin = arithmetic_key.compute_linearisation(
                &w_zeta[0],
                &w_zeta[1],
                &w_zeta[2],
                &w_zeta[3],
                zeta,
                &self.alpha.unwrap(),
            );
            let permutation_key = self.pk.get_permutation_key();
            let (sigma_0_zeta, sigma_1_zeta, sigma_2_zeta, perm_lin) =
                permutation_key.compute_linearisation(
                    &w_zeta[0],
                    &w_zeta[1],
                    &w_zeta[2],
                    &w_zeta[3],
                    &z_shifted_zeta,
                    &second_oracles.z.polynomial(),
                    &self.beta.unwrap(),
                    &self.gamma.unwrap(),
                    zeta,
                    &self.alpha.unwrap().square(),
                    &self.ks,
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
