use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial as Polynomial, EvaluationDomain,
    Evaluations, GeneralEvaluationDomain, UVPolynomial,
};
use ark_std::{cfg_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::composer::Composer;
use crate::protocol::keygen::ProverKey;
use crate::protocol::verifier::{FirstMsg, SecondMsg};
use crate::{Error, LabeledPolynomial};

pub struct Prover<F: Field> {
    pk: ProverKey<F>,

    w_0: Option<(Polynomial<F>, Vec<F>, Vec<F>)>,
    w_1: Option<(Polynomial<F>, Vec<F>, Vec<F>)>,
    w_2: Option<(Polynomial<F>, Vec<F>, Vec<F>)>,
    w_3: Option<(Polynomial<F>, Vec<F>, Vec<F>)>,

    z: Option<(Polynomial<F>, Vec<F>, Vec<F>)>,

    ks: [F; 4],
    domain_n: GeneralEvaluationDomain<F>,
    domain_4n: GeneralEvaluationDomain<F>,

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

pub struct SecondOracles<'a, F: Field> {
    pub z: LabeledPolynomial<'a, F>,
}

pub struct ThirdOracles<'a, F: Field> {
    pub t_0: LabeledPolynomial<'a, F>,
    pub t_1: LabeledPolynomial<'a, F>,
    pub t_2: LabeledPolynomial<'a, F>,
    pub t_3: LabeledPolynomial<'a, F>,
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

            w_0: None,
            w_1: None,
            w_2: None,
            w_3: None,

            z: None,

            ks,
            domain_n,
            domain_4n,

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
        let w_0_evals_ext = domain_4n.coset_fft(&w_0_poly);
        let w_1_evals_ext = domain_4n.coset_fft(&w_1_poly);
        let w_2_evals_ext = domain_4n.coset_fft(&w_2_poly);
        let w_3_evals_ext = domain_4n.coset_fft(&w_3_poly);

        let first_oracles = FirstOracles {
            w_0: LabeledPolynomial::new_owned(
                "w_0".to_string(),
                w_0_poly.clone(),
            ),
            w_1: LabeledPolynomial::new_owned(
                "w_1".to_string(),
                w_1_poly.clone(),
            ),
            w_2: LabeledPolynomial::new_owned(
                "w_2".to_string(),
                w_2_poly.clone(),
            ),
            w_3: LabeledPolynomial::new_owned(
                "w_3".to_string(),
                w_3_poly.clone(),
            ),
        };

        self.w_0 = Some((w_0_poly, w_0, w_0_evals_ext));
        self.w_1 = Some((w_1_poly, w_1, w_1_evals_ext));
        self.w_2 = Some((w_2_poly, w_2, w_2_evals_ext));
        self.w_3 = Some((w_3_poly, w_3, w_3_evals_ext));

        Ok(first_oracles)
    }

    pub fn second_round<'a>(
        &mut self,
        msg: &FirstMsg<F>,
    ) -> Result<SecondOracles<'a, F>, Error> {
        let w_0 = &self.w_0.as_ref().unwrap().1;
        let w_1 = &self.w_1.as_ref().unwrap().1;
        let w_2 = &self.w_2.as_ref().unwrap().1;
        let w_3 = &self.w_3.as_ref().unwrap().1;
        let FirstMsg { beta, gamma } = msg;

        let permutation_key = self.pk.get_permutation_key();
        let z = permutation_key.compute_z(
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
            z: LabeledPolynomial::new_owned("z".to_string(), z.0.clone()),
        };
        self.z = Some(z);
        self.beta = Some(*beta);
        self.gamma = Some(*gamma);

        Ok(second_oracles)
    }

    pub fn third_round<'a>(
        &mut self,
        msg: &SecondMsg<F>,
    ) -> Result<ThirdOracles<'a, F>, Error> {
        let w_0 = &self.w_0.as_ref().unwrap().2;
        let w_1 = &self.w_1.as_ref().unwrap().2;
        let w_2 = &self.w_2.as_ref().unwrap().2;
        let w_3 = &self.w_3.as_ref().unwrap().2;
        let z = &self.z.as_ref().unwrap().2;
        let SecondMsg { alpha } = msg;
        let alpha_2 = alpha.square();

        let arithmetic_key = self.pk.get_arithmetic_key();
        let q_0 = arithmetic_key.compute_quotient(
            self.domain_4n,
            w_0,
            w_1,
            w_2,
            w_3,
            alpha,
        );

        let permutation_key = self.pk.get_permutation_key();
        let q_1 = permutation_key.compute_quotient(
            self.domain_4n,
            w_0,
            w_1,
            w_2,
            w_3,
            z,
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
        let t_poly = Polynomial::from_coefficients_vec(
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

    fn quad_split(
        n: usize,
        poly: Polynomial<F>,
    ) -> (Polynomial<F>, Polynomial<F>, Polynomial<F>, Polynomial<F>) {
        (
            Polynomial::from_coefficients_vec(poly[0..n].to_vec()),
            Polynomial::from_coefficients_vec(poly[n..2 * n].to_vec()),
            Polynomial::from_coefficients_vec(poly[2 * n..3 * n].to_vec()),
            Polynomial::from_coefficients_vec(poly[3 * n..].to_vec()),
        )
    }
}
