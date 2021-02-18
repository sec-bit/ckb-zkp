use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial as Polynomial, EvaluationDomain,
    Evaluations, GeneralEvaluationDomain,
};

use crate::composer::Composer;
use crate::protocol::keygen::ProverKey;
use crate::protocol::verifier::FirstMsg;
use crate::{Error, LabeledPolynomial, Vec};

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
        })
    }

    pub fn first_round<'a>(
        mut prover: Prover<F>,
        cs: &Composer<F>,
    ) -> Result<(Self, FirstOracles<'a, F>), Error> {
        let (w_0, w_1, w_2, w_3) = cs.synthesize()?;

        let domain_n = prover.domain_n;
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

        let domain_4n = prover.domain_4n;
        let w_0_evals_ext = domain_4n.fft(&w_0_poly);
        let w_1_evals_ext = domain_4n.fft(&w_1_poly);
        let w_2_evals_ext = domain_4n.fft(&w_2_poly);
        let w_3_evals_ext = domain_4n.fft(&w_3_poly);

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

        prover.w_0 = Some((w_0_poly, w_0, w_0_evals_ext));
        prover.w_1 = Some((w_1_poly, w_1, w_1_evals_ext));
        prover.w_2 = Some((w_2_poly, w_2, w_2_evals_ext));
        prover.w_3 = Some((w_3_poly, w_3, w_3_evals_ext));

        Ok((prover, first_oracles))
    }

    pub fn second_round<'a>(
        mut prover: Prover<F>,
        msg: &FirstMsg<F>,
    ) -> Result<(Self, SecondOracles<'a, F>), Error> {
        let permutation_key = prover.pk.get_permutation_key();
        let w_0 = &prover.w_0.as_ref().unwrap().1;
        let w_1 = &prover.w_1.as_ref().unwrap().1;
        let w_2 = &prover.w_2.as_ref().unwrap().1;
        let w_3 = &prover.w_3.as_ref().unwrap().1;

        let z = permutation_key.compute_z_poly(
            prover.domain_n,
            prover.domain_4n,
            w_0,
            w_1,
            w_2,
            w_3,
            &msg.beta,
            &msg.gamma,
            &prover.ks,
        );

        let second_oracles = SecondOracles {
            z: LabeledPolynomial::new_owned("z".to_string(), z.0.clone()),
        };
        prover.z = Some(z);

        Ok((prover, second_oracles))
    }
}
