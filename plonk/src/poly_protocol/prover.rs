use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial as Polynomial, EvaluationDomain,
    Evaluations, GeneralEvaluationDomain,
};

use crate::composer::Composer;
use crate::poly_protocol::keygen::ProverKey;
use crate::poly_protocol::verifier::FirstMsg;
use crate::{Error, LabeledPolynomial};

pub struct Prover<F: Field> {
    pk: ProverKey<F>,

    w_0: Option<(Polynomial<F>, Evaluations<F>)>,
    w_1: Option<(Polynomial<F>, Evaluations<F>)>,
    w_2: Option<(Polynomial<F>, Evaluations<F>)>,
    w_3: Option<(Polynomial<F>, Evaluations<F>)>,

    z: Option<(Polynomial<F>, Evaluations<F>)>,

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
    pub fn init(cs: &Composer<F>) -> Result<Prover<F>, Error> {
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

            domain_n,
            domain_4n,
        })
    }

    pub fn first_round<'a>(
        mut prover: Prover<F>,
        cs: &Composer<F>,
    ) -> Result<(Self, FirstOracles<'a, F>), Error> {
        let (w_0_poly, w_1_poly, w_2_poly, w_3_poly) = cs.synthesize()?;

        let domain_4n = prover.domain_4n;
        let w_0_evals = Evaluations::from_vec_and_domain(
            prover.domain_4n.fft(&w_0_poly),
            domain_4n,
        );
        let w_1_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&w_1_poly),
            domain_4n,
        );
        let w_2_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&w_2_poly),
            domain_4n,
        );
        let w_3_evals = Evaluations::from_vec_and_domain(
            domain_4n.fft(&w_3_poly),
            domain_4n,
        );

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

        prover.w_0 = Some((w_0_poly, w_0_evals));
        prover.w_1 = Some((w_1_poly, w_1_evals));
        prover.w_2 = Some((w_2_poly, w_2_evals));
        prover.w_3 = Some((w_3_poly, w_3_evals));

        Ok((prover, first_oracles))
    }

    pub fn second_round<'a>(
        mut prover: Prover<F>,
        msg: &FirstMsg<F>,
    ) -> Result<(Self, SecondOracles<'a, F>), Error> {
        let arithmetic_key = prover.pk.get_arithmetic_key();
        let domain_n = prover.domain_n;

        Err(Error::Other)
    }

    fn compute_z_poly(
        &self,
        w_0: &Evaluations<F>,
        w_1: &Evaluations<F>,
        w_2: &Evaluations<F>,
        w_3: &Evaluations<F>,
    ) -> Polynomial<F> {
        let permutation_key = self.pk.get_permutation_key();
        let sigma_0_poly = permutation_key.sigma_0.0.clone();
        let sigma_1_poly = permutation_key.sigma_1.0.clone();
        let sigma_2_poly = permutation_key.sigma_2.0.clone();
        let sigma_3_poly = permutation_key.sigma_3.0.clone();

        let domain_n = self.domain_n;
        let roots: Vec<_> = domain_n.elements().collect();

        let sigma_0_evals = Evaluations::from_vec_and_domain(
            domain_n.fft(&sigma_0_poly),
            domain_n,
        );
        let sigma_1_evals = Evaluations::from_vec_and_domain(
            domain_n.fft(&sigma_1_poly),
            domain_n,
        );
        let sigma_2_evals = Evaluations::from_vec_and_domain(
            domain_n.fft(&sigma_2_poly),
            domain_n,
        );
        let sigma_3_evals = Evaluations::from_vec_and_domain(
            domain_n.fft(&sigma_3_poly),
            domain_n,
        );

        let mut z_evals = Vec::<F>::with_capacity(domain_n.size());
        let mut acc = F::one();

        Evaluations::from_vec_and_domain(z_evals, domain_n).interpolate()
    }
}
