use ark_ff::FftField as Field;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use rand::RngCore;

use crate::composer::Composer;
use crate::{Error, Evaluations, QuerySet};

pub struct Verifier<F: Field> {
    domain_n: GeneralEvaluationDomain<F>,

    alpha: Option<F>,
    beta: Option<F>,
    gamma: Option<F>,
    zeta: Option<F>,
}

pub struct FirstMsg<F: Field> {
    pub beta: F,
    pub gamma: F,
}

pub struct SecondMsg<F: Field> {
    pub alpha: F,
}

impl<F: Field> Verifier<F> {
    pub fn init(cs: &Composer<F>) -> Result<Verifier<F>, Error> {
        let n = cs.size();
        let domain_n = GeneralEvaluationDomain::<F>::new(n)
            .ok_or(Error::PolynomialDegreeTooLarge)?;

        Ok(Verifier {
            domain_n,
            alpha: None,
            beta: None,
            gamma: None,
            zeta: None,
        })
    }

    pub fn first_round<R: RngCore>(
        &mut self,
        rng: &mut R,
    ) -> Result<FirstMsg<F>, Error> {
        let beta = F::rand(rng);
        let gamma = F::rand(rng);
        self.beta = Some(beta);
        self.gamma = Some(gamma);

        Ok(FirstMsg { beta, gamma })
    }

    pub fn second_round<R: RngCore>(
        &mut self,
        rng: &mut R,
    ) -> Result<SecondMsg<F>, Error> {
        let alpha = F::rand(rng);
        self.alpha = Some(alpha);

        Ok(SecondMsg { alpha })
    }

    pub fn create_query_set<R: RngCore>(
        &mut self,
        rng: &mut R,
    ) -> QuerySet<F> {
        let zeta = F::rand(rng);
        self.zeta = Some(zeta);
        let g = Self::get_domain_generator(self.domain_n);

        let mut query_set = QuerySet::new();
        query_set.insert(("w_0".into(), zeta));
        query_set.insert(("w_1".into(), zeta));
        query_set.insert(("w_2".into(), zeta));
        query_set.insert(("w_3".into(), zeta));
        query_set.insert(("sigma_0".into(), zeta));
        query_set.insert(("sigma_1".into(), zeta));
        query_set.insert(("sigma_2".into(), zeta));

        query_set.insert(("z".into(), zeta));
        query_set.insert(("z_shifted".into(), zeta * g));
        query_set.insert(("t".into(), zeta));

        query_set
    }

    pub fn check_equality(
        verifier: Verifier<F>,
        evals: &Evaluations<F>,
    ) -> Result<bool, Error> {
        let alpha = verifier.alpha.unwrap();
        let beta = verifier.beta.unwrap();
        let gamma = verifier.gamma.unwrap();
        let zeta = verifier.zeta.unwrap();

        let domain_n = verifier.domain_n;
        let g = Self::get_domain_generator(domain_n);

        let v = domain_n.evaluate_vanishing_polynomial(zeta);

        let w_0 = Self::get_eval(&evals, "w_0", &zeta)?;
        let w_1 = Self::get_eval(&evals, "w_1", &zeta)?;
        let w_2 = Self::get_eval(&evals, "w_2", &zeta)?;
        let w_3 = Self::get_eval(&evals, "w_3", &zeta)?;

        let sigma_0 = Self::get_eval(&evals, "sigma_0", &zeta)?;
        let sigma_1 = Self::get_eval(&evals, "sigma_1", &zeta)?;
        let sigma_2 = Self::get_eval(&evals, "sigma_2", &zeta)?;

        let z = Self::get_eval(&evals, "z", &zeta)?;
        let z_shifted = Self::get_eval(&evals, "z_shifted", &(zeta * g))?;

        let t = Self::get_eval(&evals, "t", &zeta)?;

        Ok(false)
    }

    fn get_domain_generator(domain: GeneralEvaluationDomain<F>) -> F {
        domain.element(1)
    }

    fn get_eval(
        evals: &Evaluations<F>,
        label: &str,
        point: &F,
    ) -> Result<F, Error> {
        let key = (label.to_string(), *point);
        evals.get(&key).map(|v| *v).ok_or(Error::Other)
    }
}
