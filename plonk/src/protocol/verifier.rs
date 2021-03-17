use ark_ff::FftField as Field;
use ark_poly_commit::QuerySet;

use rand_core::RngCore;

use crate::protocol::preprocessor::PreprocessorInfo;
use crate::protocol::Error;
use crate::utils::get_domain_generator;

pub struct Verifier<F: Field> {
    info: PreprocessorInfo<F>,

    alpha: Option<F>, // combination
    beta: Option<F>,  // permutation
    gamma: Option<F>, // permutation
    zeta: Option<F>,  // evaluation
}

pub struct FirstMsg<F: Field> {
    pub beta: F,
    pub gamma: F,
}

pub struct SecondMsg<F: Field> {
    pub alpha: F,
}

pub struct ThirdMsg<F: Field> {
    pub zeta: F,
}

impl<F: Field> Verifier<F> {
    pub fn init(info: PreprocessorInfo<F>) -> Result<Verifier<F>, Error> {
        Ok(Verifier {
            info,
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

    pub fn third_round<R: RngCore>(
        &mut self,
        rng: &mut R,
    ) -> Result<ThirdMsg<F>, Error> {
        let zeta = F::rand(rng);
        self.zeta = Some(zeta);

        Ok(ThirdMsg { zeta })
    }

    pub fn query_set(&self) -> QuerySet<F> {
        let zeta = self.zeta.unwrap();
        let g = get_domain_generator(self.info.domain_n);

        let mut query_set = QuerySet::new();

        query_set.insert(("w_0".into(), ("zeta".into(), zeta)));
        query_set.insert(("w_1".into(), ("zeta".into(), zeta)));
        query_set.insert(("w_2".into(), ("zeta".into(), zeta)));
        query_set.insert(("w_3".into(), ("zeta".into(), zeta)));

        query_set.insert(("z".into(), ("shifted_zeta".into(), zeta * g)));

        query_set.insert(("sigma_0".into(), ("zeta".into(), zeta)));
        query_set.insert(("sigma_1".into(), ("zeta".into(), zeta)));
        query_set.insert(("sigma_2".into(), ("zeta".into(), zeta)));
        query_set.insert(("q_arith".into(), ("zeta".into(), zeta)));

        query_set.insert(("t".into(), ("zeta".into(), zeta)));
        query_set.insert(("r".into(), ("zeta".into(), zeta)));
        query_set.insert(("pi".into(), ("zeta".into(), zeta)));

        query_set
    }

    // pub fn check_equality(
    //     &self,
    //     evals: &Evaluations<T, F>,
    // ) -> Result<bool, Error> {
    //     let alpha = self.alpha.unwrap();
    //     let beta = self.beta.unwrap();
    //     let gamma = self.gamma.unwrap();
    //     let zeta = self.zeta.unwrap();

    //     let domain_n = self.vk.domain_n();
    //     let g = get_domain_generator(domain_n);

    //     let v = domain_n.evaluate_vanishing_polynomial(zeta);

    //     let w_0 = Self::get_eval(&evals, "w_0", &zeta)?;
    //     let w_1 = Self::get_eval(&evals, "w_1", &zeta)?;
    //     let w_2 = Self::get_eval(&evals, "w_2", &zeta)?;
    //     let w_3 = Self::get_eval(&evals, "w_3", &zeta)?;

    //     let z_shifted = Self::get_eval(&evals, "z_shifted", &(zeta * g))?;

    //     let sigma_0 = Self::get_eval(&evals, "sigma_0", &zeta)?;
    //     let sigma_1 = Self::get_eval(&evals, "sigma_1", &zeta)?;
    //     let sigma_2 = Self::get_eval(&evals, "sigma_2", &zeta)?;
    //     let q_airth = Self::get_eval(&evals, "q_arith", &zeta)?;

    //     let t = Self::get_eval(&evals, "t", &zeta)?;
    //     let r = Self::get_eval(&evals, "r", &zeta)?;
    //     let pi = self.pi_poly.evaluate(&zeta);

    //     let lhs = t * v;
    //     let rhs = r + q_airth * pi
    //         - z_shifted
    //             * (w_0 + beta * sigma_0 + gamma)
    //             * (w_1 + beta * sigma_1 + gamma)
    //             * (w_2 + beta * sigma_2 + gamma)
    //             * (w_3 + gamma)
    //             * alpha;

    //     Ok(lhs == rhs)
    // }

    // fn get_eval(
    //     evals: &Evaluations<T, F>,
    //     label: &str,
    //     point: &F,
    // ) -> Result<F, Error> {
    //     let key = label.to_string();
    //     evals
    //         .get(&key)
    //         .map(|v| *v)
    //         .ok_or(Error::MissingEvaluation(key))
    // }
}
