use math::fft::{EvaluationDomain, Evaluations as EvaluationsOnDomain};
use math::PrimeField;
use rand::RngCore;

use crate::r1cs::SynthesisError;

use crate::marlin::ahp::arithmetic::BivariatePoly;
use crate::marlin::ahp::constraint_systems::ProverConstraintSystem;
use crate::marlin::ahp::indexer::IndexInfo;
use crate::marlin::ahp::{Error, AHP};
use crate::marlin::pc::{Evaluations, QuerySet};

pub struct VerifierState<F: PrimeField> {
    pub domain_h: EvaluationDomain<F>,
    pub domain_k: EvaluationDomain<F>,
    pub eta_a: Option<F>,
    pub eta_b: Option<F>,
    pub eta_c: Option<F>,
    pub alpha: Option<F>,
    pub beta: Option<F>,
    pub gamma: Option<F>,
}

#[derive(Copy, Clone)]
pub struct VerifierFirstMsg<F: PrimeField> {
    pub alpha: F,
    pub eta_a: F,
    pub eta_b: F,
    pub eta_c: F,
}

#[derive(Copy, Clone)]
pub struct VerifierSecondMsg<F: PrimeField> {
    pub beta: F,
}

impl<F: PrimeField> AHP<F> {
    pub fn verifier_first_round<R: RngCore>(
        index_info: IndexInfo,
        rng: &mut R,
    ) -> Result<(VerifierState<F>, VerifierFirstMsg<F>), Error> {
        if index_info.num_constraints != index_info.num_variables {
            return Err(Error::NonSquareMatrix);
        }
        let domain_h = EvaluationDomain::new(index_info.num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_k = EvaluationDomain::new(index_info.num_non_zeros)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        let msg = VerifierFirstMsg {
            alpha: Self::sample_element_outside_domain(&domain_h, rng),
            eta_a: F::rand(rng),
            eta_b: F::rand(rng),
            eta_c: F::rand(rng),
        };
        let state = VerifierState {
            domain_h,
            domain_k,
            eta_a: Some(msg.eta_a),
            eta_b: Some(msg.eta_b),
            eta_c: Some(msg.eta_c),
            alpha: Some(msg.alpha),
            beta: None,
            gamma: None,
        };
        Ok((state, msg))
    }

    pub fn verifier_second_round<R: RngCore>(
        mut state: VerifierState<F>,
        rng: &mut R,
    ) -> Result<(VerifierState<F>, VerifierSecondMsg<F>), Error> {
        let beta = Self::sample_element_outside_domain(&state.domain_h, rng);
        let msg = VerifierSecondMsg { beta };
        state.beta = Some(beta);
        Ok((state, msg))
    }

    pub fn verifier_third_round<R: RngCore>(
        mut state: VerifierState<F>,
        rng: &mut R,
    ) -> Result<VerifierState<F>, Error> {
        state.gamma = Some(F::rand(rng));
        Ok(state)
    }

    pub fn verifier_query_set(state: &VerifierState<F>) -> QuerySet<F> {
        let beta = state.beta.unwrap();
        let gamma = state.gamma.unwrap();
        let mut query_set = QuerySet::new();
        query_set.insert(("w".into(), beta));
        query_set.insert(("z_a".into(), beta));
        query_set.insert(("z_b".into(), beta));
        query_set.insert(("mask".into(), beta));
        query_set.insert(("t".into(), beta));
        query_set.insert(("g_1".into(), beta));
        query_set.insert(("h_1".into(), beta));
        query_set.insert(("g_2".into(), gamma));
        query_set.insert(("h_2".into(), gamma));
        query_set.insert(("a_row".into(), gamma));
        query_set.insert(("a_col".into(), gamma));
        query_set.insert(("a_val".into(), gamma));
        query_set.insert(("a_row_col".into(), gamma));
        query_set.insert(("b_row".into(), gamma));
        query_set.insert(("b_col".into(), gamma));
        query_set.insert(("b_val".into(), gamma));
        query_set.insert(("b_row_col".into(), gamma));
        query_set.insert(("c_row".into(), gamma));
        query_set.insert(("c_col".into(), gamma));
        query_set.insert(("c_val".into(), gamma));
        query_set.insert(("c_row_col".into(), gamma));
        query_set
    }

    fn sample_element_outside_domain<R: RngCore>(domain: &EvaluationDomain<F>, rng: &mut R) -> F {
        let mut t = F::rand(rng);
        while domain.evaluate_vanishing_polynomial(t) == F::zero() {
            t = F::rand(rng);
        }
        t
    }

    pub fn verifier_equality_check(
        public_input: &[F],
        evaluations: &Evaluations<F>,
        state: &VerifierState<F>,
    ) -> Result<bool, Error> {
        let alpha = state.alpha.unwrap();
        let eta_a = state.eta_a.unwrap();
        let eta_b = state.eta_b.unwrap();
        let eta_c = state.eta_c.unwrap();
        let beta = state.beta.unwrap();
        let gamma = state.gamma.unwrap();

        let domain_h = state.domain_h;
        let v_h_at_alpha = domain_h.evaluate_vanishing_polynomial(alpha);
        let v_h_at_beta = domain_h.evaluate_vanishing_polynomial(beta);
        let r_alpha_at_beta = domain_h.bivariate_eval(alpha, beta);

        let formatted_input = ProverConstraintSystem::format_public_input(public_input);
        let domain_x = EvaluationDomain::<F>::new(formatted_input.len())
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let v_x_at_beta = domain_x.evaluate_vanishing_polynomial(beta);
        let x_poly =
            &EvaluationsOnDomain::from_vec_and_domain(formatted_input, domain_x).interpolate();
        let x_at_beta = x_poly.evaluate(beta);

        // outer sumcheck
        let mask_at_beta = Self::get_eval(&evaluations, "mask", beta)?;
        let z_a_at_beta = Self::get_eval(&evaluations, "z_a", beta)?;
        let z_b_at_beta = Self::get_eval(&evaluations, "z_b", beta)?;
        let w_at_beta = Self::get_eval(&evaluations, "w", beta)?;
        let t_at_beta = Self::get_eval(&evaluations, "t", beta)?;
        let h_1_at_beta = Self::get_eval(&evaluations, "h_1", beta)?;
        let g_1_at_beta = Self::get_eval(&evaluations, "g_1", beta)?;

        let lhs = mask_at_beta
            + r_alpha_at_beta
                * (eta_a * z_a_at_beta + eta_b * z_b_at_beta + eta_c * z_a_at_beta * z_b_at_beta)
            - t_at_beta * (v_x_at_beta * w_at_beta + x_at_beta);
        let rhs = h_1_at_beta * v_h_at_beta + beta * g_1_at_beta;
        if lhs != rhs {
            println!("outer sumcheck");
            return Ok(false);
        }

        // inner sumcheck
        let domain_k = state.domain_k;
        let v_k_at_gamma = domain_k.evaluate_vanishing_polynomial(gamma);
        let k_size = domain_k.size_as_field_element;

        let h_2_at_gamma = Self::get_eval(&evaluations, "h_2", gamma)?;
        let g_2_at_gamma = Self::get_eval(&evaluations, "g_2", gamma)?;
        let alpha_beta = alpha * beta;

        let a_val_at_gamma = Self::get_eval(&evaluations, "a_val", gamma)?;
        let a_row_at_gamma = Self::get_eval(&evaluations, "a_row", gamma)?;
        let a_col_at_gamma = Self::get_eval(&evaluations, "a_col", gamma)?;
        let a_row_col_at_gamma = Self::get_eval(&evaluations, "a_row_col", gamma)?;
        let a_denom_at_gamma =
            alpha_beta - alpha * a_row_at_gamma - beta * a_col_at_gamma + a_row_col_at_gamma;

        let b_val_at_gamma = Self::get_eval(&evaluations, "b_val", gamma)?;
        let b_row_at_gamma = Self::get_eval(&evaluations, "b_row", gamma)?;
        let b_col_at_gamma = Self::get_eval(&evaluations, "b_col", gamma)?;
        let b_row_col_at_gamma = Self::get_eval(&evaluations, "b_row_col", gamma)?;
        let b_denom_at_gamma =
            alpha_beta - alpha * b_row_at_gamma - beta * b_col_at_gamma + b_row_col_at_gamma;

        let c_val_at_gamma = Self::get_eval(&evaluations, "c_val", gamma)?;
        let c_row_at_gamma = Self::get_eval(&evaluations, "c_row", gamma)?;
        let c_col_at_gamma = Self::get_eval(&evaluations, "c_col", gamma)?;
        let c_row_col_at_gamma = Self::get_eval(&evaluations, "c_row_col", gamma)?;
        let c_denom_at_gamma =
            alpha_beta - alpha * c_row_at_gamma - beta * c_col_at_gamma + c_row_col_at_gamma;

        let mut a_at_gamma = eta_a * a_val_at_gamma * b_denom_at_gamma * c_denom_at_gamma
            + eta_b * b_val_at_gamma * c_denom_at_gamma * a_denom_at_gamma
            + eta_c * c_val_at_gamma * a_denom_at_gamma * b_denom_at_gamma;
        a_at_gamma *= v_h_at_alpha * v_h_at_beta;
        let b_at_gamma = a_denom_at_gamma * b_denom_at_gamma * c_denom_at_gamma;
        let lhs = h_2_at_gamma * v_k_at_gamma;
        let rhs = a_at_gamma - b_at_gamma * (gamma * g_2_at_gamma + t_at_beta / k_size);

        Ok(lhs == rhs)
    }

    fn get_eval(evals: &Evaluations<F>, label: &str, point: F) -> Result<F, Error> {
        let key = (label.to_string(), point);
        evals
            .get(&key)
            .map(|v| *v)
            .ok_or(Error::MissingEval(label.to_string()))
    }
}
