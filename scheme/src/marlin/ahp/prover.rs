#[cfg(feature = "parallel")]
use rayon::prelude::*;

use math::fft::{EvaluationDomain, Evaluations as EvaluationsOnDomain};
use math::PrimeField;
use rand::RngCore;

use crate::r1cs::{ConstraintSynthesizer, SynthesisError};

use crate::marlin::ahp::arithmetic::BivariatePoly;
use crate::marlin::ahp::constraint_systems::ProverConstraintSystem;
use crate::marlin::ahp::indexer::{Index, IndexInfo};
use crate::marlin::ahp::verifier::{VerifierFirstMsg, VerifierSecondMsg};
use crate::marlin::ahp::{Error, AHP};
use crate::marlin::pc::{LabeledPolynomial, Polynomial};

pub struct ProverState<'a, 'b, F: PrimeField> {
    index: &'a Index<'a, F>,

    formatted_input_assignment: Vec<F>,
    witness_assignment: Vec<F>,

    z_a: Vec<F>,
    z_b: Vec<F>,

    w: Option<LabeledPolynomial<'b, F>>,
    mask: Option<LabeledPolynomial<'b, F>>,
    z_m: Option<(LabeledPolynomial<'b, F>, LabeledPolynomial<'b, F>)>,

    verifier_msg: Option<VerifierFirstMsg<F>>,

    zk_bound: usize,

    domain_x: EvaluationDomain<F>,
    domain_h: EvaluationDomain<F>,
    domain_k: EvaluationDomain<F>,
}

impl<'a, 'b, F: PrimeField> ProverState<'a, 'b, F> {
    pub fn public_input(&self) -> Vec<F> {
        self.formatted_input_assignment[1..].to_vec()
    }
}

pub struct ProverFirstOracles<'b, F: PrimeField> {
    pub w: LabeledPolynomial<'b, F>,
    pub z_a: LabeledPolynomial<'b, F>,
    pub z_b: LabeledPolynomial<'b, F>,
    pub mask: LabeledPolynomial<'b, F>,
}

impl<'b, F: PrimeField> ProverFirstOracles<'b, F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<'b, F>> {
        vec![&self.w, &self.z_a, &self.z_b, &self.mask].into_iter()
    }
}

pub struct ProverSecondOracles<'b, F: PrimeField> {
    pub t: LabeledPolynomial<'b, F>,
    pub g_1: LabeledPolynomial<'b, F>,
    pub h_1: LabeledPolynomial<'b, F>,
}

impl<'b, F: PrimeField> ProverSecondOracles<'b, F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<'b, F>> {
        vec![&self.t, &self.g_1, &self.h_1].into_iter()
    }
}

pub struct ProverThirdOracles<'b, F: PrimeField> {
    pub g_2: LabeledPolynomial<'b, F>,
    pub h_2: LabeledPolynomial<'b, F>,
}

impl<'b, F: PrimeField> ProverThirdOracles<'b, F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<'b, F>> {
        vec![&self.g_2, &self.h_2].into_iter()
    }
}

impl<F: PrimeField> AHP<F> {
    // add assignments
    pub fn prover_init<'a, 'b, C: ConstraintSynthesizer<F>>(
        index: &'a Index<'a, F>,
        c: C,
    ) -> Result<ProverState<'a, 'b, F>, Error> {
        let mut pcs = ProverConstraintSystem::new();
        c.generate_constraints(&mut pcs)?;
        pcs.make_matrices_square();

        let ProverConstraintSystem {
            num_constraints,
            formatted_input_assignment,
            witness_assignment,
            ..
        } = pcs;
        let zk_bound = 1;
        let num_input_variables = formatted_input_assignment.len();
        let num_witness_variables = witness_assignment.len();
        let num_non_zeros = index.index_info.num_non_zeros;
        if index.index_info.num_constraints != num_constraints
            || index.index_info.num_constraints != num_input_variables + num_witness_variables
        {
            return Err(Error::InstanceDoesNotMatchIndex);
        }

        let inner_product = |row: &[(F, usize)]| {
            let mut acc = F::zero();
            for &(ref coeff, j) in row {
                let tmp = if j < num_input_variables {
                    formatted_input_assignment[j]
                } else {
                    witness_assignment[j - num_input_variables]
                };
                acc += &(if coeff.is_one() { tmp } else { tmp * coeff });
            }
            acc
        };
        let z_a = index.a.0.iter().map(|row| inner_product(row)).collect();
        let z_b = index.b.0.iter().map(|row| inner_product(row)).collect();

        let domain_x = EvaluationDomain::new(num_input_variables)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_h = EvaluationDomain::new(num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_k =
            EvaluationDomain::new(num_non_zeros).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        Ok(ProverState {
            index,
            formatted_input_assignment,
            witness_assignment,
            z_a: z_a,
            z_b: z_b,
            w: None,
            mask: None,
            z_m: None,
            verifier_msg: None,
            zk_bound,
            domain_x,
            domain_h,
            domain_k,
        })
    }

    // polynomial w, z_a, z_b, mask
    pub fn prover_first_round<'a, 'b, R: RngCore>(
        mut state: ProverState<'a, 'b, F>,
        rng: &mut R,
    ) -> Result<(ProverState<'a, 'b, F>, ProverFirstOracles<'b, F>), Error> {
        let zk_bound = state.zk_bound;
        let domain_h = state.domain_h;
        let domain_x = state.domain_x;

        let v_h = Self::vanishing_polynomial(domain_h.size());

        let x_poly = &EvaluationsOnDomain::from_vec_and_domain(
            state.formatted_input_assignment.clone(),
            domain_x,
        )
        .interpolate();
        let x_evals_on_h = domain_h.fft(&x_poly);

        let ratio = domain_h.size() / domain_x.size();

        let mut w_extended = state.witness_assignment.clone();
        w_extended.extend(vec![
            F::zero();
            domain_h.size()
                - domain_x.size()
                - state.witness_assignment.len()
        ]);
        let w_evals_on_h = math::cfg_into_iter!(0..domain_h.size())
            .map(|i| {
                if i % ratio == 0 {
                    F::zero()
                } else {
                    // z = [[x_0, w_0, ..., w_(ratio - 2)], [    x_1, w_(ratio-1), ..., w_(2*(ratio-1)-1)], ...]
                    //   = [[z_0, z_1, ...,   z_(ratio-1)], [z_ratio, z_(ratio+1), ...,     z_(2*ratio-1)], ...]
                    w_extended[i - (i / ratio) - 1] - &x_evals_on_h[i]
                }
            })
            .collect();

        let w_poly = &EvaluationsOnDomain::from_vec_and_domain(w_evals_on_h, domain_h)
            .interpolate()
            + &(&Polynomial::<F>::rand(zk_bound - 1, rng) * &v_h);
        let (w_poly, remainder) = w_poly.divide_by_vanishing_poly(domain_x).unwrap();
        assert!(remainder.is_zero());

        let z_a_poly = &EvaluationsOnDomain::from_vec_and_domain(state.z_a.clone(), domain_h)
            .interpolate()
            + &(&Polynomial::<F>::rand(zk_bound - 1, rng) * &v_h);

        let z_b_poly = &EvaluationsOnDomain::from_vec_and_domain(state.z_b.clone(), domain_h)
            .interpolate()
            + &(&Polynomial::<F>::rand(zk_bound - 1, rng) * &v_h);

        let mask_degree = 3 * domain_h.size() + 2 * zk_bound - 3;
        let mut mask_poly = Polynomial::<F>::rand(mask_degree, rng);
        let sigma = (mask_poly.divide_by_vanishing_poly(domain_h).unwrap().1)[0]; // r_0
        mask_poly[0] -= sigma; // forcing r_0 = 0, sum_over_h(mask_poly) = 0

        let w = LabeledPolynomial::new_owned("w".to_string(), w_poly, None, Some(zk_bound));
        let z_a = LabeledPolynomial::new_owned("z_a".to_string(), z_a_poly, None, Some(zk_bound));
        let z_b = LabeledPolynomial::new_owned("z_b".to_string(), z_b_poly, None, Some(zk_bound));
        let mask = LabeledPolynomial::new_owned("mask".to_string(), mask_poly, None, None);

        let oracles = ProverFirstOracles {
            w: w.clone(),
            z_a: z_a.clone(),
            z_b: z_b.clone(),
            mask: mask.clone(),
        };
        state.w = Some(w);
        state.mask = Some(mask);
        state.z_m = Some((z_a, z_b));
        Ok((state, oracles))
    }

    pub fn prover_first_round_degree_bounds(
        _info: &IndexInfo,
    ) -> impl Iterator<Item = Option<usize>> {
        vec![None; 4].into_iter()
    }

    pub fn prover_second_round<'a, 'b>(
        mut state: ProverState<'a, 'b, F>,
        verifier_msg: &VerifierFirstMsg<F>,
    ) -> Result<(ProverState<'a, 'b, F>, ProverSecondOracles<'b, F>), Error> {
        let domain_h = state.domain_h;
        let domain_x = EvaluationDomain::new(state.formatted_input_assignment.len())
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let VerifierFirstMsg {
            alpha,
            eta_a,
            eta_b,
            eta_c,
        } = *verifier_msg;

        // z_m
        let (z_a, z_b) = state.z_m.as_ref().unwrap();
        let z_c_poly = z_a.polynomial() * z_b.polynomial();
        let mut m_coeffs = z_c_poly.coeffs;
        math::cfg_iter_mut!(m_coeffs).for_each(|c| *c *= &eta_c);
        math::cfg_iter_mut!(m_coeffs)
            .zip(&z_a.polynomial().coeffs)
            .zip(&z_b.polynomial().coeffs)
            .for_each(|((c, a), b)| *c += (eta_a * a) + &(eta_b * b));
        let m_poly = Polynomial::from_coefficients_vec(m_coeffs);
        // r_alpha
        let r_alpha_evals_on_h = domain_h.batch_evals(alpha);
        let r_alpha_poly = Polynomial::from_coefficients_vec(domain_h.ifft(&r_alpha_evals_on_h));
        // t
        let mut t_evals_on_h = vec![F::zero(); domain_h.size()];
        let matrices = vec![&state.index.a, &state.index.b, &state.index.c];
        let etas = vec![eta_a, eta_b, eta_c];
        for (matrix, eta) in matrices.iter().zip(&etas) {
            for (i, row) in matrix.0.iter().enumerate() {
                for (coeff, j) in row.iter() {
                    let index = domain_h.reindex_by_subdomain(domain_x, *j);
                    t_evals_on_h[index] += *eta * coeff * &r_alpha_evals_on_h[i];
                }
            }
        }
        let t_poly = EvaluationsOnDomain::from_vec_and_domain(t_evals_on_h, domain_h).interpolate();
        // z
        let x_poly = EvaluationsOnDomain::from_vec_and_domain(
            state.formatted_input_assignment.clone(),
            domain_x,
        )
        .interpolate();
        let w_poly = state.w.as_ref().unwrap();
        let mut z_poly = w_poly.polynomial().mul_by_vanishing_poly(domain_x);
        math::cfg_iter_mut!(z_poly.coeffs)
            .zip(&x_poly.coeffs)
            .for_each(|(z, x)| *z += x);
        // h_1, g_1
        let mask_poly = state.mask.as_ref().unwrap().polynomial();
        let domain_size = *[
            mask_poly.coeffs.len(),
            r_alpha_poly.coeffs.len() + m_poly.coeffs.len(),
            t_poly.coeffs.len() + z_poly.coeffs.len(),
        ]
        .iter()
        .max()
        .unwrap();
        let domain =
            EvaluationDomain::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let mut r_alpha_evals = r_alpha_poly.evaluate_over_domain_by_ref(domain);
        let m_evals = m_poly.evaluate_over_domain_by_ref(domain);
        let t_evals = t_poly.evaluate_over_domain_by_ref(domain);
        let z_evals = z_poly.evaluate_over_domain_by_ref(domain);
        math::cfg_iter_mut!(r_alpha_evals.evals)
            .zip(&m_evals.evals)
            .zip(&t_evals.evals)
            .zip(z_evals.evals)
            .for_each(|(((r, m), t), z)| {
                *r *= m;
                *r -= *t * z
            });
        let q_1_poly = mask_poly + &r_alpha_evals.interpolate();
        let (h_1_poly, x_g_1_poly) = q_1_poly.divide_by_vanishing_poly(domain_h).unwrap();
        let g_1_poly = Polynomial::from_coefficients_slice(&x_g_1_poly.coeffs[1..]);
        let oracles = ProverSecondOracles {
            t: LabeledPolynomial::new_owned("t".to_string(), t_poly, None, None),
            h_1: LabeledPolynomial::new_owned("h_1".to_string(), h_1_poly, None, None),
            g_1: LabeledPolynomial::new_owned(
                "g_1".to_string(),
                g_1_poly,
                Some(domain_h.size() - 2),
                Some(state.zk_bound),
            ),
        };
        state.verifier_msg = Some(*verifier_msg);
        Ok((state, oracles))
    }

    pub fn prover_second_round_degree_bounds(
        info: &IndexInfo,
    ) -> impl Iterator<Item = Option<usize>> {
        let domain_h_size =
            EvaluationDomain::<F>::compute_size_of_domain(info.num_constraints).unwrap();
        vec![None, Some(domain_h_size - 2), None].into_iter()
    }

    pub fn prover_third_round<'a, 'b>(
        state: ProverState<'a, 'b, F>,
        verifier_msg: &VerifierSecondMsg<F>,
    ) -> Result<ProverThirdOracles<'b, F>, Error> {
        let beta = verifier_msg.beta;
        let ProverState {
            index,
            domain_h,
            domain_k,
            verifier_msg,
            ..
        } = state;
        let VerifierFirstMsg {
            alpha,
            eta_a,
            eta_b,
            eta_c,
        } = verifier_msg.expect("verifier's first message is empty");
        let v_h_at_alpha = domain_h.evaluate_vanishing_polynomial(alpha);
        let v_h_at_beta = domain_h.evaluate_vanishing_polynomial(beta);
        let (a_star, b_star, c_star) = (
            &index.a_star_polys,
            &index.b_star_polys,
            &index.c_star_polys,
        );

        let mut inverse_a = Vec::with_capacity(domain_k.size());
        let mut inverse_b = Vec::with_capacity(domain_k.size());
        let mut inverse_c = Vec::with_capacity(domain_k.size());
        for i in 0..domain_k.size() {
            inverse_a.push((beta - a_star.row_evals_on_k[i]) * (alpha - a_star.col_evals_on_k[i]));
            inverse_b.push((beta - b_star.row_evals_on_k[i]) * (alpha - b_star.col_evals_on_k[i]));
            inverse_c.push((beta - c_star.row_evals_on_k[i]) * (alpha - c_star.col_evals_on_k[i]));
        }
        math::fields::batch_inversion(&mut inverse_a);
        math::fields::batch_inversion(&mut inverse_b);
        math::fields::batch_inversion(&mut inverse_c);

        let mut t_evals_on_k = Vec::with_capacity(domain_k.size());
        for i in 0..domain_k.size() {
            let t = eta_a * a_star.val_evals_on_k[i] * inverse_a[i]
                + eta_b * b_star.val_evals_on_k[i] * inverse_b[i]
                + eta_c * c_star.val_evals_on_k[i] * inverse_c[i];
            t_evals_on_k.push(t * v_h_at_alpha * v_h_at_beta);
        }

        let t_poly = EvaluationsOnDomain::from_vec_and_domain(t_evals_on_k, domain_k).interpolate();
        let g_2_poly = Polynomial::from_coefficients_slice(&t_poly.coeffs[1..]);

        let denom_a: Vec<_> = math::cfg_iter!(a_star.row_evals_on_b.evals)
            .zip(&a_star.col_evals_on_b.evals)
            .zip(&a_star.row_col_evals_on_b.evals)
            .map(|((r, c), r_c)| beta * alpha - (alpha * r) - (beta * c) + r_c)
            .collect();
        let denom_b: Vec<_> = math::cfg_iter!(b_star.row_evals_on_b.evals)
            .zip(&b_star.col_evals_on_b.evals)
            .zip(&b_star.row_col_evals_on_b.evals)
            .map(|((r, c), r_c)| beta * alpha - (alpha * r) - (beta * c) + r_c)
            .collect();
        let denom_c: Vec<_> = math::cfg_iter!(c_star.row_evals_on_b.evals)
            .zip(&c_star.col_evals_on_b.evals)
            .zip(&c_star.row_col_evals_on_b.evals)
            .map(|((r, c), r_c)| beta * alpha - (alpha * r) - (beta * c) + r_c)
            .collect();

        let domain_b = EvaluationDomain::new(3 * domain_k.size() - 3)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        let a_evals_on_b = math::cfg_into_iter!(0..domain_b.size())
            .map(|i| {
                let tmp = eta_a * a_star.val_evals_on_b.evals[i] * denom_b[i] * denom_c[i]
                    + eta_b * b_star.val_evals_on_b.evals[i] * denom_c[i] * denom_a[i]
                    + eta_c * c_star.val_evals_on_b.evals[i] * denom_a[i] * denom_b[i];
                tmp * v_h_at_alpha * v_h_at_beta
            })
            .collect();
        let a_poly = EvaluationsOnDomain::from_vec_and_domain(a_evals_on_b, domain_b).interpolate();

        let b_evals_on_b = math::cfg_into_iter!(0..domain_b.size())
            .map(|i| denom_a[i] * denom_b[i] * denom_c[i])
            .collect();
        let b_poly = EvaluationsOnDomain::from_vec_and_domain(b_evals_on_b, domain_b).interpolate();

        let h_2_poly = (&a_poly - &(&b_poly * &t_poly))
            .divide_by_vanishing_poly(domain_k)
            .unwrap()
            .0;
        Ok(ProverThirdOracles {
            h_2: LabeledPolynomial::new_owned("h_2".to_string(), h_2_poly, None, None),
            g_2: LabeledPolynomial::new_owned(
                "g_2".to_string(),
                g_2_poly,
                Some(domain_k.size() - 2),
                None,
            ),
        })
    }

    pub fn prover_third_round_degree_bounds(
        info: &IndexInfo,
    ) -> impl Iterator<Item = Option<usize>> {
        let domain_k_size =
            EvaluationDomain::<F>::compute_size_of_domain(info.num_non_zeros).unwrap();
        vec![Some(domain_k_size - 2), None].into_iter()
    }

    fn vanishing_polynomial(domain_size: usize) -> Polynomial<F> {
        let mut coeffs = vec![F::zero(); domain_size + 1];
        coeffs[0] = -F::one();
        coeffs[domain_size] = F::one();
        Polynomial::from_coefficients_vec(coeffs)
    }
}
