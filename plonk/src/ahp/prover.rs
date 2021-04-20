use ark_ff::{FftField as Field, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations as EvaluationsOnDomain, UVPolynomial,
};
use ark_std::{cfg_iter, string::ToString, vec, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::ahp::indexer::Index;
use crate::ahp::verifier::{FirstMsg, SecondMsg};
use crate::ahp::{AHPForPLONK, Error};
use crate::composer::{Composer, Witnesses};
use crate::data_structures::LabeledPolynomial;
use crate::utils::{pad_to_size, to_labeled};

pub struct ProverState<'a, F: Field> {
    index: &'a Index<F>,
    pi_4n: Vec<F>,

    w_0: Option<(Vec<F>, Vec<F>)>,
    w_1: Option<(Vec<F>, Vec<F>)>,
    w_2: Option<(Vec<F>, Vec<F>)>,
    w_3: Option<(Vec<F>, Vec<F>)>,

    z: Option<(Vec<F>, Vec<F>)>,

    beta: Option<F>,
    gamma: Option<F>,
}

pub struct FirstOracles<F: Field> {
    pub w_0: LabeledPolynomial<F>,
    pub w_1: LabeledPolynomial<F>,
    pub w_2: LabeledPolynomial<F>,
    pub w_3: LabeledPolynomial<F>,
}

impl<F: Field> FirstOracles<F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        vec![&self.w_0, &self.w_1, &self.w_2, &self.w_3].into_iter()
    }
}

pub struct SecondOracles<F: Field> {
    pub z: LabeledPolynomial<F>,
}

impl<F: Field> SecondOracles<F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        vec![&self.z].into_iter()
    }
}

pub struct ThirdOracles<F: Field> {
    pub t_0: LabeledPolynomial<F>,
    pub t_1: LabeledPolynomial<F>,
    pub t_2: LabeledPolynomial<F>,
    pub t_3: LabeledPolynomial<F>,
}

impl<F: Field> ThirdOracles<F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        vec![&self.t_0, &self.t_1, &self.t_2, &self.t_3].into_iter()
    }
}

impl<F: Field> AHPForPLONK<F> {
    pub fn prover_init<'a>(
        cs: &Composer<F>,
        index: &'a Index<F>,
    ) -> Result<ProverState<'a, F>, Error> {
        let domain_n = index.domain_n();
        let domain_4n = index.domain_4n();

        let pi = cs.public_inputs();
        let pi_n = pad_to_size(pi, domain_n.size());
        let pi_poly = EvaluationsOnDomain::from_vec_and_domain(pi_n, domain_n).interpolate();
        let pi_4n = domain_4n.coset_fft(&pi_poly);

        Ok(ProverState {
            index,
            pi_4n,

            w_0: None,
            w_1: None,
            w_2: None,
            w_3: None,

            z: None,

            beta: None,
            gamma: None,
        })
    }

    pub fn prover_first_round<'a>(
        mut ps: ProverState<'a, F>,
        cs: &Composer<F>,
    ) -> Result<(ProverState<'a, F>, FirstOracles<F>), Error> {
        let witnesses = cs.synthesize()?;
        let Witnesses { w_0, w_1, w_2, w_3 } = witnesses;

        let domain_n = ps.index.domain_n();
        let w_0_poly =
            EvaluationsOnDomain::from_vec_and_domain(w_0.clone(), domain_n).interpolate();
        let w_1_poly =
            EvaluationsOnDomain::from_vec_and_domain(w_1.clone(), domain_n).interpolate();
        let w_2_poly =
            EvaluationsOnDomain::from_vec_and_domain(w_2.clone(), domain_n).interpolate();
        let w_3_poly =
            EvaluationsOnDomain::from_vec_and_domain(w_3.clone(), domain_n).interpolate();

        let domain_4n = ps.index.domain_4n();
        let w_0_4n = domain_4n.coset_fft(&w_0_poly);
        let w_1_4n = domain_4n.coset_fft(&w_1_poly);
        let w_2_4n = domain_4n.coset_fft(&w_2_poly);
        let w_3_4n = domain_4n.coset_fft(&w_3_poly);

        let first_oracles = FirstOracles {
            w_0: to_labeled("w_0", w_0_poly),
            w_1: to_labeled("w_1", w_1_poly),
            w_2: to_labeled("w_2", w_2_poly),
            w_3: to_labeled("w_3", w_3_poly),
        };

        ps.w_0 = Some((w_0, w_0_4n));
        ps.w_1 = Some((w_1, w_1_4n));
        ps.w_2 = Some((w_2, w_2_4n));
        ps.w_3 = Some((w_3, w_3_4n));

        Ok((ps, first_oracles))
    }

    pub fn prover_second_round<'a>(
        mut ps: ProverState<'a, F>,
        msg: &FirstMsg<F>,
        ks: &[F; 4],
    ) -> Result<(ProverState<'a, F>, SecondOracles<F>), Error> {
        let w_0 = &ps.w_0.as_ref().unwrap().0;
        let w_1 = &ps.w_1.as_ref().unwrap().0;
        let w_2 = &ps.w_2.as_ref().unwrap().0;
        let w_3 = &ps.w_3.as_ref().unwrap().0;
        let FirstMsg { beta, gamma } = msg;

        let permutation_key = ps.index.permutation_key();
        let (z_poly, z, z_4n) = permutation_key.compute_z(
            ps.index.domain_n(),
            ps.index.domain_4n(),
            ks,
            (w_0, w_1, w_2, w_3),
            beta,
            gamma,
        );

        let second_oracles = SecondOracles {
            z: LabeledPolynomial::new("z".to_string(), z_poly, None, None),
        };

        ps.z = Some((z, z_4n));
        ps.beta = Some(*beta);
        ps.gamma = Some(*gamma);

        Ok((ps, second_oracles))
    }

    pub fn prover_third_round<'a>(
        ps: ProverState<'a, F>,
        msg: &SecondMsg<F>,
        ks: &[F; 4],
    ) -> Result<ThirdOracles<F>, Error> {
        let domain_n = ps.index.domain_n();
        let domain_4n = ps.index.domain_4n();

        let w_0_4n = &ps.w_0.as_ref().unwrap().1;
        let w_1_4n = &ps.w_1.as_ref().unwrap().1;
        let w_2_4n = &ps.w_2.as_ref().unwrap().1;
        let w_3_4n = &ps.w_3.as_ref().unwrap().1;
        let z_4n = &ps.z.as_ref().unwrap().1;

        let SecondMsg { alpha } = *msg;

        let arithmetic_key = ps.index.arithmetic_key();
        let t_arith =
            arithmetic_key.compute_quotient(domain_4n, (w_0_4n, w_1_4n, w_2_4n, w_3_4n), &ps.pi_4n);

        let permutation_key = ps.index.permutation_key();
        let t_perm = permutation_key.compute_quotient(
            domain_4n,
            ks,
            (w_0_4n, w_1_4n, w_2_4n, w_3_4n),
            z_4n,
            &ps.beta.unwrap(),
            &ps.gamma.unwrap(),
            &alpha,
        );

        let t: Vec<_> = cfg_iter!(t_arith)
            .zip(&t_perm)
            .zip(ps.index.v_4n_inversed())
            .map(|((t_arith, t_perm), vi)| (*t_arith + t_perm) * vi)
            .collect();

        let t_poly = DensePolynomial::from_coefficients_vec(domain_4n.coset_ifft(&t));

        let t_polys = Self::quad_split(domain_n.size(), t_poly);

        let third_oracles = ThirdOracles {
            t_0: LabeledPolynomial::new("t_0".into(), t_polys.0, None, None),
            t_1: LabeledPolynomial::new("t_1".into(), t_polys.1, None, None),
            t_2: LabeledPolynomial::new("t_2".into(), t_polys.2, None, None),
            t_3: LabeledPolynomial::new("t_3".into(), t_polys.3, None, None),
        };

        Ok(third_oracles)
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
            poly_0 = DensePolynomial::from_coefficients_vec(chunk.to_vec());
        }
        if coeffs.peek().is_some() {
            let chunk: Vec<_> = coeffs.by_ref().take(n).collect();
            poly_1 = DensePolynomial::from_coefficients_vec(chunk.to_vec());
        }
        if coeffs.peek().is_some() {
            let chunk: Vec<_> = coeffs.by_ref().take(n).collect();
            poly_2 = DensePolynomial::from_coefficients_vec(chunk.to_vec());
        }
        if coeffs.peek().is_some() {
            let chunk: Vec<_> = coeffs.by_ref().take(n).collect();
            poly_3 = DensePolynomial::from_coefficients_vec(chunk.to_vec());
        }

        (poly_0, poly_1, poly_2, poly_3)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::{Field, One, UniformRand};
    use ark_poly::{univariate::DensePolynomial, Polynomial};
    use ark_poly_commit::LinearCombination;
    use ark_std::test_rng;

    use super::*;
    use crate::ahp::Error;
    use crate::ahp::EvaluationsProvider;

    fn compare(n: usize, t: DensePolynomial<Fr>, zeta: Fr) -> Result<bool, Error> {
        let (t_0, t_1, t_2, t_3) = AHPForPLONK::quad_split(n, t.clone());

        let labeled_poly = |label: String, poly: DensePolynomial<Fr>| {
            LabeledPolynomial::new(label, poly, None, None)
        };
        let ts = vec![
            labeled_poly("t_0".to_string(), t_0),
            labeled_poly("t_1".to_string(), t_1),
            labeled_poly("t_2".to_string(), t_2),
            labeled_poly("t_3".to_string(), t_3),
        ];

        let t_lc = {
            let zeta_n = zeta.pow(&[n as u64]);
            let zeta_2n = zeta_n.square();

            LinearCombination::new(
                "t",
                vec![
                    (Fr::one(), "t_0"),
                    (zeta_n, "t_1"),
                    (zeta_2n, "t_2"),
                    (zeta_n * zeta_2n, "t_3"),
                ],
            )
        };
        let t_lc_zeta = ts.get_lc_eval(&t_lc, zeta)?;
        let t_zeta = t.evaluate(&zeta);
        Ok(t_lc_zeta == t_zeta)
    }

    #[test]
    fn test_quad_split_full() -> Result<(), Error> {
        let rng = &mut test_rng();
        let n = 7;

        let t = DensePolynomial::<Fr>::rand(4 * n - 1, rng);
        let zeta = Fr::rand(rng);
        let is_equal = compare(n, t, zeta)?;
        assert!(is_equal);
        Ok(())
    }

    #[test]
    fn test_quad_split_not_full() -> Result<(), Error> {
        let rng = &mut test_rng();
        let n = 7;

        let t = DensePolynomial::<Fr>::rand(2 * n, rng);
        let zeta = Fr::rand(rng);
        let is_equal = compare(n, t, zeta)?;
        assert!(is_equal);
        Ok(())
    }
}
