use ark_ff::{FftField as Field, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_poly_commit::{LCTerm, LinearCombination};
use ark_std::{borrow::Borrow, format, vec, vec::Vec};

use crate::data_structures::LabeledPolynomial;
use crate::utils::scalar_mul;

use crate::ahp::Error;

pub trait EvaluationsProvider<F: Field> {
    fn get_lc_eval(&self, lc: &LinearCombination<F>, point: F) -> Result<F, Error>;
}

impl<'a, F: Field> EvaluationsProvider<F> for ark_poly_commit::Evaluations<F, F> {
    fn get_lc_eval(&self, lc: &LinearCombination<F>, point: F) -> Result<F, Error> {
        let key = (lc.label.clone(), point);
        self.get(&key)
            .copied()
            .ok_or_else(|| Error::MissingEvaluation(lc.label.clone()))
    }
}

impl<F: Field, T: Borrow<LabeledPolynomial<F>>> EvaluationsProvider<F> for Vec<T> {
    fn get_lc_eval(&self, lc: &LinearCombination<F>, point: F) -> Result<F, Error> {
        let mut acc = DensePolynomial::zero();
        for (coeff, term) in lc.iter() {
            acc = if let LCTerm::PolyLabel(label) = term {
                let poly = self
                    .iter()
                    .find(|p| {
                        let p: &LabeledPolynomial<F> = (*p).borrow();
                        p.label() == label
                    })
                    .ok_or_else(|| {
                        Error::MissingEvaluation(format!("Missing {} for {}", label, lc.label))
                    })?
                    .borrow();
                acc + scalar_mul(poly, coeff)
            } else {
                assert!(term.is_one());
                acc + DensePolynomial::from_coefficients_vec(vec![*coeff])
            };
        }

        let eval = acc.evaluate(&point);
        Ok(eval)
    }
}

#[cfg(test)]
mod test {
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_std::{test_rng, vec};

    use rand_core::RngCore;

    use super::*;

    fn make_polys<R: RngCore>(rng: &mut R) -> Vec<LabeledPolynomial<Fr>> {
        let a =
            LabeledPolynomial::<Fr>::new("a".into(), DensePolynomial::rand(10, rng), None, None);
        let b =
            LabeledPolynomial::<Fr>::new("b".into(), DensePolynomial::rand(10, rng), None, None);
        let c =
            LabeledPolynomial::<Fr>::new("c".into(), DensePolynomial::rand(10, rng), None, None);
        vec![a, b, c]
    }

    #[test]
    fn test_polynomial_vector() -> Result<(), Error> {
        let rng = &mut test_rng();
        let polys = make_polys(rng);

        let rands = vec![Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)];
        let terms: Vec<_> = polys
            .iter()
            .zip(rands.iter().cloned())
            .map(|(p, r)| (r, p.label().to_string()))
            .collect();
        let lc = LinearCombination::new("test", terms);

        let zeta = Fr::rand(rng);

        let lc_eval = polys.get_lc_eval(&lc, zeta)?;
        let eval: Fr = polys
            .iter()
            .zip(rands.iter())
            .map(|(p, r)| *r * p.evaluate(&zeta))
            .sum();
        assert_eq!(eval, lc_eval);
        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_with_missing_term() {
        let rng = &mut test_rng();
        let polys = make_polys(rng);

        let rands = vec![Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)];
        let mut terms: Vec<_> = polys
            .iter()
            .zip(rands.iter().cloned())
            .map(|(p, r)| (r, p.label().to_string()))
            .collect();
        terms.push((Fr::zero(), "absent".to_string()));
        let lc = LinearCombination::new("test", terms);

        let zeta = Fr::rand(rng);

        polys.get_lc_eval(&lc, zeta).unwrap();
    }
}
