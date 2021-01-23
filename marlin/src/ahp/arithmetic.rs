use ark_ff::{fields, PrimeField};
use ark_poly::{EvaluationDomain, Evaluations, MixedRadixEvaluationDomain};
use ark_std::{cfg_iter, cfg_iter_mut};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::ahp::Error;
use crate::pc::LabeledPolynomial;
use crate::{Cow, ToString, Vec};

pub trait BivariatePoly<F: PrimeField> {
    fn bivariate_eval(&self, x: F, y: F) -> F;
    fn batch_evals(&self, x: F) -> Vec<F>;
    fn diagonal_evals(&self) -> Vec<F>;
}

impl<F: PrimeField> BivariatePoly<F> for MixedRadixEvaluationDomain<F> {
    fn bivariate_eval(&self, x: F, y: F) -> F {
        if x != y {
            (self.evaluate_vanishing_polynomial(x) - self.evaluate_vanishing_polynomial(y))
                / (x - y)
        } else {
            self.size_as_field_element * x.pow(&[(self.size() as u64) - 1])
        }
    }

    fn batch_evals(&self, x: F) -> Vec<F> {
        let v_x = self.evaluate_vanishing_polynomial(x);
        let mut denoms: Vec<_> = self.elements().map(|u| x - u).collect();
        fields::batch_inversion(&mut denoms);
        cfg_iter_mut!(denoms).for_each(|u| *u *= v_x);
        denoms
    }

    fn diagonal_evals(&self) -> Vec<F> {
        let mut elements: Vec<_> = self
            .elements()
            .map(|u| self.size_as_field_element * u)
            .collect();
        elements[1..].reverse();
        elements
    }
}

#[derive(Clone, Debug)]
pub struct Matrix<F>(pub Vec<Vec<(F, usize)>>);

pub fn matrix_density<F>(m: &Matrix<F>) -> usize {
    if m.0.is_empty() {
        0
    } else {
        m.0.iter().map(|row| row.len()).sum()
    }
}

pub fn sort_matrix_columns<F>(m: &mut Matrix<F>) {
    for row in m.0.iter_mut() {
        if !is_in_ascending_order(&row, |(_, a), (_, b)| a < b) {
            row.sort_by(|(_, a), (_, b)| a.cmp(b));
        }
    }
}

fn is_in_ascending_order<T>(v: &[T], is_less_than: impl Fn(&T, &T) -> bool) -> bool {
    if v.is_empty() {
        true
    } else {
        let mut is_sorted = true;
        for i in 1..v.len() {
            is_sorted &= is_less_than(&v[i - 1], &v[i]);
            if !is_sorted {
                break;
            }
        }
        is_sorted
    }
}

#[derive(Clone, Debug)]
pub struct MatrixPolynomials<'a, F: PrimeField> {
    pub row: LabeledPolynomial<'a, F>,
    pub col: LabeledPolynomial<'a, F>,
    pub val: LabeledPolynomial<'a, F>,
    pub row_col: LabeledPolynomial<'a, F>,

    pub row_evals_on_k: Cow<'a, Evaluations<F>>,
    pub col_evals_on_k: Cow<'a, Evaluations<F>>,
    pub val_evals_on_k: Cow<'a, Evaluations<F>>,

    pub row_evals_on_b: Cow<'a, Evaluations<F>>,
    pub col_evals_on_b: Cow<'a, Evaluations<F>>,
    pub val_evals_on_b: Cow<'a, Evaluations<F>>,
    pub row_col_evals_on_b: Cow<'a, Evaluations<F>>, // reduce h_2 from 6k-6 to 3k-3
}

pub fn compose_matrix_polynomials<'a, F: PrimeField>(
    matrix_name: &str,
    matrix: &Matrix<F>,
    domain_x: MixedRadixEvaluationDomain<F>,
    domain_h: MixedRadixEvaluationDomain<F>,
    domain_k: MixedRadixEvaluationDomain<F>,
    domain_b: MixedRadixEvaluationDomain<F>,
) -> Result<MatrixPolynomials<'a, F>, Error> {
    let h_elements: Vec<_> = domain_h.elements().collect();
    let h_diag_evals: Vec<_> = domain_h.diagonal_evals();

    let mut row_vec = Vec::new();
    let mut col_vec = Vec::new();
    let mut val_vec = Vec::new();
    let mut denom_vec = Vec::new();
    let mut count = 0;
    for (i, row) in matrix.0.iter().enumerate() {
        for &(v, j) in row.iter() {
            let j = domain_h.reindex_by_subdomain(domain_x, j);
            row_vec.push(h_elements[j]);
            col_vec.push(h_elements[i]);
            val_vec.push(v);
            denom_vec.push(h_diag_evals[j]);
            count += 1;
        }
    }
    fields::batch_inversion(&mut denom_vec);
    cfg_iter_mut!(val_vec)
        .zip(denom_vec)
        .for_each(|(val, denom)| *val *= denom);

    // paddings
    for _ in 0..(domain_k.size() - count) {
        row_vec.push(h_elements[0]); // arbitrary of h
        col_vec.push(h_elements[0]);
        val_vec.push(F::zero());
    }
    let row_col_vec = cfg_iter!(row_vec)
        .zip(&col_vec)
        .map(|(r, c)| *r * c)
        .collect();

    let row_evals_on_k = Evaluations::from_vec_and_domain(row_vec, domain_k);
    let col_evals_on_k = Evaluations::from_vec_and_domain(col_vec, domain_k);
    let val_evals_on_k = Evaluations::from_vec_and_domain(val_vec, domain_k);
    let row_col_evals_on_k = Evaluations::from_vec_and_domain(row_col_vec, domain_k);

    let row = row_evals_on_k.clone().interpolate();
    let col = col_evals_on_k.clone().interpolate();
    let val = val_evals_on_k.clone().interpolate();
    let row_col = row_col_evals_on_k.interpolate();

    let row_evals_on_b = Evaluations::from_vec_and_domain(domain_b.fft(&row), domain_b);
    let col_evals_on_b = Evaluations::from_vec_and_domain(domain_b.fft(&col), domain_b);
    let val_evals_on_b = Evaluations::from_vec_and_domain(domain_b.fft(&val), domain_b);
    let row_col_evals_on_b = Evaluations::from_vec_and_domain(domain_b.fft(&row_col), domain_b);

    let name = matrix_name.to_string();

    Ok(MatrixPolynomials {
        row: LabeledPolynomial::new_owned(name.clone() + "_row", row, None, None),
        col: LabeledPolynomial::new_owned(name.clone() + "_col", col, None, None),
        val: LabeledPolynomial::new_owned(name.clone() + "_val", val, None, None),
        row_col: LabeledPolynomial::new_owned(name.clone() + "_row_col", row_col, None, None),

        row_evals_on_k: Cow::Owned(row_evals_on_k),
        col_evals_on_k: Cow::Owned(col_evals_on_k),
        val_evals_on_k: Cow::Owned(val_evals_on_k),

        row_evals_on_b: Cow::Owned(row_evals_on_b),
        col_evals_on_b: Cow::Owned(col_evals_on_b),
        val_evals_on_b: Cow::Owned(val_evals_on_b),
        row_col_evals_on_b: Cow::Owned(row_col_evals_on_b),
    })
}
