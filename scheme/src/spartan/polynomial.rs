use crate::r1cs::Index;
use crate::Vec;
use math::{Curve, One, Zero};

// ~eq(x, rx)
pub fn eval_eq<G: Curve>(rx: &Vec<G::Fr>) -> Vec<G::Fr> {
    let base: usize = 2;
    let rlen = rx.len();
    let pow_len = base.pow(rlen as u32);

    let mut evals: Vec<G::Fr> = vec![G::Fr::one(); pow_len];
    let mut size = 1;
    for i in 0..rlen {
        let scalar = rx[rlen - i - 1];
        for j in 0..size {
            evals[size + j] = scalar * &evals[j]; // eval * scalar
            evals[j] = (G::Fr::one() - &scalar) * &evals[j]; // eval * (1- scalar)
        }
        size *= 2;
    }
    evals
}

pub fn eval_eq_x_y<G: Curve>(rx: &Vec<G::Fr>, ry: &Vec<G::Fr>) -> G::Fr {
    assert_eq!(rx.len(), ry.len());
    let result = (0..rx.len())
        .map(|i| (G::Fr::one() - &rx[i]) * &(G::Fr::one() - &ry[i]) + &(rx[i] * &ry[i]))
        .product();
    result
}


// pub fn evaluate_value<E: PairingEngine>(value: &Vec<E::Fr>, r: &Vec<E::Fr>) -> E::Fr {
//     let eq_vec = eval_eq::<E>(&r);
//     let result = (0..value.len()).map(|i| value[i] * &eq_vec[i]).sum();
//     result
// }

pub fn sparse_evaluate_value<G: Curve>(value: &Vec<G::Fr>, r: &Vec<G::Fr>) -> G::Fr  {
    let num_bits = r.len();
    let result = value
        .iter()
        .filter(|&v| !v.is_zero())
        .enumerate()
        .map(|(i, v)| {
            let bits = (0..num_bits)
                .map(|shift_amount| ((i & (1 << (num_bits - shift_amount - 1))) > 0))
                .collect::<Vec<bool>>();
            let eq: G::Fr = (0..num_bits)
                .map(|j| if bits[j] { r[j] } else { G::Fr::one() - &r[j] })
                .product();
            eq * v
        })
        .sum();

    result
}

pub fn evaluate_mle<G: Curve>(
    m_matrix: &Vec<Vec<(G::Fr, Index)>>,
    rx: &Vec<G::Fr>,
    ry: &Vec<G::Fr>,
) -> G::Fr {
    let evals_rx = eval_eq::<G>(&rx);
    let evals_ry = eval_eq::<G>(&ry);

    let mut sum = G::Fr::zero();

    for (row, m_vec) in m_matrix.iter().enumerate() {
        for (val, col) in m_vec.iter() {
            match col {
                Index::Aux(i) => sum += &(evals_ry[*i] * &evals_rx[row] * val),
                Index::Input(i) => {
                    sum += &(evals_ry[*i + evals_ry.len() / 2] * &evals_rx[row] * val)
                }
            }
        }
    }

    sum
}

pub fn evaluate_matrix_vec<G: Curve>(
    polys: &Vec<Vec<(G::Fr, Index)>>,
    z: &Vec<G::Fr>,
) -> Vec<G::Fr> {
    let mut ms = vec![G::Fr::zero(); polys.len()];
    for (row, poly) in polys.iter().enumerate() {
        // assert_eq!(poly.len(), z.len());

        for (val, col) in poly.iter() {
            match col {
                Index::Aux(i) => ms[row] += &(*val * &z[*i]),
                Index::Input(i) => ms[row] += &(*val * &z[*i + z.len() / 2]),
            }
        }
    }
    ms
}

pub fn evaluate_matrix_vec_col<G: Curve>(
    m_matrix: &Vec<Vec<(G::Fr, Index)>>,
    coeffs: &Vec<G::Fr>,
    num_rows: usize,
) -> Vec<G::Fr> {
    let mut ms = vec![G::Fr::zero(); num_rows];

    for (row, m_vec) in m_matrix.iter().enumerate() {
        // assert_eq!(poly.len(), num_rows);
        for (val, col) in m_vec.iter() {
            match col {
                Index::Aux(i) => ms[*i] += &(*val * &coeffs[row]),
                Index::Input(i) => ms[*i + num_rows / 2] += &(*val * &coeffs[row]),
            }
        }
    }
    ms
}

pub fn combine_with_n<G: Curve>(values: &Vec<G::Fr>, r: G::Fr) -> Vec<G::Fr> {
    let len = values.len() / 2;
    assert!(len.is_power_of_two());
    let mut new_values: Vec<G::Fr> = vec![G::Fr::zero(); len];
    for i in 0..len {
        new_values[i] = r * &values[i + len] + &((G::Fr::one() - &r) * &values[i]);
    }
    new_values
}

pub fn combine_with_r<G: Curve>(values: &mut Vec<G::Fr>, r: G::Fr) {
    let len = values.len() / 2;
    assert!(len.is_power_of_two());
    for i in 0..len {
        values[i] = r * &values[i + len] + &((G::Fr::one() - &r) * &values[i]);
    }
    values.truncate(len);
}

pub fn bound_poly_var_bot<G: Curve>(values: &mut Vec<G::Fr>, r: G::Fr) {
    let len = values.len() / 2;
    assert!(len.is_power_of_two());
    for i in 0..len {
        values[i] = r * &values[2 * i + 1] + &((G::Fr::one() - &r) * &values[2 * i]);
    }
    values.truncate(len);
}
