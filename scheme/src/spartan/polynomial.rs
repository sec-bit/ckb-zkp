use crate::r1cs::Index;
use crate::Vec;
use math::{One, PairingEngine, Zero};

// ~eq(x, rx)
pub fn eval_eq<E: PairingEngine>(rx: &Vec<E::Fr>) -> Vec<E::Fr> {
    let base: usize = 2;
    let rlen = rx.len();
    let pow_len = base.pow(rlen as u32);

    let mut evals: Vec<E::Fr> = vec![E::Fr::one(); pow_len];
    let mut size = 1;
    for i in 0..rlen {
        let scalar = rx[rlen - i - 1];
        for j in 0..size {
            evals[size + j] = scalar * &evals[j]; // eval * scalar
            evals[j] = (E::Fr::one() - &scalar) * &evals[j]; // eval * (1- scalar)
        }
        size *= 2;
    }
    evals
}

pub fn eval_eq_x_y<E: PairingEngine>(rx: &Vec<E::Fr>, ry: &Vec<E::Fr>) -> E::Fr {
    assert_eq!(rx.len(), ry.len());
    let result = (0..rx.len())
        .map(|i| (E::Fr::one() - &rx[i]) * &(E::Fr::one() - &ry[i]) + &(rx[i] * &ry[i]))
        .product();
    result
}

// pub fn evaluate_value<E: PairingEngine>(value: &Vec<E::Fr>, r: &Vec<E::Fr>) -> E::Fr {
//     let eq_vec = eval_eq::<E>(&r);
//     let result = (0..value.len()).map(|i| value[i] * &eq_vec[i]).sum();
//     result
// }

pub fn sparse_evaluate_value<E: PairingEngine>(value: &Vec<E::Fr>, r: &Vec<E::Fr>) -> E::Fr {
    let num_bits = r.len();
    let result = value
        .iter()
        .filter(|&v| !v.is_zero())
        .enumerate()
        .map(|(i, v)| {
            let bits = (0..num_bits)
                .map(|shift_amount| ((i & (1 << (num_bits - shift_amount - 1))) > 0))
                .collect::<Vec<bool>>();
            let eq: E::Fr = (0..num_bits)
                .map(|j| if bits[j] { r[j] } else { E::Fr::one() - &r[j] })
                .product();
            eq * v
        })
        .sum();

    result
}

pub fn evaluate_mle<E: PairingEngine>(
    m_matrix: &Vec<Vec<(E::Fr, Index)>>,
    rx: &Vec<E::Fr>,
    ry: &Vec<E::Fr>,
) -> E::Fr {
    let evals_rx = eval_eq::<E>(&rx);
    let evals_ry = eval_eq::<E>(&ry);

    let mut sum = E::Fr::zero();

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

pub fn evaluate_matrix_vec<E: PairingEngine>(
    polys: &Vec<Vec<(E::Fr, Index)>>,
    z: &Vec<E::Fr>,
) -> Vec<E::Fr> {
    let mut ms = vec![E::Fr::zero(); polys.len()];
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

pub fn evaluate_matrix_vec_col<E: PairingEngine>(
    m_matrix: &Vec<Vec<(E::Fr, Index)>>,
    coeffs: &Vec<E::Fr>,
    num_rows: usize,
) -> Vec<E::Fr> {
    let mut ms = vec![E::Fr::zero(); num_rows];

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

pub fn combine_with_n<E: PairingEngine>(values: &Vec<E::Fr>, r: E::Fr) -> Vec<E::Fr> {
    let len = values.len() / 2;
    assert!(len.is_power_of_two());
    let mut new_values: Vec<E::Fr> = vec![E::Fr::zero(); len];
    for i in 0..len {
        new_values[i] = r * &values[i + len] + &((E::Fr::one() - &r) * &values[i]);
    }
    new_values
}

pub fn combine_with_r<E: PairingEngine>(values: &mut Vec<E::Fr>, r: E::Fr) {
    let len = values.len() / 2;
    assert!(len.is_power_of_two());
    for i in 0..len {
        values[i] = r * &values[i + len] + &((E::Fr::one() - &r) * &values[i]);
    }
    values.truncate(len);
}

pub fn bound_poly_var_bot<E: PairingEngine>(values: &mut Vec<E::Fr>, r: E::Fr) {
    let len = values.len() / 2;
    assert!(len.is_power_of_two());
    for i in 0..len {
        values[i] = r * &values[2 * i + 1] + &((E::Fr::one() - &r) * &values[2 * i]);
    }
    values.truncate(len);
}
