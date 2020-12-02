use crate::libra::circuit::Gate;
use core::ops::AddAssign;
use curve::ProjectiveCurve;
use math::{msm::VariableBaseMSM, AffineCurve, Field, One, PairingEngine, PrimeField, Zero};
use merlin::Transcript;

pub fn eval_output<E: PairingEngine>(
    output: &Vec<E::Fr>,
    bit_size: usize,
    transcript: &mut Transcript,
) -> (E::Fr, Vec<E::Fr>) {
    let mut outputs = output.clone();
    let mut rs = Vec::new();
    outputs.append(&mut vec![
        E::Fr::zero();
        (2usize).pow(bit_size as u32) - outputs.len()
    ]);

    for _ in 0..bit_size {
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let r_j = random_bytes_to_fr::<E>(&buf);
        rs.push(r_j);
    }

    let eq_vec = eval_eq::<E>(&rs);
    let result = (0..outputs.len()).map(|i| outputs[i] * &eq_vec[i]).sum();
    (result, rs)

    // for _ in 0..bit_size {
    //     let t = (2 as usize).pow((bit_size - 1) as u32);
    //     for j in 0..t - 1 {
    //         let mut buf = [0u8; 32];
    //         transcript.challenge_bytes(b"challenge_nextround", &mut buf);
    //         let r_j = random_bytes_to_fr::<E>(&buf);
    //         outputs[j] = outputs[j] * &(E::Fr::one() - &r_j) + &(outputs[j + t] * &r_j);
    //         rs.push(r_j);
    //     }
    // }

    // (outputs[0], rs)
}

pub fn eval_eq_x_y<E: PairingEngine>(rx: &Vec<E::Fr>, ry: &Vec<E::Fr>) -> E::Fr {
    assert_eq!(rx.len(), ry.len());
    let result = (0..rx.len())
        .map(|i| (E::Fr::one() - &rx[i]) * &(E::Fr::one() - &ry[i]) + &(rx[i] * &ry[i]))
        .product();
    result
}

// evaluate H_g(x) = \sum{ ~I(g, z) * ~f_1(g, x, y) * ~f_3(y)}
pub fn eval_hg<E: PairingEngine>(
    evals_g_vec: &Vec<E::Fr>,
    v_vec: &Vec<E::Fr>,
    gates: &Vec<Gate<E>>,
    bit_size: usize,
) -> (Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>) {
    let mut mul_hg_vec = vec![E::Fr::zero(); (2usize).pow(bit_size as u32)];
    let mut add_hg_vec1 = vec![E::Fr::zero(); (2usize).pow(bit_size as u32)];
    let mut add_hg_vec2 = vec![E::Fr::zero(); (2usize).pow(bit_size as u32)];
    for gate in gates.iter() {
        if gate.op == 1 {
            let (g, x, y) = (gate.g, gate.left_node, gate.right_node);
            mul_hg_vec[x] += &(evals_g_vec[g] * &v_vec[y]);
        } else if gate.op == 0 {
            let (g, x, y) = (gate.g, gate.left_node, gate.right_node);
            add_hg_vec1[x] += &evals_g_vec[g];
            add_hg_vec2[x] += &(evals_g_vec[g] * &v_vec[y]);
        }
    }
    (mul_hg_vec, add_hg_vec1, add_hg_vec2)
}

pub fn eval_fgu<E: PairingEngine>(
    evals_g_vec: &Vec<E::Fr>,
    ru_vec: &Vec<E::Fr>,
    gates: &Vec<Gate<E>>,
    bit_size: usize,
) -> (Vec<E::Fr>, Vec<E::Fr>) {
    let mut mul_hg_vec = vec![E::Fr::zero(); (2usize).pow(bit_size as u32)];
    let mut add_hg_vec = vec![E::Fr::zero(); (2usize).pow(bit_size as u32)];
    for gate in gates.iter() {
        if gate.op == 1 {
            let (g, x, y) = (gate.g, gate.left_node, gate.right_node);
            mul_hg_vec[y] += &(evals_g_vec[g] * &ru_vec[x]);
        } else if gate.op == 0 {
            let (g, x, y) = (gate.g, gate.left_node, gate.right_node);
            add_hg_vec[y] += &(evals_g_vec[g] * &ru_vec[x]);
        }
    }
    (mul_hg_vec, add_hg_vec)
}

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

pub fn random_bytes_to_fr<E: PairingEngine>(bytes: &[u8]) -> E::Fr {
    let mut r_bytes = [0u8; 31];
    // only use the first 31 bytes, to avoid value over modulus
    // we could mod modulus here too to keep value in range
    r_bytes.copy_from_slice(&bytes[0..31]);
    let r = <E::Fr as Field>::from_random_bytes(&r_bytes);
    r.unwrap()
}

pub fn poly_commit_vec<E: PairingEngine>(
    generators: &Vec<E::G1Affine>,
    values: &Vec<E::Fr>,
    h: &E::G1Affine,
    blind_value: E::Fr,
) -> E::G1Affine {
    let scalars = values.clone();
    let mut commit = VariableBaseMSM::multi_scalar_mul(
        &generators.clone(),
        &scalars
            .into_iter()
            .map(|e| e.into_repr())
            .collect::<Vec<_>>(),
    );

    commit.add_assign(&(h.mul(blind_value)));

    commit.into_affine()
}

pub fn combine_with_r<E: PairingEngine>(values: &Vec<E::Fr>, r: E::Fr) -> Vec<E::Fr> {
    let len = values.len() / 2;
    assert!(len.is_power_of_two());
    let mut new_values: Vec<E::Fr> = vec![E::Fr::zero(); len];
    for i in 0..len {
        new_values[i] = r * &values[i + len] + &((E::Fr::one() - &r) * &values[i]);
    }
    new_values
}

pub fn eval_value<E: PairingEngine>(value: &Vec<E::Fr>, r: &Vec<E::Fr>) -> E::Fr {
    let eq_vec = eval_eq::<E>(&r);
    let result = (0..value.len()).map(|i| value[i] * &eq_vec[i]).sum();
    result
}
