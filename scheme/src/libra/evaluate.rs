use crate::libra::circuit::Gate;
use core::ops::AddAssign;
use curve::ProjectiveCurve;
use math::{msm::VariableBaseMSM, AffineCurve, Curve, Field, One, PrimeField, Zero};
use merlin::Transcript;

pub fn eval_output<G: Curve>(
    output: &Vec<G::Fr>,
    bit_size: usize,
    transcript: &mut Transcript,
) -> (G::Fr, Vec<G::Fr>) {
    let mut outputs = output.clone();
    let mut rs = Vec::new();
    outputs.append(&mut vec![
        G::Fr::zero();
        (2usize).pow(bit_size as u32) - outputs.len()
    ]);

    for _ in 0..bit_size {
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let r_j = random_bytes_to_fr::<G>(&buf);
        rs.push(r_j);
    }

    let eq_vec = eval_eq::<G>(&rs);
    let result = (0..outputs.len()).map(|i| outputs[i] * &eq_vec[i]).sum();
    (result, rs)
}

pub fn eval_eq_x_y<G: Curve>(rx: &Vec<G::Fr>, ry: &Vec<G::Fr>) -> G::Fr {
    assert_eq!(rx.len(), ry.len());
    let result = (0..rx.len())
        .map(|i| (G::Fr::one() - &rx[i]) * &(G::Fr::one() - &ry[i]) + &(rx[i] * &ry[i]))
        .product();
    result
}

// evaluate H_g(x) = \sum{ ~I(g, z) * ~f_1(g, x, y) * ~f_3(y)}
pub fn eval_hg<G: Curve>(
    evals_g_vec: &Vec<G::Fr>,
    v_vec: &Vec<G::Fr>,
    gates: &Vec<Gate<G>>,
    bit_size: usize,
) -> (Vec<G::Fr>, Vec<G::Fr>, Vec<G::Fr>) {
    let mut mul_hg_vec = vec![G::Fr::zero(); (2usize).pow(bit_size as u32)];
    let mut add_hg_vec1 = vec![G::Fr::zero(); (2usize).pow(bit_size as u32)];
    let mut add_hg_vec2 = vec![G::Fr::zero(); (2usize).pow(bit_size as u32)];
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

pub fn eval_fgu<G: Curve>(
    evals_g_vec: &Vec<G::Fr>,
    ru_vec: &Vec<G::Fr>,
    gates: &Vec<Gate<G>>,
    bit_size: usize,
) -> (Vec<G::Fr>, Vec<G::Fr>) {
    let mut mul_hg_vec = vec![G::Fr::zero(); (2usize).pow(bit_size as u32)];
    let mut add_hg_vec = vec![G::Fr::zero(); (2usize).pow(bit_size as u32)];
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

pub fn random_bytes_to_fr<G: Curve>(bytes: &[u8]) -> G::Fr {
    let mut r_bytes = [0u8; 31];
    // only use the first 31 bytes, to avoid value over modulus
    // we could mod modulus here too to keep value in range
    r_bytes.copy_from_slice(&bytes[0..31]);
    let r = <G::Fr as Field>::from_random_bytes(&r_bytes);
    r.unwrap()
}

pub fn poly_commit_vec<G: Curve>(
    generators: &Vec<G::Affine>,
    values: &Vec<G::Fr>,
    h: &G::Affine,
    blind_value: G::Fr,
) -> G::Affine {
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

pub fn combine_with_r<G: Curve>(values: &Vec<G::Fr>, r: G::Fr) -> Vec<G::Fr> {
    let len = values.len() / 2;
    assert!(len.is_power_of_two());
    let mut new_values: Vec<G::Fr> = vec![G::Fr::zero(); len];
    for i in 0..len {
        new_values[i] = r * &values[i + len] + &((G::Fr::one() - &r) * &values[i]);
    }
    new_values
}

pub fn eval_value<G: Curve>(value: &Vec<G::Fr>, r: &Vec<G::Fr>) -> G::Fr {
    let eq_vec = eval_eq::<G>(&r);
    let result = (0..value.len()).map(|i| value[i] * &eq_vec[i]).sum();
    result
}
