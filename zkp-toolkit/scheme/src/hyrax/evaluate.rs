use crate::hyrax::circuit::Gate;
use core::ops::{AddAssign, Neg};
use curve::ProjectiveCurve;
use math::{
    log2, msm::VariableBaseMSM, AffineCurve, Curve, Field, One, PrimeField, UniformRand, Zero,
};
use merlin::Transcript;
use rand::Rng;

pub fn eval_outputs<G: Curve>(
    outputs: &Vec<Vec<G::Fr>>,
    transcript: &mut Transcript,
) -> (G::Fr, Vec<G::Fr>, Vec<G::Fr>) {
    assert!(outputs.len() >= 1);
    let n = outputs.len().next_power_of_two();
    let log_n = log2(n);

    let g = outputs[0].len().next_power_of_two();
    let log_g = log2(g);

    let mut q_vec = Vec::new();
    for _ in 0..log_g {
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let q = random_bytes_to_fr::<G>(&buf);
        q_vec.push(q);
    }
    let eq_q_vec = eval_eq::<G>(&q_vec);
    let mut eq_qs_vec = Vec::new();
    for (_, output) in outputs.iter().enumerate() {
        let mut output = output.clone();
        output.append(&mut vec![G::Fr::zero(); g - output.len()]);
        let result = (0..g).map(|j| output[j] * &eq_q_vec[j]).sum();
        eq_qs_vec.push(result);
    }
    let mut q_aside_vec = Vec::new();
    for _ in 0..log_n {
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let q = random_bytes_to_fr::<G>(&buf);
        q_aside_vec.push(q);
    }
    let eq_q_aside_vec = eval_eq::<G>(&q_aside_vec);

    eq_qs_vec.append(&mut vec![G::Fr::zero(); n - eq_qs_vec.len()]);
    let result = (0..n).map(|i| eq_qs_vec[i] * &eq_q_aside_vec[i]).sum();

    (result, q_aside_vec, q_vec)
}

pub fn eval_eq_x_y<G: Curve>(rx: &Vec<G::Fr>, ry: &Vec<G::Fr>) -> G::Fr {
    assert_eq!(rx.len(), ry.len());
    let result = (0..rx.len())
        .map(|i| (G::Fr::one() - &rx[i]) * &(G::Fr::one() - &ry[i]) + &(rx[i] * &ry[i]))
        .product();
    result
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

pub fn packing_poly_commit<G: Curve, R: Rng>(
    generators: &Vec<G::Affine>,
    values: &Vec<G::Fr>,
    h: &G::Affine,
    rng: &mut R,
    is_blind: bool,
) -> (Vec<G::Affine>, Vec<G::Fr>) {
    let mut comms = Vec::new();
    let mut blinds = Vec::new();

    let n = values.len();
    let size = log2(n) as usize;
    let l_size = (2usize).pow((size / 2) as u32);
    let r_size = (2usize).pow((size - size / 2) as u32);
    assert_eq!(n, l_size * r_size);

    for i in 0..l_size {
        let mut blind = G::Fr::zero();
        if is_blind {
            blind = G::Fr::rand(rng);
        }
        blinds.push(blind);

        let commit = poly_commit_vec::<G>(
            generators,
            &values[i * r_size..(i + 1) * r_size].to_vec(),
            h,
            blind,
        );
        comms.push(commit);
    }
    (comms, blinds)
}

pub fn construct_matrix<G: Curve>(
    rs: (&Vec<G::Fr>, &Vec<G::Fr>, &Vec<G::Fr>),
    q_vec: (&Vec<G::Fr>, &Vec<G::Fr>, &Vec<G::Fr>),
    gates: &Vec<Gate>,
    u: (G::Fr, G::Fr),
    log_n: usize,
    log_g: usize,
) -> Vec<Vec<G::Fr>> {
    let (rs, r0, r1) = rs;
    let (q_aside_vec, q_left_vec, q_right_vec) = q_vec;
    let (u0, u1) = u;
    let mut rs_vec = Vec::new();
    rs_vec.extend(r0.clone());
    rs_vec.extend(r1.clone());

    let mut mm = (0..log_n + 2 * log_g + 1)
        .map(|_| vec![G::Fr::zero(); 4 * log_n + 6 * log_g + 3])
        .collect::<Vec<_>>();

    mm[0][0] = G::Fr::one().double();
    mm[0][1] = G::Fr::one();
    mm[0][2] = G::Fr::one();
    mm[0][3] = G::Fr::one();
    for i in 0..log_n - 1 {
        let mut r = G::Fr::one().neg();
        mm[i + 1][i * 4] = r;
        r *= &rs[i];
        mm[i + 1][i * 4 + 1] = r;
        r *= &rs[i];
        mm[i + 1][i * 4 + 2] = r;
        r *= &rs[i];
        mm[i + 1][i * 4 + 3] = r;
        mm[i + 1][i * 4 + 4] = G::Fr::one().double();
        mm[i + 1][i * 4 + 5] = G::Fr::one();
        mm[i + 1][i * 4 + 6] = G::Fr::one();
        mm[i + 1][i * 4 + 7] = G::Fr::one();
    }
    let mut r = G::Fr::one().neg();
    mm[log_n][(log_n - 1) * 4] = r;
    r *= &rs[log_n - 1];
    mm[log_n][(log_n - 1) * 4 + 1] = r;
    r *= &rs[log_n - 1];
    mm[log_n][(log_n - 1) * 4 + 2] = r;
    r *= &rs[log_n - 1];
    mm[log_n][(log_n - 1) * 4 + 3] = r;
    mm[log_n][(log_n - 1) * 4 + 4] = G::Fr::one().double();
    mm[log_n][(log_n - 1) * 4 + 5] = G::Fr::one();
    mm[log_n][(log_n - 1) * 4 + 6] = G::Fr::one();
    for i in 0..2 * log_g {
        let mut r = G::Fr::one().neg();
        mm[log_n + 1 + i][log_n * 4 + i * 3] = r;
        r *= &rs_vec[i];
        mm[log_n + 1 + i][log_n * 4 + i * 3 + 1] = r;
        r *= &rs_vec[i];
        mm[log_n + 1 + i][log_n * 4 + i * 3 + 2] = r;
        mm[log_n + 1 + i][log_n * 4 + i * 3 + 3] = G::Fr::one().double();
        mm[log_n + 1 + i][log_n * 4 + i * 3 + 4] = G::Fr::one();
        mm[log_n + 1 + i][log_n * 4 + i * 3 + 5] = G::Fr::one();
    }

    let eval_0 = eval_eq_x_y::<G>(q_aside_vec, rs);
    let eq_ql_vec = eval_eq::<G>(q_left_vec);
    let eq_qr_vec = eval_eq::<G>(q_right_vec);

    let mut add_gate_eval = G::Fr::zero();
    let mut mult_gate_eval = G::Fr::zero();

    let mut eq_node_r0_vec = Vec::new();
    let mut eq_node_r1_vec = Vec::new();
    for i in 0..2usize.pow(log_g as u32) {
        let node_vec = convert_to_bit::<G>(i, log_g);
        let eq_node_r0 = eval_eq_x_y::<G>(&node_vec, &r0);
        let eq_node_r1 = eval_eq_x_y::<G>(&node_vec, &r1);
        eq_node_r0_vec.push(eq_node_r0);
        eq_node_r1_vec.push(eq_node_r1);
    }

    for gate in gates.iter() {
        let eval = eval_0 * &(eq_ql_vec[gate.g] * &u0 + &(eq_qr_vec[gate.g] * &u1));
        if gate.op == 0 {
            add_gate_eval +=
                &((eq_node_r0_vec[gate.left_node] * &eq_node_r1_vec[gate.right_node]) * &eval);
        } else if gate.op == 1 {
            mult_gate_eval +=
                &(eq_node_r0_vec[gate.left_node] * &eq_node_r1_vec[gate.right_node] * &eval);
        }
    }
    mm[log_n + log_g * 2][log_n * 4 + log_g * 6] = add_gate_eval;
    mm[log_n + log_g * 2][log_n * 4 + log_g * 6 + 1] = add_gate_eval;
    mm[log_n + log_g * 2][log_n * 4 + log_g * 6 + 2] = mult_gate_eval;
    mm
}

pub fn convert_to_bit<G: Curve>(n: usize, log_g: usize) -> Vec<G::Fr> {
    let mut n_vec = Vec::new();
    let mut n = n;
    while n > 0 {
        if n % 2 == 0 {
            n_vec.push(G::Fr::zero());
        } else {
            n_vec.push(G::Fr::one());
        }
        n /= 2;
    }
    n_vec.extend(vec![G::Fr::zero(); log_g - n_vec.len()]);
    n_vec.reverse();
    n_vec
}
