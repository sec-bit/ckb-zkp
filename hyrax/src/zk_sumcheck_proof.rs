use ark_ff::{to_bytes, Field, UniformRand, Zero};
use ark_poly::{polynomial::univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_std::log2;
use core::ops::{Deref, Neg};
use merlin::Transcript;
use rand::Rng;
use zkp_curve::{AffineCurve, Curve, ProjectiveCurve};

use crate::circuit::Gate;
use crate::commitment::ProductProof;
use crate::evaluate::{
    combine_with_r, construct_matrix, convert_to_bit, eval_eq, poly_commit_vec, random_bytes_to_fr,
};
use crate::params::SumCheckCommitmentSetupParameters;

pub struct ZkSumcheckProof<G: Curve> {
    pub prod_proof: ProductProof<G>,
    pub comm_a0: G::Affine,
    pub comm_c: G::Affine,
    pub comm_x: G::Affine,
    pub comm_y: G::Affine,
    pub comm_z: G::Affine,
    pub comm_polys: Vec<G::Affine>,
    pub comm_evals: Vec<G::Affine>,
    pub comm_deltas: Vec<G::Affine>,
    pub z_vec: Vec<G::Fr>,
    pub z_delta_vec: Vec<G::Fr>,
    pub zc: G::Fr,
}

impl<G: Curve> ZkSumcheckProof<G> {
    pub fn prover<R: Rng>(
        params: &SumCheckCommitmentSetupParameters<G>,
        claim: G::Fr,
        comm_a0: G::Affine,
        rc0: G::Fr,
        u: (G::Fr, G::Fr),
        q_vec: (&Vec<G::Fr>, &Vec<G::Fr>, &Vec<G::Fr>),
        gates: &Vec<Gate>,
        circuit_evals: &Vec<Vec<G::Fr>>,
        n: usize,
        ng: usize,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> (
        Self,
        Vec<G::Fr>,
        Vec<G::Fr>,
        Vec<G::Fr>,
        Vec<G::Fr>,
        Vec<G::Fr>,
    ) {
        let (u0, u1) = u;
        let (q_aside_vec, ql_vec, qr_vec) = q_vec;
        let mut comm_claim = comm_a0;
        let mut claim = claim;

        let log_g = ql_vec.len();
        let log_ng: usize = log2(ng) as usize;
        let log_n: usize = log2(n) as usize;

        let mut circuit_evals = circuit_evals.clone();

        assert_eq!(q_aside_vec.len(), log_n);
        assert_eq!(ql_vec.len(), qr_vec.len());

        let r_alpha_vec = (0..log_n + 2 * log_ng)
            .map(|_| G::Fr::rand(rng))
            .collect::<Vec<_>>();
        let r_alpha_eval_vec = (0..log_n + 2 * log_ng)
            .map(|_| G::Fr::rand(rng))
            .collect::<Vec<_>>();
        let mut polys = Vec::new();
        let mut comm_polys = Vec::new();
        let mut comm_evals = Vec::new();

        let eq_vec = eval_eq::<G>(&q_aside_vec);
        let eq_ql_vec = eval_eq::<G>(&ql_vec);
        let eq_qr_vec = eval_eq::<G>(&qr_vec);
        let xg_q = (0..eq_ql_vec.len())
            .map(|i| eq_ql_vec[i] * &u0 + &(eq_qr_vec[i] * &u1))
            .collect::<Vec<_>>();
        let mut temp_vec = Vec::new();
        for i in 0..xg_q.len() {
            let temp_p_vec = (0..eq_vec.len())
                .map(|t| eq_vec[t] * &xg_q[i])
                .collect::<Vec<_>>();
            temp_vec.push(temp_p_vec);
        }
        assert_eq!(temp_vec.len(), gates.len());

        // sumcheck #1
        let mut rs = Vec::new();
        let mut size = n;
        for j in 0..log_n {
            size /= 2;
            let mut eval_0 = G::Fr::zero();
            let mut eval_2 = G::Fr::zero();
            let mut eval_3 = G::Fr::zero();
            for (gate, temp_p_vec) in gates.iter().zip(temp_vec.iter()) {
                if gate.op == 0 {
                    eval_0 += &(0..size)
                        .map(|t| {
                            temp_p_vec[t]
                                * &(circuit_evals[gate.left_node][t]
                                    + &circuit_evals[gate.right_node][t])
                        })
                        .sum();
                    let temp_p_vec_tmp = combine_with_r::<G>(&temp_p_vec, G::Fr::from(2u32));
                    let temp_l_vec_tmp =
                        combine_with_r::<G>(&circuit_evals[gate.left_node], G::Fr::from(2u32));
                    let temp_r_vec_tmp =
                        combine_with_r::<G>(&circuit_evals[gate.right_node], G::Fr::from(2u32));
                    eval_2 += &(0..size)
                        .map(|t| temp_p_vec_tmp[t] * &(temp_l_vec_tmp[t] + &temp_r_vec_tmp[t]))
                        .sum();
                    let temp_p_vec_tmp = combine_with_r::<G>(&temp_p_vec, G::Fr::from(3u32));
                    let temp_l_vec_tmp =
                        combine_with_r::<G>(&circuit_evals[gate.left_node], G::Fr::from(3u32));
                    let temp_r_vec_tmp =
                        combine_with_r::<G>(&circuit_evals[gate.right_node], G::Fr::from(3u32));
                    eval_3 += &(0..size)
                        .map(|t| temp_p_vec_tmp[t] * &(temp_l_vec_tmp[t] + &temp_r_vec_tmp[t]))
                        .sum();
                } else {
                    eval_0 += &(0..size)
                        .map(|t| {
                            temp_p_vec[t]
                                * &(circuit_evals[gate.left_node][t]
                                    * &circuit_evals[gate.right_node][t])
                        })
                        .sum();
                    let temp_p_vec_tmp = combine_with_r::<G>(&temp_p_vec, G::Fr::from(2u32));
                    let temp_l_vec_tmp =
                        combine_with_r::<G>(&circuit_evals[gate.left_node], G::Fr::from(2u32));
                    let temp_r_vec_tmp =
                        combine_with_r::<G>(&circuit_evals[gate.right_node], G::Fr::from(2u32));
                    eval_2 += &(0..size)
                        .map(|t| temp_p_vec_tmp[t] * &(temp_l_vec_tmp[t] * &temp_r_vec_tmp[t]))
                        .sum();
                    let temp_p_vec_tmp = combine_with_r::<G>(&temp_p_vec, G::Fr::from(3u32));
                    let temp_l_vec_tmp =
                        combine_with_r::<G>(&circuit_evals[gate.left_node], G::Fr::from(3u32));
                    let temp_r_vec_tmp =
                        combine_with_r::<G>(&circuit_evals[gate.right_node], G::Fr::from(3u32));
                    eval_3 += &(0..size)
                        .map(|t| temp_p_vec_tmp[t] * &(temp_l_vec_tmp[t] * &temp_r_vec_tmp[t]))
                        .sum();
                }
            }
            let eval_1 = claim - &eval_0;

            // degree = 3
            // f(x) = ax^3 + bx^2 + cx + d
            // a = (-eval_0 + 3eval_1 - 3eval_2 + eval_3)/6
            let a_coeff = (eval_0.neg() + &eval_1.double() + &eval_1 - &eval_2.double() - &eval_2
                + &eval_3)
                * &G::Fr::from(6u32).inverse().unwrap();
            // b = (2eval_0 - 5eval_1 + 4eval_2 - eval_3)/2
            let b_coeff = (eval_0.double() - &(eval_1.double().double()) - &eval_1
                + &eval_2.double().double()
                - &eval_3)
                * &G::Fr::from(2u32).inverse().unwrap();
            // c = eval_1 - eval_0 - a - b
            let c_coeff = eval_1 - &eval_0 - &a_coeff - &b_coeff;
            // d = eval_0
            let d_coeff = eval_0;
            // degree = 3
            let coeffs = vec![d_coeff, c_coeff, b_coeff, a_coeff];
            polys.push(coeffs.clone());
            let poly = DensePolynomial::from_coefficients_vec(coeffs);
            let comm_poly = poly_commit_vec::<G>(
                &params.gen_4.generators,
                &poly.deref().to_vec(),
                &params.gen_4.h,
                r_alpha_vec[j],
            );
            transcript.append_message(b"comm_poly", &to_bytes!(comm_poly).unwrap());
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_nextround", &mut buf);
            let r_i = random_bytes_to_fr::<G>(&buf);

            let mut temp_p_vec_tmp = Vec::new();
            for i in 0..temp_vec.len() {
                let temp_p_vec = combine_with_r::<G>(&temp_vec[i], r_i);
                temp_p_vec_tmp.push(temp_p_vec);
            }
            temp_vec = temp_p_vec_tmp;

            let mut circuit_evals_tmp = Vec::new();
            for i in 0..circuit_evals.len() {
                let eval = combine_with_r::<G>(&circuit_evals[i], r_i);
                circuit_evals_tmp.push(eval);
            }
            circuit_evals = circuit_evals_tmp;

            let eval_ri = poly.evaluate(&r_i);
            let comm_eval = poly_commit_vec::<G>(
                &params.gen_1.generators,
                &vec![eval_ri],
                &params.gen_1.h,
                r_alpha_eval_vec[j],
            );
            transcript.append_message(b"comm_claim_per_round", &to_bytes!(comm_claim).unwrap());
            transcript.append_message(b"comm_eval", &to_bytes!(comm_eval).unwrap());

            rs.push(r_i);
            comm_polys.push(comm_poly);
            comm_evals.push(comm_eval);
            comm_claim = comm_eval;
            claim = eval_ri;
        }

        let v_vec = (0..circuit_evals.len())
            .map(|i| circuit_evals[i][0])
            .collect::<Vec<_>>();
        let mut temp_p_xg_vec = (0..temp_vec.len())
            .map(|i| temp_vec[i][0])
            .collect::<Vec<_>>();
        let eq_node_vec = (0..ng)
            .map(|i| {
                let node_vec = convert_to_bit::<G>(i, log_ng);
                eval_eq::<G>(&node_vec)
            })
            .collect::<Vec<_>>();

        let mut left_eq_vec = Vec::new();
        let mut right_eq_vec = Vec::new();
        for gate in gates.iter() {
            left_eq_vec.push(eq_node_vec[gate.left_node].clone());
            right_eq_vec.push(eq_node_vec[gate.right_node].clone());
        }
        // sumcheck #2
        size = ng;
        let mut r0 = Vec::new();
        let mut v_vec_left = v_vec.clone();
        for j in 0..log_ng {
            size /= 2;
            let mut eval_0 = G::Fr::zero();
            let mut eval_2 = G::Fr::zero();

            for ((temp_p_xg, gate), left_eq) in temp_p_xg_vec
                .iter()
                .zip(gates.iter())
                .zip(left_eq_vec.iter())
            {
                if gate.op == 0 {
                    eval_0 += &((0..size)
                        .map(|i| {
                            (left_eq[i] * temp_p_xg) * &(v_vec_left[i] + &v_vec[gate.right_node])
                        })
                        .sum());
                    let left_eq_tmp = combine_with_r::<G>(&left_eq, G::Fr::from(2u32));
                    let v_vec_left_tmp = combine_with_r::<G>(&v_vec_left, G::Fr::from(2u32));
                    eval_2 += &((0..size)
                        .map(|i| {
                            (left_eq_tmp[i] * temp_p_xg)
                                * &(v_vec_left_tmp[i] + &v_vec[gate.right_node])
                        })
                        .sum());
                } else if gate.op == 1 {
                    eval_0 += &((0..size)
                        .map(|i| {
                            (left_eq[i] * temp_p_xg) * &(v_vec_left[i] * &v_vec[gate.right_node])
                        })
                        .sum());
                    let left_eq_tmp = combine_with_r::<G>(&left_eq, G::Fr::from(2u32));
                    let v_vec_left_tmp = combine_with_r::<G>(&v_vec_left, G::Fr::from(2u32));
                    eval_2 += &((0..size)
                        .map(|i| {
                            (left_eq_tmp[i] * temp_p_xg)
                                * &(v_vec_left_tmp[i] * &v_vec[gate.right_node])
                        })
                        .sum());
                }
            }
            let eval_1 = claim - &eval_0;

            // degree = 2
            // f(x) = ax^2 + bx + c
            // a = (eval_0 - 2eval_1 + eval_2)/2
            let a_coeff =
                (eval_0 - &eval_1.double() + &eval_2) * &G::Fr::from(2u32).inverse().unwrap();
            // c = eval_0
            let c_coeff = eval_0;
            // b = eval_1 - a - c
            let b_coeff = eval_1 - &a_coeff - &c_coeff;

            let coeffs = vec![c_coeff, b_coeff, a_coeff];
            polys.push(coeffs.clone());
            let poly = DensePolynomial::from_coefficients_vec(coeffs);
            let comm_poly = poly_commit_vec::<G>(
                &params.gen_3.generators,
                &poly.deref().to_vec(),
                &params.gen_3.h,
                r_alpha_vec[log_n + j],
            );
            transcript.append_message(b"comm_poly", &to_bytes!(comm_poly).unwrap());
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_nextround", &mut buf);
            let r_i = random_bytes_to_fr::<G>(&buf);

            let mut left_eq_vec_tmp = Vec::new();
            for i in 0..left_eq_vec.len() {
                let left_eq = combine_with_r::<G>(&left_eq_vec[i], r_i);
                left_eq_vec_tmp.push(left_eq);
            }
            left_eq_vec = left_eq_vec_tmp;

            v_vec_left = combine_with_r::<G>(&v_vec_left, r_i);
            let eval_ri = poly.evaluate(&r_i);
            let comm_eval = poly_commit_vec::<G>(
                &params.gen_1.generators,
                &vec![eval_ri],
                &params.gen_1.h,
                r_alpha_eval_vec[log_n + j],
            );
            transcript.append_message(b"comm_claim_per_round", &to_bytes!(comm_claim).unwrap());
            transcript.append_message(b"comm_eval", &to_bytes!(comm_eval).unwrap());

            r0.push(r_i);
            comm_polys.push(comm_poly);
            comm_evals.push(comm_eval);
            comm_claim = comm_eval;
            claim = eval_ri;
        }

        let mut temp_p_xg_vec_tmp = Vec::new();
        for i in 0..temp_p_xg_vec.len() {
            let temp_p_xg = left_eq_vec[i][0] * &temp_p_xg_vec[i];
            temp_p_xg_vec_tmp.push(temp_p_xg);
        }
        temp_p_xg_vec = temp_p_xg_vec_tmp;

        let x = v_vec_left[0];

        // sumcheck #3
        size = ng;
        let mut r1 = Vec::new();
        let mut v_vec_right = v_vec.clone();
        for j in 0..log_ng {
            size /= 2;
            let mut eval_0 = G::Fr::zero();
            let mut eval_1 = G::Fr::zero();
            let mut eval_2 = G::Fr::zero();

            for ((temp_p_xg, gate), right_eq) in temp_p_xg_vec
                .iter()
                .zip(gates.iter())
                .zip(right_eq_vec.iter())
            {
                if gate.op == 0 {
                    eval_0 += &((0..size)
                        .map(|i| (right_eq[i] * temp_p_xg) * &(x + &v_vec_right[i]))
                        .sum());
                    eval_1 += &((size..size * 2)
                        .map(|i| (right_eq[i] * temp_p_xg) * &(x + &v_vec_right[i]))
                        .sum());
                    let right_eq_tmp = combine_with_r::<G>(&right_eq, G::Fr::from(2u32));
                    let v_vec_right_tmp = combine_with_r::<G>(&v_vec_right, G::Fr::from(2u32));
                    eval_2 += &((0..size)
                        .map(|i| (right_eq_tmp[i] * temp_p_xg) * &(x + &v_vec_right_tmp[i]))
                        .sum());
                } else if gate.op == 1 {
                    eval_0 += &((0..size)
                        .map(|i| (right_eq[i] * temp_p_xg) * &(x * &v_vec_right[i]))
                        .sum());
                    eval_1 += &((size..size * 2)
                        .map(|i| (right_eq[i] * temp_p_xg) * &(x * &v_vec_right[i]))
                        .sum());
                    let right_eq_tmp = combine_with_r::<G>(&right_eq, G::Fr::from(2u32));
                    let v_vec_right_tmp = combine_with_r::<G>(&v_vec_right, G::Fr::from(2u32));
                    eval_2 += &((0..size)
                        .map(|i| (right_eq_tmp[i] * temp_p_xg) * &(x * &v_vec_right_tmp[i]))
                        .sum());
                }
            }
            let eval_1 = claim - &eval_0;

            // degree = 2
            // f(x) = ax^2 + bx + c
            // a = (eval_0 - 2eval_1 + eval_2)/2
            let a_coeff =
                (eval_0 - &eval_1.double() + &eval_2) * &G::Fr::from(2u32).inverse().unwrap();
            // c = eval_0
            let c_coeff = eval_0;
            // b = eval_1 - a - c
            let b_coeff = eval_1 - &a_coeff - &c_coeff;

            let coeffs = vec![c_coeff, b_coeff, a_coeff];
            polys.push(coeffs.clone());
            let poly = DensePolynomial::from_coefficients_vec(coeffs);
            let comm_poly = poly_commit_vec::<G>(
                &params.gen_3.generators,
                &poly.deref().to_vec(),
                &params.gen_3.h,
                r_alpha_vec[log_n + log_ng + j],
            );
            transcript.append_message(b"comm_poly", &to_bytes!(comm_poly).unwrap());
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_nextround", &mut buf);
            let r_i = random_bytes_to_fr::<G>(&buf);

            let mut right_eq_vec_tmp = Vec::new();
            for i in 0..right_eq_vec.len() {
                let right_eq = combine_with_r::<G>(&right_eq_vec[i], r_i);
                right_eq_vec_tmp.push(right_eq);
            }
            right_eq_vec = right_eq_vec_tmp;

            v_vec_right = combine_with_r::<G>(&v_vec_right, r_i);
            let eval_ri = poly.evaluate(&r_i);
            let comm_eval = poly_commit_vec::<G>(
                &params.gen_1.generators,
                &vec![eval_ri],
                &params.gen_1.h,
                r_alpha_eval_vec[log_n + log_g + j],
            );
            transcript.append_message(b"comm_claim_per_round", &to_bytes!(comm_claim).unwrap());
            transcript.append_message(b"comm_eval", &to_bytes!(comm_eval).unwrap());

            r1.push(r_i);
            comm_polys.push(comm_poly);
            comm_evals.push(comm_eval);
            comm_claim = comm_eval;
            claim = eval_ri;
        }
        let y = v_vec_right[0];

        let m_vec = construct_matrix::<G>((&rs, &r0, &r1), q_vec, gates, u, log_n, log_ng);

        let mut pie_vec = Vec::new();
        for i in 0..polys.len() {
            pie_vec.extend(&polys[i]);
        }
        pie_vec.push(x);
        pie_vec.push(y);
        pie_vec.push(x * &y);

        let (
            (prod_proof, comm_x, comm_y, comm_z),
            comm_deltas,
            comm_c,
            z_vec,
            z_delta_vec,
            zc,
            blind_vec,
        ) = Self::sumcheck_prover::<R>(
            params,
            (x, y),
            log_ng,
            log_n,
            &m_vec,
            &pie_vec,
            &r_alpha_vec,
            rc0,
            rng,
            transcript,
        );

        let proof = Self {
            prod_proof,
            comm_a0,
            comm_c,
            comm_x,
            comm_y,
            comm_z,
            comm_polys,
            comm_evals,
            comm_deltas,
            z_vec,
            z_delta_vec,
            zc,
        };

        (proof, rs, r0, r1, vec![x, y], blind_vec)
    }

    pub fn sumcheck_prover<R: Rng>(
        params: &SumCheckCommitmentSetupParameters<G>,
        xy: (G::Fr, G::Fr),
        log_g: usize,
        log_n: usize,
        m_vec: &Vec<Vec<G::Fr>>,
        pie_vec: &Vec<G::Fr>,
        r_alpha_vec: &Vec<G::Fr>,
        rc0: G::Fr,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> (
        (ProductProof<G>, G::Affine, G::Affine, G::Affine),
        Vec<G::Affine>,
        G::Affine,
        Vec<G::Fr>,
        Vec<G::Fr>,
        G::Fr,
        Vec<G::Fr>,
    ) {
        let (x, y) = xy;
        let z = x * &y;

        let rx = G::Fr::rand(rng);
        let ry = G::Fr::rand(rng);
        let rz = G::Fr::rand(rng);
        let prod_proof =
            ProductProof::prover::<R>(&params.gen_1, x, rx, y, ry, z, rz, rng, transcript);

        let mut r_delta_vec: Vec<G::Fr> = Vec::new();
        let mut d_vec: Vec<G::Fr> = Vec::new();
        let mut delta_vec = (0..log_n)
            .map(|_| {
                let d3 = G::Fr::rand(rng);
                let d2 = G::Fr::rand(rng);
                let d1 = G::Fr::rand(rng);
                let d0 = G::Fr::rand(rng);
                let r_delta = G::Fr::rand(rng);
                d_vec.push(d3);
                d_vec.push(d2);
                d_vec.push(d1);
                d_vec.push(d0);
                r_delta_vec.push(r_delta);
                let delta_comm = poly_commit_vec::<G>(
                    &params.gen_4.generators,
                    &vec![d3, d2, d1, d0],
                    &params.gen_4.h,
                    r_delta,
                );
                transcript.append_message(b"comm_delta", &to_bytes!(delta_comm).unwrap());
                delta_comm
            })
            .collect::<Vec<G::Affine>>();

        let delta_vec2 = (0..2 * log_g)
            .map(|_| {
                let d2 = G::Fr::rand(rng);
                let d1 = G::Fr::rand(rng);
                let d0 = G::Fr::rand(rng);
                let r_delta = G::Fr::rand(rng);
                d_vec.push(d2);
                d_vec.push(d1);
                d_vec.push(d0);
                r_delta_vec.push(r_delta);
                let delta_comm = poly_commit_vec::<G>(
                    &params.gen_3.generators,
                    &vec![d2, d1, d0],
                    &params.gen_3.h,
                    r_delta,
                );
                transcript.append_message(b"comm_delta", &to_bytes!(delta_comm).unwrap());
                delta_comm
            })
            .collect::<Vec<G::Affine>>();
        delta_vec.extend(delta_vec2);

        let rou_vec = (0..log_n + 2 * log_g + 1)
            .map(|_| {
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"challenge_nextround", &mut buf);
                random_bytes_to_fr::<G>(&buf)
            })
            .collect::<Vec<_>>();

        let j_vec = (0..4 * log_n + 6 * log_g + 3)
            .map(|k| {
                (0..log_n + 2 * log_g + 1)
                    .map(|j| rou_vec[j] * &m_vec[j][k])
                    .sum()
            })
            .collect::<Vec<G::Fr>>();

        let rc = G::Fr::rand(rng);
        let prod_jd_star = (0..4 * log_n + 6 * log_g)
            .map(|k| j_vec[k] * &d_vec[k])
            .sum();
        let j_x = j_vec[4 * log_n + 6 * log_g];
        let j_y = j_vec[4 * log_n + 6 * log_g + 1];
        let j_z = j_vec[4 * log_n + 6 * log_g + 2];

        let comm_c = poly_commit_vec::<G>(
            &params.gen_1.generators,
            &vec![prod_jd_star],
            &params.gen_1.h,
            rc,
        );
        transcript.append_message(b"comm_c", &to_bytes!(comm_c).unwrap());
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let c = random_bytes_to_fr::<G>(&buf);
        let z_vec = (0..4 * log_n + 6 * log_g)
            .map(|k| c * &pie_vec[k] + &d_vec[k])
            .collect::<Vec<_>>();
        let z_delta_vec = (0..log_n + 2 * log_g)
            .map(|k| c * &r_alpha_vec[k] + &r_delta_vec[k])
            .collect::<Vec<_>>();
        let zc = c * &(rou_vec[0] * &rc0 - &(j_x * &rx) - &(j_y * &ry) - &(j_z * &rz)) + &rc;

        (
            prod_proof,
            delta_vec,
            comm_c,
            z_vec,
            z_delta_vec,
            zc,
            vec![rx, ry],
        )
    }

    pub fn verify(
        &self,
        params: &SumCheckCommitmentSetupParameters<G>,
        comm_claim: G::Affine,
        u: (G::Fr, G::Fr),
        q_vec: (&Vec<G::Fr>, &Vec<G::Fr>, &Vec<G::Fr>),
        gates: &Vec<Gate>,
        n: usize,
        ng: usize,
        transcript: &mut Transcript,
    ) -> (G::Affine, G::Affine, Vec<G::Fr>, Vec<G::Fr>, Vec<G::Fr>) {
        let mut comm_claim = comm_claim;
        let log_ng = log2(ng) as usize;
        let log_n = log2(n) as usize;

        let mut rs = Vec::new();
        let mut r0 = Vec::new();
        let mut r1 = Vec::new();
        for j in 0..log_n + 2 * log_ng {
            let comm_poly = self.comm_polys[j];
            let comm_eval = self.comm_evals[j];
            transcript.append_message(b"comm_poly", &to_bytes!(comm_poly).unwrap());
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_nextround", &mut buf);
            let r_i = random_bytes_to_fr::<G>(&buf);

            transcript.append_message(b"comm_claim_per_round", &to_bytes!(comm_claim).unwrap());
            transcript.append_message(b"comm_eval", &to_bytes!(comm_eval).unwrap());

            comm_claim = comm_eval;
            if j < log_n {
                rs.push(r_i);
            } else if j < log_n + log_ng {
                r0.push(r_i);
            } else {
                r1.push(r_i);
            }
        }

        let m_vec = construct_matrix::<G>((&rs, &r0, &r1), q_vec, gates, u, log_n, log_ng);

        let result = self.sumcheck_verify(params, &m_vec, log_ng, log_n, transcript);
        assert!(result);

        (self.comm_x, self.comm_y, rs, r0, r1)
    }

    pub fn sumcheck_verify(
        &self,
        params: &SumCheckCommitmentSetupParameters<G>,
        m_vec: &Vec<Vec<G::Fr>>,
        log_g: usize,
        log_n: usize,
        transcript: &mut Transcript,
    ) -> bool {
        let result = self.prod_proof.verify(
            &params.gen_1,
            self.comm_x,
            self.comm_y,
            self.comm_z,
            transcript,
        );
        assert!(result);

        for i in 0..self.comm_deltas.len() {
            transcript.append_message(b"comm_delta", &to_bytes!(self.comm_deltas[i]).unwrap());
        }

        let rou_vec = (0..log_n + 2 * log_g + 1)
            .map(|_| {
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"challenge_nextround", &mut buf);
                random_bytes_to_fr::<G>(&buf)
            })
            .collect::<Vec<_>>();

        transcript.append_message(b"comm_c", &to_bytes!(self.comm_c).unwrap());
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let c = random_bytes_to_fr::<G>(&buf);
        for j in 0..log_n + 2 * log_g {
            let right = self.comm_polys[j].mul(c) + &self.comm_deltas[j].into_projective();
            let left: G::Affine;
            if j < log_n {
                left = poly_commit_vec::<G>(
                    &params.gen_4.generators,
                    &vec![
                        self.z_vec[j * 4 + 0],
                        self.z_vec[j * 4 + 1],
                        self.z_vec[j * 4 + 2],
                        self.z_vec[j * 4 + 3],
                    ],
                    &params.gen_4.h,
                    self.z_delta_vec[j],
                );
            } else {
                left = poly_commit_vec::<G>(
                    &params.gen_3.generators,
                    &vec![
                        self.z_vec[log_n + j * 3 + 0],
                        self.z_vec[log_n + j * 3 + 1],
                        self.z_vec[log_n + j * 3 + 2],
                    ],
                    &params.gen_3.h,
                    self.z_delta_vec[j],
                );
            }

            if left.into_projective() != right {
                return false;
            }
        }

        let j_vec = (0..4 * log_n + 6 * log_g + 3)
            .map(|k| {
                (0..log_n + 2 * log_g + 1)
                    .map(|j| rou_vec[j] * &m_vec[j][k])
                    .sum()
            })
            .collect::<Vec<G::Fr>>();
        let mut left = self.comm_a0.mul(rou_vec[0])
            + &self.comm_x.mul(j_vec[j_vec.len() - 3].neg())
            + &self.comm_y.mul(j_vec[j_vec.len() - 2].neg())
            + &self.comm_z.mul(j_vec[j_vec.len() - 1].neg());
        left = left.mul(c.into()) + &self.comm_c.into_projective();

        let prod_jz_star = (0..4 * log_n + 6 * log_g)
            .map(|k| j_vec[k] * &self.z_vec[k])
            .sum();
        let right = poly_commit_vec::<G>(
            &params.gen_1.generators,
            &vec![prod_jz_star],
            &params.gen_1.h,
            self.zc,
        );

        left == right.into_projective()
    }
}
