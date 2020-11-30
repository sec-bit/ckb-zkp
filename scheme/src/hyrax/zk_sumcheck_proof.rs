use crate::hyrax::circuit::Gate;
use crate::hyrax::commitment::ProductProof;
use crate::hyrax::evaluate::{
    combine_with_r, construct_matrix, convert_to_bit, eval_eq, poly_commit_vec, random_bytes_to_fr,
};
use crate::hyrax::params::PolyCommitmentSetupParameters;
use core::ops::{Deref, Neg};
use math::fft::DensePolynomial as Polynomial;
use math::{
    bytes::ToBytes, log2, AffineCurve, Field, PairingEngine, ProjectiveCurve, UniformRand, Zero,
};
use merlin::Transcript;
use rand::Rng;

pub struct ZkSumcheckProof<E: PairingEngine> {
    pub prod_proof: ProductProof<E>,
    pub comm_a0: E::G1Affine,
    pub comm_c: E::G1Affine,
    pub comm_x: E::G1Affine,
    pub comm_y: E::G1Affine,
    pub comm_z: E::G1Affine,
    pub comm_polys: Vec<E::G1Affine>,
    pub comm_evals: Vec<E::G1Affine>,
    pub comm_deltas: Vec<E::G1Affine>,
    pub z_vec: Vec<E::Fr>,
    pub z_delta_vec: Vec<E::Fr>,
    pub zc: E::Fr,
}

impl<E: PairingEngine> ZkSumcheckProof<E> {
    pub fn prover<R: Rng>(
        params: &PolyCommitmentSetupParameters<E>,
        comm_a0: E::G1Affine,
        rc0: E::Fr,
        u: (E::Fr, E::Fr),
        q_vec: (&Vec<E::Fr>, &Vec<E::Fr>, &Vec<E::Fr>),
        gates: &Vec<Gate>,
        circuit_evals: &Vec<Vec<E::Fr>>,
        n: usize,
        ng: usize,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> (
        Self,
        Vec<E::Fr>,
        Vec<E::Fr>,
        Vec<E::Fr>,
        Vec<E::Fr>,
        Vec<E::Fr>,
    ) {
        let (u0, u1) = u;
        let (q_aside_vec, ql_vec, qr_vec) = q_vec;
        let mut comm_claim = comm_a0;

        let log_g = ql_vec.len();
        // let g = 2usize.pow(log_g as u32);
        let log_ng: usize = log2(ng) as usize;
        let log_n: usize = log2(n) as usize;
        // let mut claim = claim;

        let mut circuit_evals = circuit_evals.clone();

        assert_eq!(q_aside_vec.len(), log_n);
        assert_eq!(ql_vec.len(), qr_vec.len());

        let r_alpha_vec = (0..log_n + 2 * log_ng)
            .map(|_| E::Fr::rand(rng))
            .collect::<Vec<_>>();
        let r_alpha_eval_vec = (0..log_n + 2 * log_ng)
            .map(|_| E::Fr::rand(rng))
            .collect::<Vec<_>>();
        let mut polys = Vec::new();
        let mut comm_polys = Vec::new();
        let mut comm_evals = Vec::new();

        let eq_vec = eval_eq::<E>(&q_aside_vec);
        let eq_ql_vec = eval_eq::<E>(&ql_vec);
        let eq_qr_vec = eval_eq::<E>(&qr_vec);
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
        // let mut evalt = E::Fr::zero();
        let mut size = n;
        for j in 0..log_n {
            size /= 2;
            let mut eval_0 = E::Fr::zero();
            let mut eval_1 = E::Fr::zero();
            let mut eval_2 = E::Fr::zero();
            let mut eval_3 = E::Fr::zero();
            for (gate, temp_p_vec) in gates.iter().zip(temp_vec.iter()) {
                if gate.op == 0 {
                    eval_0 += &(0..size)
                        .map(|t| {
                            temp_p_vec[t]
                                * &(circuit_evals[gate.left_node][t]
                                    + &circuit_evals[gate.right_node][t])
                        })
                        .sum();
                    eval_1 += &(size..size * 2)
                        .map(|t| {
                            temp_p_vec[t]
                                * &(circuit_evals[gate.left_node][t]
                                    + &(circuit_evals[gate.right_node][t]))
                        })
                        .sum();
                    let temp_p_vec_tmp = combine_with_r::<E>(&temp_p_vec, E::Fr::from(2));
                    let temp_l_vec_tmp =
                        combine_with_r::<E>(&circuit_evals[gate.left_node], E::Fr::from(2));
                    let temp_r_vec_tmp =
                        combine_with_r::<E>(&circuit_evals[gate.right_node], E::Fr::from(2));
                    eval_2 += &(0..size)
                        .map(|t| temp_p_vec_tmp[t] * &(temp_l_vec_tmp[t] + &temp_r_vec_tmp[t]))
                        .sum();
                    let temp_p_vec_tmp = combine_with_r::<E>(&temp_p_vec, E::Fr::from(3));
                    let temp_l_vec_tmp =
                        combine_with_r::<E>(&circuit_evals[gate.left_node], E::Fr::from(3));
                    let temp_r_vec_tmp =
                        combine_with_r::<E>(&circuit_evals[gate.right_node], E::Fr::from(3));
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
                    eval_1 += &(size..size * 2)
                        .map(|t| {
                            temp_p_vec[t]
                                * &(circuit_evals[gate.left_node][t]
                                    * &(circuit_evals[gate.right_node][t]))
                        })
                        .sum();
                    let temp_p_vec_tmp = combine_with_r::<E>(&temp_p_vec, E::Fr::from(2));
                    let temp_l_vec_tmp =
                        combine_with_r::<E>(&circuit_evals[gate.left_node], E::Fr::from(2));
                    let temp_r_vec_tmp =
                        combine_with_r::<E>(&circuit_evals[gate.right_node], E::Fr::from(2));
                    eval_2 += &(0..size)
                        .map(|t| temp_p_vec_tmp[t] * &(temp_l_vec_tmp[t] * &temp_r_vec_tmp[t]))
                        .sum();
                    let temp_p_vec_tmp = combine_with_r::<E>(&temp_p_vec, E::Fr::from(3));
                    let temp_l_vec_tmp =
                        combine_with_r::<E>(&circuit_evals[gate.left_node], E::Fr::from(3));
                    let temp_r_vec_tmp =
                        combine_with_r::<E>(&circuit_evals[gate.right_node], E::Fr::from(3));
                    eval_3 += &(0..size)
                        .map(|t| temp_p_vec_tmp[t] * &(temp_l_vec_tmp[t] * &temp_r_vec_tmp[t]))
                        .sum();
                }
            }

            // degree = 3
            // f(x) = ax^3 + bx^2 + cx + d
            // a = (-eval_0 + 3eval_1 - 3eval_2 + eval_3)/6
            let a_coeff = (eval_0.neg() + &eval_1.double() + &eval_1 - &eval_2.double() - &eval_2
                + &eval_3)
                * &E::Fr::from(6).inverse().unwrap();
            // b = (2eval_0 - 5eval_1 + 4eval_2 - eval_3)/2
            let b_coeff = (eval_0.double() - &(eval_1.double().double()) - &eval_1
                + &eval_2.double().double()
                - &eval_3)
                * &E::Fr::from(2).inverse().unwrap();
            // c = eval_1 - eval_0 - a - b
            let c_coeff = eval_1 - &eval_0 - &a_coeff - &b_coeff;
            // d = eval_0
            let d_coeff = eval_0;
            // degree = 3
            let coeffs = vec![d_coeff, c_coeff, b_coeff, a_coeff];
            polys.push(coeffs.clone());
            let poly = Polynomial::from_coefficients_vec(coeffs);
            let comm_poly = poly_commit_vec::<E>(
                &params.gen_n.generators,
                &poly.deref().to_vec(),
                &params.gen_n.h,
                r_alpha_vec[j],
            );
            transcript.append_message(b"comm_poly", &math::to_bytes!(comm_poly).unwrap());
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_nextround", &mut buf);
            let r_i = random_bytes_to_fr::<E>(&buf);

            let mut temp_p_vec_tmp = Vec::new();
            for i in 0..temp_vec.len() {
                let temp_p_vec = combine_with_r::<E>(&temp_vec[i], r_i);
                temp_p_vec_tmp.push(temp_p_vec);
            }
            temp_vec = temp_p_vec_tmp;

            let mut circuit_evals_tmp = Vec::new();
            for i in 0..circuit_evals.len() {
                let eval = combine_with_r::<E>(&circuit_evals[i], r_i);
                circuit_evals_tmp.push(eval);
            }
            circuit_evals = circuit_evals_tmp;

            let eval_ri = poly.evaluate(r_i);
            let comm_eval = poly_commit_vec::<E>(
                &params.gen_1.generators,
                &vec![eval_ri],
                &params.gen_1.h,
                r_alpha_eval_vec[j],
            );
            transcript.append_message(
                b"comm_claim_per_round",
                &math::to_bytes!(comm_claim).unwrap(),
            );
            transcript.append_message(b"comm_eval", &math::to_bytes!(comm_eval).unwrap());

            rs.push(r_i);
            comm_polys.push(comm_poly);
            comm_evals.push(comm_eval);
            comm_claim = comm_eval;
        }

        let v_vec = (0..circuit_evals.len())
            .map(|i| circuit_evals[i][0])
            .collect::<Vec<_>>();
        let mut temp_p_xg_vec = (0..temp_vec.len())
            .map(|i| temp_vec[i][0])
            .collect::<Vec<_>>();
        let eq_node_vec = (0..ng)
            .map(|i| {
                let node_vec = convert_to_bit::<E>(i, log_ng);
                eval_eq::<E>(&node_vec)
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
            let mut eval_0 = E::Fr::zero();
            let mut eval_1 = E::Fr::zero();
            let mut eval_2 = E::Fr::zero();

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
                    eval_1 += &((size..size * 2)
                        .map(|i| {
                            (left_eq[i] * temp_p_xg) * &(v_vec_left[i] + &v_vec[gate.right_node])
                        })
                        .sum());
                    let left_eq_tmp = combine_with_r::<E>(&left_eq, E::Fr::from(2));
                    let v_vec_left_tmp = combine_with_r::<E>(&v_vec_left, E::Fr::from(2));
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
                    eval_1 += &((size..size * 2)
                        .map(|i| {
                            (left_eq[i] * temp_p_xg) * &(v_vec_left[i] * &v_vec[gate.right_node])
                        })
                        .sum());
                    let left_eq_tmp = combine_with_r::<E>(&left_eq, E::Fr::from(2));
                    let v_vec_left_tmp = combine_with_r::<E>(&v_vec_left, E::Fr::from(2));
                    eval_2 += &((0..size)
                        .map(|i| {
                            (left_eq_tmp[i] * temp_p_xg)
                                * &(v_vec_left_tmp[i] * &v_vec[gate.right_node])
                        })
                        .sum());
                }
            }

            // degree = 2
            // f(x) = ax^2 + bx + c
            // a = (eval_0 - 2eval_1 + eval_2)/2
            let a_coeff =
                (eval_0 - &eval_1.double() + &eval_2) * &E::Fr::from(2).inverse().unwrap();
            // c = eval_0
            let c_coeff = eval_0;
            // b = eval_1 - a - c
            let b_coeff = eval_1 - &a_coeff - &c_coeff;

            let coeffs = vec![c_coeff, b_coeff, a_coeff];
            polys.push(coeffs.clone());
            let poly = Polynomial::from_coefficients_vec(coeffs);
            let comm_poly = poly_commit_vec::<E>(
                &params.gen_n.generators,
                &poly.deref().to_vec(),
                &params.gen_n.h,
                r_alpha_vec[log_n + j],
            );
            transcript.append_message(b"comm_poly", &math::to_bytes!(comm_poly).unwrap());
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_nextround", &mut buf);
            let r_i = random_bytes_to_fr::<E>(&buf);

            let mut left_eq_vec_tmp = Vec::new();
            for i in 0..left_eq_vec.len() {
                let left_eq = combine_with_r::<E>(&left_eq_vec[i], r_i);
                left_eq_vec_tmp.push(left_eq);
            }
            left_eq_vec = left_eq_vec_tmp;

            v_vec_left = combine_with_r::<E>(&v_vec_left, r_i);
            let eval_ri = poly.evaluate(r_i);
            let comm_eval = poly_commit_vec::<E>(
                &params.gen_1.generators,
                &vec![eval_ri],
                &params.gen_1.h,
                r_alpha_eval_vec[log_n + j],
            );
            transcript.append_message(
                b"comm_claim_per_round",
                &math::to_bytes!(comm_claim).unwrap(),
            );
            transcript.append_message(b"comm_eval", &math::to_bytes!(comm_eval).unwrap());

            r0.push(r_i);
            comm_polys.push(comm_poly);
            comm_evals.push(comm_eval);
            comm_claim = comm_eval;
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
            let mut eval_0 = E::Fr::zero();
            let mut eval_1 = E::Fr::zero();
            let mut eval_2 = E::Fr::zero();

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
                    let right_eq_tmp = combine_with_r::<E>(&right_eq, E::Fr::from(2));
                    let v_vec_right_tmp = combine_with_r::<E>(&v_vec_right, E::Fr::from(2));
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
                    let right_eq_tmp = combine_with_r::<E>(&right_eq, E::Fr::from(2));
                    let v_vec_right_tmp = combine_with_r::<E>(&v_vec_right, E::Fr::from(2));
                    eval_2 += &((0..size)
                        .map(|i| (right_eq_tmp[i] * temp_p_xg) * &(x * &v_vec_right_tmp[i]))
                        .sum());
                }
            }

            // degree = 2
            // f(x) = ax^2 + bx + c
            // a = (eval_0 - 2eval_1 + eval_2)/2
            let a_coeff =
                (eval_0 - &eval_1.double() + &eval_2) * &E::Fr::from(2).inverse().unwrap();
            // c = eval_0
            let c_coeff = eval_0;
            // b = eval_1 - a - c
            let b_coeff = eval_1 - &a_coeff - &c_coeff;

            let coeffs = vec![c_coeff, b_coeff, a_coeff];
            polys.push(coeffs.clone());
            let poly = Polynomial::from_coefficients_vec(coeffs);
            let comm_poly = poly_commit_vec::<E>(
                &params.gen_n.generators,
                &poly.deref().to_vec(),
                &params.gen_n.h,
                r_alpha_vec[log_n + log_ng + j],
            );
            transcript.append_message(b"comm_poly", &math::to_bytes!(comm_poly).unwrap());
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_nextround", &mut buf);
            let r_i = random_bytes_to_fr::<E>(&buf);

            let mut right_eq_vec_tmp = Vec::new();
            for i in 0..right_eq_vec.len() {
                let right_eq = combine_with_r::<E>(&right_eq_vec[i], r_i);
                right_eq_vec_tmp.push(right_eq);
            }
            right_eq_vec = right_eq_vec_tmp;

            v_vec_right = combine_with_r::<E>(&v_vec_right, r_i);
            let eval_ri = poly.evaluate(r_i);
            let comm_eval = poly_commit_vec::<E>(
                &params.gen_1.generators,
                &vec![eval_ri],
                &params.gen_1.h,
                r_alpha_eval_vec[log_n + log_g + j],
            );
            transcript.append_message(
                b"comm_claim_per_round",
                &math::to_bytes!(comm_claim).unwrap(),
            );
            transcript.append_message(b"comm_eval", &math::to_bytes!(comm_eval).unwrap());

            r1.push(r_i);
            comm_polys.push(comm_poly);
            comm_evals.push(comm_eval);
            comm_claim = comm_eval;
        }
        let y = v_vec_right[0];

        let m_vec = construct_matrix::<E>((&rs, &r0, &r1), q_vec, gates, u, log_n, log_ng);

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
            // &polys,
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
        params: &PolyCommitmentSetupParameters<E>,
        xy: (E::Fr, E::Fr),
        log_g: usize,
        log_n: usize,
        // polys: &Vec<Vec<E::Fr>>,
        m_vec: &Vec<Vec<E::Fr>>,
        pie_vec: &Vec<E::Fr>,
        r_alpha_vec: &Vec<E::Fr>,
        rc0: E::Fr,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> (
        (ProductProof<E>, E::G1Affine, E::G1Affine, E::G1Affine),
        Vec<E::G1Affine>,
        E::G1Affine,
        Vec<E::Fr>,
        Vec<E::Fr>,
        E::Fr,
        Vec<E::Fr>,
    ) {
        let (x, y) = xy;
        let z = x * &y;

        let rx = E::Fr::rand(rng);
        let ry = E::Fr::rand(rng);
        let rz = E::Fr::rand(rng);
        let prod_proof =
            ProductProof::prover::<R>(&params.gen_1, x, rx, y, ry, z, rz, rng, transcript);

        let mut r_delta_vec: Vec<E::Fr> = Vec::new();
        let mut d_vec: Vec<E::Fr> = Vec::new();
        let mut delta_vec = (0..log_n)
            .map(|_| {
                let d3 = E::Fr::rand(rng);
                let d2 = E::Fr::rand(rng);
                let d1 = E::Fr::rand(rng);
                let d0 = E::Fr::rand(rng);
                let r_delta = E::Fr::rand(rng);
                d_vec.push(d3);
                d_vec.push(d2);
                d_vec.push(d1);
                d_vec.push(d0);
                r_delta_vec.push(r_delta);
                let delta_comm = poly_commit_vec::<E>(
                    &params.gen_n.generators,
                    &vec![d3, d2, d1, d0],
                    &params.gen_n.h,
                    r_delta,
                );
                transcript.append_message(b"comm_delta", &math::to_bytes!(delta_comm).unwrap());
                delta_comm
            })
            .collect::<Vec<E::G1Affine>>();

        let delta_vec2 = (0..2 * log_g)
            .map(|_| {
                let d2 = E::Fr::rand(rng);
                let d1 = E::Fr::rand(rng);
                let d0 = E::Fr::rand(rng);
                let r_delta = E::Fr::rand(rng);
                d_vec.push(d2);
                d_vec.push(d1);
                d_vec.push(d0);
                r_delta_vec.push(r_delta);
                let delta_comm = poly_commit_vec::<E>(
                    &params.gen_n.generators,
                    &vec![d2, d1, d0],
                    &params.gen_n.h,
                    r_delta,
                );
                transcript.append_message(b"comm_delta", &math::to_bytes!(delta_comm).unwrap());
                delta_comm
            })
            .collect::<Vec<E::G1Affine>>();
        delta_vec.extend(delta_vec2);

        let rou_vec = (0..log_n + 2 * log_g + 1)
            .map(|_| {
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"challenge_nextround", &mut buf);
                random_bytes_to_fr::<E>(&buf)
            })
            .collect::<Vec<_>>();

        let j_vec = (0..4 * log_n + 6 * log_g + 3)
            .map(|k| {
                (0..log_n + 2 * log_g + 1)
                    .map(|j| rou_vec[j] * &m_vec[j][k])
                    .sum()
            })
            .collect::<Vec<E::Fr>>();

        let rc = E::Fr::rand(rng);
        let prod_jd_star = (0..4 * log_n + 6 * log_g)
            .map(|k| j_vec[k] * &d_vec[k])
            .sum();
        let j_x = j_vec[4 * log_n + 6 * log_g];
        let j_y = j_vec[4 * log_n + 6 * log_g + 1];
        let j_z = j_vec[4 * log_n + 6 * log_g + 2];

        let comm_c = poly_commit_vec::<E>(
            &params.gen_1.generators,
            &vec![prod_jd_star],
            &params.gen_1.h,
            rc,
        );
        transcript.append_message(b"comm_c", &math::to_bytes!(comm_c).unwrap());
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let c = random_bytes_to_fr::<E>(&buf);
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
        params: &PolyCommitmentSetupParameters<E>,
        comm_claim: E::G1Affine,
        u: (E::Fr, E::Fr),
        q_vec: (&Vec<E::Fr>, &Vec<E::Fr>, &Vec<E::Fr>),
        gates: &Vec<Gate>,
        n: usize,
        ng: usize,
        transcript: &mut Transcript,
    ) -> (E::G1Affine, E::G1Affine, Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>) {
        let mut comm_claim = comm_claim;
        let log_ng = log2(ng) as usize;
        let log_n = log2(n) as usize;

        let mut rs = Vec::new();
        let mut r0 = Vec::new();
        let mut r1 = Vec::new();
        for j in 0..log_n + 2 * log_ng {
            let comm_poly = self.comm_polys[j];
            let comm_eval = self.comm_evals[j];
            transcript.append_message(b"comm_poly", &math::to_bytes!(comm_poly).unwrap());
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_nextround", &mut buf);
            let r_i = random_bytes_to_fr::<E>(&buf);

            transcript.append_message(
                b"comm_claim_per_round",
                &math::to_bytes!(comm_claim).unwrap(),
            );
            transcript.append_message(b"comm_eval", &math::to_bytes!(comm_eval).unwrap());

            comm_claim = comm_eval;
            if j < log_n {
                rs.push(r_i);
            } else if j < log_n + log_ng {
                r0.push(r_i);
            } else {
                r1.push(r_i);
            }
        }

        let m_vec = construct_matrix::<E>((&rs, &r0, &r1), q_vec, gates, u, log_n, log_ng);

        let result = self.sumcheck_verify(params, &m_vec, log_ng, log_n, transcript);
        assert!(result);
        println!("sumcheck_verify....{}", result);

        (self.comm_x, self.comm_y, rs, r0, r1)
    }

    pub fn sumcheck_verify(
        &self,
        params: &PolyCommitmentSetupParameters<E>,
        m_vec: &Vec<Vec<E::Fr>>,
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
            transcript.append_message(
                b"comm_delta",
                &math::to_bytes!(self.comm_deltas[i]).unwrap(),
            );
        }

        let rou_vec = (0..log_n + 2 * log_g + 1)
            .map(|_| {
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"challenge_nextround", &mut buf);
                random_bytes_to_fr::<E>(&buf)
            })
            .collect::<Vec<_>>();

        transcript.append_message(b"comm_c", &math::to_bytes!(self.comm_c).unwrap());
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let c = random_bytes_to_fr::<E>(&buf);
        for j in 0..log_n + 2 * log_g {
            let right = self.comm_polys[j].mul(c) + &self.comm_deltas[j].into_projective();
            let left: E::G1Affine;
            if j < log_n {
                left = poly_commit_vec::<E>(
                    &params.gen_n.generators,
                    &vec![
                        self.z_vec[j * 4 + 0],
                        self.z_vec[j * 4 + 1],
                        self.z_vec[j * 4 + 2],
                        self.z_vec[j * 4 + 3],
                    ],
                    &params.gen_n.h,
                    self.z_delta_vec[j],
                );
            } else {
                left = poly_commit_vec::<E>(
                    &params.gen_n.generators,
                    &vec![
                        self.z_vec[log_n + j * 3 + 0],
                        self.z_vec[log_n + j * 3 + 1],
                        self.z_vec[log_n + j * 3 + 2],
                    ],
                    &params.gen_n.h,
                    self.z_delta_vec[j],
                );
            }
            if left.into_projective() != right {
                println!("{} left != right", j);
                return false;
            }
        }

        let j_vec = (0..4 * log_n + 6 * log_g + 3)
            .map(|k| {
                (0..log_n + 2 * log_g + 1)
                    .map(|j| rou_vec[j] * &m_vec[j][k])
                    .sum()
            })
            .collect::<Vec<E::Fr>>();
        let mut left = self.comm_a0.mul(rou_vec[0])
            + &self.comm_x.mul(j_vec[j_vec.len() - 3].neg())
            + &self.comm_y.mul(j_vec[j_vec.len() - 2].neg())
            + &self.comm_z.mul(j_vec[j_vec.len() - 1].neg());
        left = left.mul(c) + &self.comm_c.into_projective();

        let prod_jz_star = (0..4 * log_n + 6 * log_g)
            .map(|k| j_vec[k] * &self.z_vec[k])
            .sum();
        let right = poly_commit_vec::<E>(
            &params.gen_1.generators,
            &vec![prod_jz_star],
            &params.gen_n.h,
            self.zc,
        );
        left == right.into_projective()
    }
}
