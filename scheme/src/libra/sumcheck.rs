use crate::libra::data_structure::{
    SumCheckCommitmentSetupParameters, SumCheckEvalProof, SumCheckProof, ZKSumCheckProof,
};
use crate::libra::evaluate::{combine_with_r, poly_commit_vec, random_bytes_to_fr};
use math::fft::DensePolynomial as Polynomial;
use math::{
    bytes::ToBytes, AffineCurve, Field, One, PairingEngine, ProjectiveCurve, UniformRand, Zero,
};
use merlin::Transcript;
use rand::Rng;
use std::ops::{Add, Deref};

pub fn sumcheck_phase_one<E: PairingEngine>(
    f_vec: &Vec<E::Fr>,
    g_vec: &(Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>),
    bit_size: usize,
    claim: E::Fr,
    // rng: &mut R,
    transcript: &mut Transcript,
) -> (SumCheckProof<E>, Vec<E::Fr>) {
    let mut size = f_vec.len();
    let (mut mul_hg_vec, mut add_hg_vec1, mut add_hg_vec2) =
        (g_vec.0.clone(), g_vec.1.clone(), g_vec.2.clone());
    let mut f_vec = f_vec.clone();
    assert_eq!(size, g_vec.0.len());
    assert_eq!(size, g_vec.1.len());
    assert_eq!(size, g_vec.2.len());
    assert_eq!(size, (2usize).pow(bit_size as u32));

    let mut claim = claim;
    let mut ru = Vec::new();
    let mut polys = Vec::new();

    for _ in 0..bit_size {
        size /= 2;
        let eval_0: E::Fr = (0..size)
            .map(|j| f_vec[j] * &mul_hg_vec[j] + &(f_vec[j] * &add_hg_vec1[j]) + &add_hg_vec2[j])
            .sum();
        let eval_1 = claim - &eval_0;

        let f_vec_tmp = combine_with_r::<E>(&f_vec, E::Fr::from(2));
        let mul_hg_vec_tmp = combine_with_r::<E>(&mul_hg_vec, E::Fr::from(2));
        let add_hg_vec1_tmp = combine_with_r::<E>(&add_hg_vec1, E::Fr::from(2));
        let add_hg_vec2_tmp = combine_with_r::<E>(&add_hg_vec2, E::Fr::from(2));
        let eval_2: E::Fr = (0..size)
            .map(|j| {
                f_vec_tmp[j] * &mul_hg_vec_tmp[j]
                    + &(f_vec_tmp[j] * &add_hg_vec1_tmp[j])
                    + &add_hg_vec2_tmp[j]
            })
            .sum();

        // degree = 2
        // f(x) = ax^2 + bx + c
        // a = (eval_0 - 2eval_1 + eval_2)/2
        let a_coeff = (eval_0 - &eval_1.double() + &eval_2) * &E::Fr::from(2).inverse().unwrap();
        // c = eval_0
        let c_coeff = eval_0;
        // b = eval_1 - a - c
        let b_coeff = eval_1 - &a_coeff - &c_coeff;
        let poly = Polynomial::from_coefficients_vec(vec![c_coeff, b_coeff, a_coeff]);

        transcript.append_message(b"poly", &math::to_bytes!(poly).unwrap());
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let r_i = random_bytes_to_fr::<E>(&buf);

        mul_hg_vec = combine_with_r::<E>(&mul_hg_vec, r_i);
        add_hg_vec1 = combine_with_r::<E>(&add_hg_vec1, r_i);
        add_hg_vec2 = combine_with_r::<E>(&add_hg_vec2, r_i);
        f_vec = combine_with_r::<E>(&f_vec, r_i);

        claim = poly.evaluate(r_i);
        ru.push(r_i);
        polys.push(poly);
    }

    let poly_value_at_r = vec![f_vec[0], mul_hg_vec[0], add_hg_vec1[0], add_hg_vec2[0]];
    transcript.append_message(b"claim_final", &math::to_bytes!(poly_value_at_r).unwrap());

    let proof = SumCheckProof::<E> {
        polys,
        poly_value_at_r,
    };
    (proof, ru)
}

pub fn sumcheck_phase_two<E: PairingEngine>(
    f_vec: &Vec<E::Fr>,
    g_vec: &(Vec<E::Fr>, Vec<E::Fr>, E::Fr),
    bit_size: usize,
    claim: E::Fr,
    transcript: &mut Transcript,
) -> (SumCheckProof<E>, Vec<E::Fr>) {
    let mut size = f_vec.len();
    let (mut mul_hg_vec, mut add_hg_vec, fu) = (g_vec.0.clone(), g_vec.1.clone(), g_vec.2);
    let mut f_vec = f_vec.clone();
    assert_eq!(size, g_vec.0.len());
    assert_eq!(size, g_vec.1.len());
    assert_eq!(size, (2usize).pow(bit_size as u32));

    let mut claim = claim;
    let mut rv = Vec::new();
    let mut polys = Vec::new();

    for _ in 0..bit_size {
        size /= 2;
        let eval_0: E::Fr = (0..size)
            .map(|j| {
                mul_hg_vec[j] * &f_vec[j] * &fu
                    + &(add_hg_vec[j] * &fu)
                    + &(add_hg_vec[j] * &f_vec[j])
            })
            .sum();
        let eval_1 = claim - &eval_0;

        let f_vec_tmp = combine_with_r::<E>(&f_vec, E::Fr::from(2));
        let mul_hg_vec_tmp = combine_with_r::<E>(&mul_hg_vec, E::Fr::from(2));
        let add_hg_vec_tmp = combine_with_r::<E>(&add_hg_vec, E::Fr::from(2));
        // let add_hg_vec2_tmp = combine_with_r::<E>(&add_hg_vec2, E::Fr::from(2));
        let eval_2: E::Fr = (0..size)
            .map(|j| {
                mul_hg_vec_tmp[j] * &f_vec_tmp[j] * &fu
                    + &(add_hg_vec_tmp[j] * &fu)
                    + &(add_hg_vec_tmp[j] * &f_vec_tmp[j])
            })
            .sum();

        // degree = 2
        // f(x) = ax^2 + bx + c
        // a = (eval_0 - 2eval_1 + eval_2)/2
        let a_coeff = (eval_0 - &eval_1.double() + &eval_2) * &E::Fr::from(2).inverse().unwrap();
        // c = eval_0
        let c_coeff = eval_0;
        // b = eval_1 - a - c
        let b_coeff = eval_1 - &a_coeff - &c_coeff;
        let poly = Polynomial::from_coefficients_vec(vec![c_coeff, b_coeff, a_coeff]);

        transcript.append_message(b"poly", &math::to_bytes!(poly).unwrap());
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let r_i = random_bytes_to_fr::<E>(&buf);
        mul_hg_vec = combine_with_r::<E>(&mul_hg_vec, r_i);
        add_hg_vec = combine_with_r::<E>(&add_hg_vec, r_i);
        f_vec = combine_with_r::<E>(&f_vec, r_i);

        claim = poly.evaluate(r_i);
        rv.push(r_i);
        polys.push(poly);
    }

    let poly_value_at_r = vec![f_vec[0], mul_hg_vec[0], add_hg_vec[0]];
    transcript.append_message(b"claim_final", &math::to_bytes!(poly_value_at_r).unwrap());

    let proof = SumCheckProof::<E> {
        polys,
        poly_value_at_r,
    };

    (proof, rv)
}

pub fn zk_sumcheck_phase_one<E: PairingEngine, R: Rng>(
    params: &SumCheckCommitmentSetupParameters<E>,
    f_vec: &Vec<E::Fr>,
    g_vec: &(Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>),
    bit_size: usize,
    claim: E::Fr,
    blind_claim: E::Fr,
    rng: &mut R,
    transcript: &mut Transcript,
) -> (ZKSumCheckProof<E>, Vec<E::Fr>) {
    let mut size = f_vec.len();
    let (mut mul_hg_vec, mut add_hg_vec1, mut add_hg_vec2) =
        (g_vec.0.clone(), g_vec.1.clone(), g_vec.2.clone());
    let mut f_vec = f_vec.clone();
    assert_eq!(size, g_vec.0.len());
    assert_eq!(size, g_vec.1.len());
    assert_eq!(size, g_vec.2.len());
    assert_eq!(size, (2usize).pow(bit_size as u32));

    let mut blind_polys = Vec::new();
    let mut blind_evals = Vec::new();
    for _ in 0..bit_size {
        blind_polys.push(E::Fr::rand(rng));
        blind_evals.push(E::Fr::rand(rng));
    }

    let mut ru = Vec::new();

    let mut claim = claim;
    let mut comm_claim = poly_commit_vec::<E>(
        &params.gen_1.generators,
        &vec![claim],
        &params.gen_1.h,
        blind_claim,
    );
    let mut comm_polys = Vec::new();
    let mut comm_evals = Vec::new();
    let mut proofs = Vec::new();

    for i in 0..bit_size {
        size /= 2;
        let eval_0: E::Fr = (0..size)
            .map(|j| f_vec[j] * &mul_hg_vec[j] + &(f_vec[j] * &add_hg_vec1[j]) + &add_hg_vec2[j])
            .sum();
        let eval_1 = claim - &eval_0;

        let f_vec_tmp = combine_with_r::<E>(&f_vec, E::Fr::from(2));
        let mul_hg_vec_tmp = combine_with_r::<E>(&mul_hg_vec, E::Fr::from(2));
        let add_hg_vec1_tmp = combine_with_r::<E>(&add_hg_vec1, E::Fr::from(2));
        let add_hg_vec2_tmp = combine_with_r::<E>(&add_hg_vec2, E::Fr::from(2));
        let eval_2: E::Fr = (0..size)
            .map(|j| {
                f_vec_tmp[j] * &mul_hg_vec_tmp[j]
                    + &(f_vec_tmp[j] * &add_hg_vec1_tmp[j])
                    + &add_hg_vec2_tmp[j]
            })
            .sum();

        // degree = 2
        // f(x) = ax^2 + bx + c
        // a = (eval_0 - 2eval_1 + eval_2)/2
        let a_coeff = (eval_0 - &eval_1.double() + &eval_2) * &E::Fr::from(2).inverse().unwrap();
        // c = eval_0
        let c_coeff = eval_0;
        // b = eval_1 - a - c
        let b_coeff = eval_1 - &a_coeff - &c_coeff;
        let poly = Polynomial::from_coefficients_vec(vec![c_coeff, b_coeff, a_coeff]);
        let comm_poly = poly_commit_vec::<E>(
            &params.gen_3.generators,
            &poly.deref().to_vec(),
            &params.gen_3.h,
            blind_polys[i],
        );
        transcript.append_message(b"comm_poly", &math::to_bytes!(comm_poly).unwrap());
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let r_i = random_bytes_to_fr::<E>(&buf);
        f_vec = combine_with_r::<E>(&f_vec, r_i);
        mul_hg_vec = combine_with_r::<E>(&mul_hg_vec, r_i);
        add_hg_vec1 = combine_with_r::<E>(&add_hg_vec1, r_i);
        add_hg_vec2 = combine_with_r::<E>(&add_hg_vec2, r_i);

        let eval_ri = poly.evaluate(r_i);
        let comm_eval = poly_commit_vec::<E>(
            &params.gen_1.generators,
            &vec![eval_ri],
            &params.gen_1.h,
            blind_evals[i],
        );
        transcript.append_message(
            b"comm_claim_per_round",
            &math::to_bytes!(comm_claim).unwrap(),
        );
        transcript.append_message(b"comm_eval", &math::to_bytes!(comm_eval).unwrap());

        let mut blind_claim_t = blind_claim;
        if i > 0 {
            blind_claim_t = blind_evals[i - 1];
        }
        let proof = sum_check_eval_prover::<E, R>(
            params,
            3,
            &poly.deref().to_vec(),
            comm_poly,
            blind_polys[i],
            claim,
            blind_claim_t,
            eval_ri,
            blind_evals[i],
            r_i,
            rng,
            transcript,
        );

        ru.push(r_i);
        claim = eval_ri;
        comm_claim = comm_eval;
        comm_evals.push(comm_eval);
        comm_polys.push(comm_poly);
        proofs.push(proof);
    }

    let poly_value_at_r = vec![f_vec[0], mul_hg_vec[0], add_hg_vec1[0], add_hg_vec2[0]];

    let proof = ZKSumCheckProof::<E> {
        comm_evals,
        comm_polys,
        proofs,
        poly_value_at_r,
        blind_eval: blind_evals[bit_size - 1],
    };

    (proof, ru)
}

pub fn zk_sumcheck_phase_two<E: PairingEngine, R: Rng>(
    params: &SumCheckCommitmentSetupParameters<E>,
    f_vec: &Vec<E::Fr>,
    g_vec: &(Vec<E::Fr>, Vec<E::Fr>, E::Fr),
    bit_size: usize,
    claim: E::Fr,
    blind_claim: E::Fr,
    rng: &mut R,
    transcript: &mut Transcript,
) -> (ZKSumCheckProof<E>, Vec<E::Fr>) {
    let mut size = f_vec.len();
    let (mut mul_hg_vec, mut add_hg_vec, fu) = (g_vec.0.clone(), g_vec.1.clone(), g_vec.2);
    let mut f_vec = f_vec.clone();
    assert_eq!(size, g_vec.0.len());
    assert_eq!(size, g_vec.1.len());
    assert_eq!(size, (2usize).pow(bit_size as u32));

    let mut blind_polys = Vec::new();
    let mut blind_evals = Vec::new();
    for _ in 0..bit_size {
        blind_polys.push(E::Fr::rand(rng));
        blind_evals.push(E::Fr::rand(rng));
    }

    let mut claim = claim;
    let mut comm_claim = poly_commit_vec::<E>(
        &params.gen_1.generators,
        &vec![claim],
        &params.gen_1.h,
        blind_claim,
    );
    let mut rv = Vec::new();
    let mut comm_polys: Vec<E::G1Affine> = Vec::new();
    let mut comm_evals: Vec<E::G1Affine> = Vec::new();
    let mut proofs: Vec<SumCheckEvalProof<E>> = Vec::new();

    for i in 0..bit_size {
        size /= 2;
        let eval_0: E::Fr = (0..size)
            .map(|j| {
                mul_hg_vec[j] * &f_vec[j] * &fu
                    + &(add_hg_vec[j] * &fu)
                    + &(add_hg_vec[j] * &f_vec[j])
            })
            .sum();
        let eval_1 = claim - &eval_0;

        let f_vec_tmp = combine_with_r::<E>(&f_vec, E::Fr::from(2));
        let mul_hg_vec_tmp = combine_with_r::<E>(&mul_hg_vec, E::Fr::from(2));
        let add_hg_vec_tmp = combine_with_r::<E>(&add_hg_vec, E::Fr::from(2));
        let eval_2: E::Fr = (0..size)
            .map(|j| {
                mul_hg_vec_tmp[j] * &f_vec_tmp[j] * &fu
                    + &(add_hg_vec_tmp[j] * &fu)
                    + &(add_hg_vec_tmp[j] * &f_vec_tmp[j])
            })
            .sum();

        // degree = 2
        // f(x) = ax^2 + bx + c
        // a = (eval_0 - 2eval_1 + eval_2)/2
        let a_coeff = (eval_0 - &eval_1.double() + &eval_2) * &E::Fr::from(2).inverse().unwrap();
        // c = eval_0
        let c_coeff = eval_0;
        // b = eval_1 - a - c
        let b_coeff = eval_1 - &a_coeff - &c_coeff;
        let poly = Polynomial::from_coefficients_vec(vec![c_coeff, b_coeff, a_coeff]);
        let comm_poly = poly_commit_vec::<E>(
            &params.gen_3.generators,
            &poly.deref().to_vec(),
            &params.gen_3.h,
            blind_polys[i],
        );
        transcript.append_message(b"comm_poly", &math::to_bytes!(comm_poly).unwrap());
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let r_i = random_bytes_to_fr::<E>(&buf);

        mul_hg_vec = combine_with_r::<E>(&mul_hg_vec, r_i);
        add_hg_vec = combine_with_r::<E>(&add_hg_vec, r_i);
        f_vec = combine_with_r::<E>(&f_vec, r_i);

        let eval_ri = poly.evaluate(r_i);
        let comm_eval = poly_commit_vec::<E>(
            &params.gen_1.generators,
            &vec![eval_ri],
            &params.gen_1.h,
            blind_evals[i],
        );

        transcript.append_message(
            b"comm_claim_per_round",
            &math::to_bytes!(comm_claim).unwrap(),
        );
        transcript.append_message(b"comm_eval", &math::to_bytes!(comm_eval).unwrap());

        let mut blind_claim_t = blind_claim;
        if i > 0 {
            blind_claim_t = blind_evals[i - 1];
        }
        let proof = sum_check_eval_prover::<E, R>(
            params,
            3,
            &poly.deref().to_vec(),
            comm_poly,
            blind_polys[i],
            claim,
            blind_claim_t,
            eval_ri,
            blind_evals[i],
            r_i,
            rng,
            transcript,
        );

        rv.push(r_i);
        comm_polys.push(comm_poly);
        comm_evals.push(comm_eval);
        proofs.push(proof);
        claim = eval_ri;
        comm_claim = comm_eval;
    }

    let poly_value_at_r = vec![f_vec[0], mul_hg_vec[0], add_hg_vec[0], fu];

    let proof = ZKSumCheckProof::<E> {
        comm_evals,
        comm_polys,
        proofs,
        poly_value_at_r,
        blind_eval: blind_evals[bit_size - 1],
    };

    (proof, rv)
}

pub fn sum_check_eval_prover<E: PairingEngine, R: Rng>(
    params: &SumCheckCommitmentSetupParameters<E>,
    poly_size: usize,
    poly: &Vec<E::Fr>,
    comm_poly: E::G1Affine,
    blind_poly: E::Fr,
    claim: E::Fr,
    blind_claim: E::Fr,
    eval: E::Fr,
    blind_eval: E::Fr,
    r: E::Fr,
    rng: &mut R,
    transcript: &mut Transcript,
) -> SumCheckEvalProof<E> {
    //  TODO:
    let w = (0..2)
        .map(|_i| {
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"combine_two_claims_to_one", &mut buf);
            random_bytes_to_fr::<E>(&buf)
        })
        .collect::<Vec<_>>();
    let mut polynomial = vec![E::Fr::zero(); poly_size];
    for i in 0..poly.len() {
        polynomial[i] = poly[i];
    }

    // (degree = 3)
    // claim_value = w0 * claim + w1 * eval
    //             = w0 * [poly(0) + poly(1)] + w1 * poly(ri)
    //             = w0 * [(poly_0 + poly_1 * 0 + poly_2 * 0) + (poly_0 + poly_1 * 1 + poly_2 * 1)]
    //              + w1 *  (poly_0 + poly_1 * ri + poly_2 * ri^2)
    //             = (w0 * 2 + w1) * poly_0 + (w0 + w1 * ri) * poly_1 + (w0 + w1 * ri^2) * poly_2
    // coeffs = [w0 * 2 + w1, w0 + w1 * ri, w0 + w1 * ri^2]
    let claim_value = w[0] * &claim + &(w[1] * &eval);
    let blind = w[0] * &blind_claim + &(w[1] * &blind_eval);
    let mut coeffs = Vec::new();
    let mut rc = E::Fr::one();
    for _ in 0..poly_size {
        coeffs.push(w[0] + &(w[1] * &rc));
        rc *= &r;
    }
    coeffs[0] += &w[0];

    transcript.append_message(b"Cx", &math::to_bytes!(comm_poly).unwrap());

    let comm_claim_value: E::G1Affine = poly_commit_vec::<E>(
        &params.gen_1.generators,
        &vec![claim_value],
        &params.gen_1.h,
        blind,
    );
    transcript.append_message(b"Cy", &math::to_bytes!(comm_claim_value).unwrap());
    let mut d_vec = Vec::new();
    for _ in 0..poly_size {
        d_vec.push(E::Fr::rand(rng));
    }

    let r_delta = E::Fr::rand(rng);
    let d_commit = poly_commit_vec::<E>(&params.gen_3.generators, &d_vec, &params.gen_3.h, r_delta);
    transcript.append_message(b"delta", &math::to_bytes!(d_commit).unwrap());
    // dot_cd[i] = coeffs[i] * d_vec[i]
    let r_beta = E::Fr::rand(rng);
    let dot_cd = (0..coeffs.len()).map(|i| coeffs[i] * &d_vec[i]).sum();
    let dot_cd_commit = poly_commit_vec::<E>(
        &params.gen_1.generators,
        &vec![dot_cd],
        &params.gen_1.h,
        r_beta,
    );
    transcript.append_message(b"beta", &math::to_bytes!(dot_cd_commit).unwrap());

    let mut buf = [0u8; 32];
    transcript.challenge_bytes(b"c", &mut buf);
    let c = random_bytes_to_fr::<E>(&buf);

    // println!(
    //     "sum_check_eval_verify ----- w[0] = {}, w[1] = {}, comm_poly = {}, comm_claim_value = {}, proof.d_commit = {}, proof.dot_cd_commit = {}, c = {}, comm1 = {}, comm2 = {}",
    //     w[0], w[1], comm_poly, comm_claim_value, d_commit, dot_cd_commit, c, comm1, comm2
    // );
    // z[i] = c * poly[i] + d_vec[i]
    let z = (0..poly_size)
        .map(|i| c * &polynomial[i] + &d_vec[i])
        .collect::<Vec<E::Fr>>();
    let z_delta = c * &blind_poly + &r_delta;
    let z_beta = c * &blind + &r_beta;

    let proof = SumCheckEvalProof::<E> {
        d_commit: d_commit,
        dot_cd_commit: dot_cd_commit,
        z: z,
        z_delta: z_delta,
        z_beta: z_beta,
    };

    proof
}

pub fn sum_check_eval_verify<E: PairingEngine>(
    params: &SumCheckCommitmentSetupParameters<E>,
    comm_poly: E::G1Affine,
    comm_eval: E::G1Affine,
    comm_claim: E::G1Affine,
    proof: &SumCheckEvalProof<E>,
    r: E::Fr,
    bit_size: usize,
    transcript: &mut Transcript,
) -> bool {
    let w = (0..2)
        .map(|_i| {
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"combine_two_claims_to_one", &mut buf);
            random_bytes_to_fr::<E>(&buf)
        })
        .collect::<Vec<_>>();
    transcript.append_message(b"Cx", &math::to_bytes!(comm_poly).unwrap());
    let comm_claim_value = (comm_claim.mul(w[0]) + &(comm_eval.mul(w[1]))).into_affine();
    transcript.append_message(b"Cy", &math::to_bytes!(comm_claim_value).unwrap());
    transcript.append_message(b"delta", &math::to_bytes!(proof.d_commit).unwrap());
    transcript.append_message(b"beta", &math::to_bytes!(proof.dot_cd_commit).unwrap());

    let mut buf = [0u8; 32];
    transcript.challenge_bytes(b"c", &mut buf);
    let c = random_bytes_to_fr::<E>(&buf);

    // println!(
    //     "sum_check_eval_verify ----- w[0] = {}, w[1] = {}, comm_poly = {}, comm_claim_value = {}, proof.d_commit = {}, proof.dot_cd_commit = {}, c = {}, comm_claim = {}, comm_eval = {}",
    //     w[0], w[1], comm_poly, comm_claim_value, proof.d_commit, proof.dot_cd_commit, c, comm_claim, comm_eval
    // );
    // commit(d)
    let mut coeffs = Vec::new();
    let mut rc = E::Fr::one();
    for _ in 0..bit_size {
        coeffs.push(w[0] + &(w[1] * &rc));
        rc *= &r;
    }
    coeffs[0] += &w[0];

    // first step
    // commit(poly)*c + commit(d)
    let lhs = comm_poly
        .mul(c)
        .add(&proof.d_commit.into_projective())
        .into_affine();
    // commit(z); z[i] = poly[i] * c + d[i]
    let rhs = poly_commit_vec::<E>(
        &params.gen_3.generators,
        &proof.z,
        &params.gen_3.h,
        proof.z_delta,
    );
    let rs1 = lhs == rhs;

    // second step
    let lhs = (comm_claim_value.mul(c) + &proof.dot_cd_commit.into_projective()).into_affine();
    let sum: E::Fr = (0..bit_size).map(|i| proof.z[i] * &coeffs[i]).sum();
    let rhs = poly_commit_vec::<E>(
        &params.gen_1.generators,
        &vec![sum],
        &params.gen_1.h,
        proof.z_beta,
    );
    let rs2 = lhs == rhs;

    rs1 && rs2
}
