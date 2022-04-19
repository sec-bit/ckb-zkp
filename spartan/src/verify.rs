use ark_ff::{to_bytes, One, PrimeField, Zero};
use ark_poly::{polynomial::univariate::DensePolynomial, Polynomial};
use ark_std::log2;
use core::{cmp, ops::Add};
use merlin::Transcript;
use zkp_curve::{AffineCurve, Curve, ProjectiveCurve};
use zkp_r1cs::SynthesisError;

use crate::{
    commitments::poly_commit_vec,
    data_structure::{
        random_bytes_to_fr, DotProductProof, EncodeCommit, EqProof, HashLayerProof, KnowledgeProof,
        MultiCommitmentParameters, NIZKProof, NizkParameters, PolyCommitmentParameters,
        ProductCircuitEvalProof, ProductLayerProof, ProductProof, R1CSEvalsParameters,
        R1CSEvalsProof, R1CSSatProof, R1CSSatisfiedParameters, SNARKProof, SnarkParameters,
        SumCheckEvalProof, SumCheckProof,
    },
    inner_product::bullet_inner_product_verify,
    polynomial::{bound_poly_var_bot, eval_eq, eval_eq_x_y, evaluate_mle, sparse_evaluate_value},
    r1cs::R1CSInstance,
    spark::equalize_length,
    Vec,
};

pub fn verify_nizk_proof<G: Curve>(
    params: &NizkParameters<G>,
    r1cs: &R1CSInstance<G>,
    inputs: &[G::Fr],
    proof: &NIZKProof<G>,
) -> Result<bool, SynthesisError> {
    let mut transcript = Transcript::new(b"Spartan NIZK proof");

    let (rx, ry) = &proof.r;
    let eval_a_r = evaluate_mle::<G>(&r1cs.a_matrix, rx, ry);
    let eval_b_r = evaluate_mle::<G>(&r1cs.b_matrix, rx, ry);
    let eval_c_r = evaluate_mle::<G>(&r1cs.c_matrix, rx, ry);
    let (result, _, _) = r1cs_satisfied_verify::<G>(
        &params.r1cs_satisfied_params,
        r1cs,
        inputs,
        &proof.r1cs_satisfied_proof,
        (eval_a_r, eval_b_r, eval_c_r),
        &mut transcript,
    )?;

    Ok(result)
}

pub fn verify_snark_proof<G: Curve>(
    params: &SnarkParameters<G>,
    r1cs: &R1CSInstance<G>,
    inputs: &[G::Fr],
    proof: &SNARKProof<G>,
    encode_commit: &EncodeCommit<G>,
) -> Result<bool, SynthesisError> {
    let mut transcript = Transcript::new(b"Spartan SNARK proof");

    let (result, rx, ry) = r1cs_satisfied_verify::<G>(
        &params.r1cs_satisfied_params,
        r1cs,
        inputs,
        &proof.r1cs_satisfied_proof,
        proof.matrix_evals,
        &mut transcript,
    )?;

    if !result {
        return Ok(false);
    }

    let (eval_a_r, eval_b_r, eval_c_r) = proof.matrix_evals;
    transcript.append_message(b"Ar_claim", &to_bytes!(eval_a_r)?);
    transcript.append_message(b"Br_claim", &to_bytes!(eval_b_r)?);
    transcript.append_message(b"Cr_claim", &to_bytes!(eval_c_r)?);

    Ok(sparse_poly_eval_verify::<G>(
        &params.r1cs_eval_params,
        &proof.r1cs_evals_proof,
        encode_commit,
        (&rx, &ry),
        proof.matrix_evals,
        &mut transcript,
    )
    .is_ok())
}

pub fn r1cs_satisfied_verify<G: Curve>(
    params: &R1CSSatisfiedParameters<G>,
    r1cs: &R1CSInstance<G>,
    inputs: &[G::Fr],
    proof: &R1CSSatProof<G>,
    matrix_evals: (G::Fr, G::Fr, G::Fr),
    transcript: &mut Transcript,
) -> Result<(bool, Vec<G::Fr>, Vec<G::Fr>), SynthesisError> {
    let (eval_a_r, eval_b_r, eval_c_r) = matrix_evals;

    transcript.append_message(b"poly_commitment", &to_bytes!(proof.commit_witness)?);

    let t = cmp::max(r1cs.num_aux, r1cs.num_inputs).next_power_of_two();
    let (num_rounds_x, num_rounds_y) = (log2(r1cs.num_constraints) as usize, log2(t) as usize + 1);
    // calculate τ
    let tau: Vec<G::Fr> = (0..num_rounds_x)
        .map(|_i| {
            let mut buf = [0u8; 31];
            transcript.challenge_bytes(b"challenge_tau", &mut buf);
            random_bytes_to_fr::<G>(&buf)
        })
        .collect();

    // sumcheck #1 verify
    let claim = G::Fr::zero();
    let commit_claim = poly_commit_vec::<G>(
        &params.sc_params.gen_1.generators,
        &vec![claim],
        &params.sc_params.gen_1.h,
        G::Fr::zero(),
    )?
    .commit;
    let (rx, commit_eval_x) = sum_check_verify::<G>(
        &params.sc_params.gen_1,
        &params.sc_params.gen_4,
        &proof.proof_one,
        commit_claim,
        4,
        num_rounds_x,
        transcript,
    )?;

    let result = knowledge_verify::<G>(
        &params.sc_params.gen_1,
        &proof.knowledge_product_proof.knowledge_proof,
        proof.knowledge_product_commit.vc_commit,
        transcript,
    )?;
    if !result {
        return Ok((false, Vec::new(), Vec::new()));
    }

    let result = product_verify::<G>(
        &params.sc_params.gen_1,
        &proof.knowledge_product_proof.product_proof,
        proof.knowledge_product_commit.va_commit,
        proof.knowledge_product_commit.vb_commit,
        proof.knowledge_product_commit.prod_commit,
        transcript,
    )?;
    if !result {
        return Ok((false, Vec::new(), Vec::new()));
    }

    transcript.append_message(
        b"comm_Az_claim",
        &to_bytes!(proof.knowledge_product_commit.va_commit)?,
    );
    transcript.append_message(
        b"comm_Bz_claim",
        &to_bytes!(proof.knowledge_product_commit.vb_commit)?,
    );
    transcript.append_message(
        b"comm_Cz_claim",
        &to_bytes!(proof.knowledge_product_commit.vc_commit)?,
    );
    transcript.append_message(
        b"comm_prod_Az_Bz_claims",
        &to_bytes!(proof.knowledge_product_commit.prod_commit)?,
    );

    let eval_rx_tau = eval_eq_x_y::<G>(&rx, &tau);
    let claim_commit_phase_one = (proof.knowledge_product_commit.prod_commit.into_projective()
        - &proof.knowledge_product_commit.vc_commit.into_projective())
        .mul(eval_rx_tau.into())
        .into_affine();

    let result = eq_verify::<G>(
        &params.sc_params.gen_1,
        claim_commit_phase_one,
        commit_eval_x,
        &proof.sc1_eq_proof,
        transcript,
    )?;
    if !result {
        return Ok((false, Vec::new(), Vec::new()));
    }
    // sumcheck #2 verify
    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"challenege_Az", &mut buf);
    let r_a = random_bytes_to_fr::<G>(&buf);

    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"challenege_Bz", &mut buf);
    let r_b = random_bytes_to_fr::<G>(&buf);

    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"challenege_Cz", &mut buf);
    let r_c = random_bytes_to_fr::<G>(&buf);
    let claim_commit_two = (proof
        .knowledge_product_commit
        .va_commit
        .into_projective()
        .mul(r_a.into())
        + &(proof
            .knowledge_product_commit
            .vb_commit
            .into_projective()
            .mul(r_b.into()))
        + &(proof
            .knowledge_product_commit
            .vc_commit
            .into_projective()
            .mul(r_c.into())))
        .into_affine();
    let (ry, commit_eval_y) = sum_check_verify::<G>(
        &params.sc_params.gen_1,
        &params.sc_params.gen_3,
        &proof.proof_two,
        claim_commit_two,
        3,
        num_rounds_y,
        transcript,
    )?;

    let result = inner_product_verify::<G>(
        &params.pc_params,
        &ry[1..].to_vec(),
        &proof.commit_witness,
        proof.commit_ry,
        &proof.product_proof,
        transcript,
    )?;
    if !result {
        return Ok((false, Vec::new(), Vec::new()));
    }

    let mut public_inputs = vec![G::Fr::one()];
    public_inputs.extend(inputs.clone());
    public_inputs.extend(&vec![
        G::Fr::zero();
        (2usize).pow(ry[1..].len() as u32) - inputs.len() - 1
    ]);

    let eval_input_tau = sparse_evaluate_value::<G>(&public_inputs, &ry[1..].to_vec());
    let commit_input = poly_commit_vec::<G>(
        &params.pc_params.gen_1.generators,
        &vec![eval_input_tau],
        &params.pc_params.gen_1.h,
        G::Fr::zero(),
    )?
    .commit;
    let commit_eval_z =
        (proof.commit_ry.mul(G::Fr::one() - &ry[0]) + &(commit_input.mul(ry[0]))).into_affine();

    // let (eval_a_r, eval_b_r, eval_c_r) = evals;
    let claim_commit_phase_two = commit_eval_z
        .mul(eval_a_r * &r_a + &(eval_b_r * &r_b) + &(eval_c_r * &r_c))
        .into_affine();

    let result = eq_verify::<G>(
        &params.pc_params.gen_1,
        claim_commit_phase_two,
        commit_eval_y,
        &proof.sc2_eq_proof,
        transcript,
    )?;
    if !result {
        return Ok((false, Vec::new(), Vec::new()));
    }

    Ok((result, rx, ry))
}

fn sum_check_verify<G: Curve>(
    params_gen_1: &MultiCommitmentParameters<G>,
    params_gen_n: &MultiCommitmentParameters<G>,
    proof: &SumCheckProof<G>,
    commit_claim: G::Affine,
    size: usize,
    num_rounds: usize,
    transcript: &mut Transcript,
) -> Result<(Vec<G::Fr>, G::Affine), SynthesisError> {
    let mut commit_claim = commit_claim;

    let mut rx: Vec<G::Fr> = Vec::new();
    for i in 0..num_rounds {
        let commit_poly = proof.comm_polys[i];
        let commit_eval = proof.comm_evals[i];
        let proof = &proof.proofs[i];

        transcript.append_message(b"comm_poly", &to_bytes!(commit_poly)?);

        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let r_i = random_bytes_to_fr::<G>(&buf);

        transcript.append_message(b"comm_claim_per_round", &to_bytes!(commit_claim)?);
        transcript.append_message(b"comm_eval", &to_bytes!(commit_eval)?);

        let result = sum_check_eval_verify::<G>(
            &params_gen_1,
            &params_gen_n,
            commit_poly,
            commit_eval,
            commit_claim,
            proof,
            r_i,
            size,
            transcript,
        )?;
        if !result {
            return Err(SynthesisError::MalformedVerifyingKey);
        }

        rx.push(r_i);
        commit_claim = commit_eval;
    }

    Ok((rx, commit_claim))
}

fn sum_check_eval_verify<G: Curve>(
    params_gen_1: &MultiCommitmentParameters<G>,
    params_gen_n: &MultiCommitmentParameters<G>,
    commit_poly: G::Affine,
    commit_eval: G::Affine,
    commit_claim: G::Affine,
    proof: &SumCheckEvalProof<G>,
    r: G::Fr,
    size: usize,
    transcript: &mut Transcript,
) -> Result<bool, SynthesisError> {
    let w = (0..2)
        .map(|_i| {
            let mut buf = [0u8; 31];
            transcript.challenge_bytes(b"combine_two_claims_to_one", &mut buf);
            random_bytes_to_fr::<G>(&buf)
        })
        .collect::<Vec<_>>();

    transcript.append_message(b"Cx", &to_bytes!(commit_poly)?);
    let commit_claim_value = (commit_claim.mul(w[0]) + &(commit_eval.mul(w[1]))).into_affine();
    transcript.append_message(b"Cy", &to_bytes!(commit_claim_value)?);
    transcript.append_message(b"delta", &to_bytes!(proof.d_commit)?);
    transcript.append_message(b"beta", &to_bytes!(proof.dot_cd_commit)?);

    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"c", &mut buf);
    let c = random_bytes_to_fr::<G>(&buf);

    // commit(d)
    let mut coeffs = Vec::new();
    let mut rc = G::Fr::one();
    for _ in 0..size {
        coeffs.push(w[0] + &(w[1] * &rc));
        rc *= &r;
    }
    coeffs[0] += &w[0];

    // first step
    // commit(poly)*c + commit(d)
    let lhs = commit_poly
        .mul(c)
        .add(&proof.d_commit.into_projective())
        .into_affine();
    // commit(z); z[i] = poly[i] * c + d[i]
    let rhs = poly_commit_vec::<G>(
        &params_gen_n.generators,
        &proof.z,
        &params_gen_n.h,
        proof.z_delta,
    )?
    .commit;
    let rs1 = lhs == rhs;

    // second step
    let lhs = (commit_claim_value.mul(c) + &proof.dot_cd_commit.into_projective()).into_affine();
    let sum: G::Fr = (0..size).map(|i| proof.z[i] * &coeffs[i]).sum();
    let rhs = poly_commit_vec::<G>(
        &params_gen_1.generators,
        &vec![sum],
        &params_gen_1.h,
        proof.z_beta,
    )?
    .commit;
    let rs2 = lhs == rhs;

    Ok(rs1 && rs2)
}

fn knowledge_verify<G: Curve>(
    params: &MultiCommitmentParameters<G>,
    proof: &KnowledgeProof<G>,
    commit: G::Affine,
    transcript: &mut Transcript,
) -> Result<bool, SynthesisError> {
    transcript.append_message(b"C", &to_bytes!(commit)?);
    transcript.append_message(b"alpha", &to_bytes!(proof.t_commit)?);
    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"c", &mut buf);
    let c = random_bytes_to_fr::<G>(&buf);

    let lhs =
        poly_commit_vec::<G>(&params.generators, &vec![proof.z1], &params.h, proof.z2)?.commit;

    let rhs = commit.mul(c) + &proof.t_commit.into_projective();

    Ok(lhs == rhs.into_affine())
}

fn product_verify<G: Curve>(
    params: &MultiCommitmentParameters<G>,
    proof: &ProductProof<G>,
    va_commit: G::Affine,
    vb_commit: G::Affine,
    prod_commit: G::Affine,
    transcript: &mut Transcript,
) -> Result<bool, SynthesisError> {
    let z1 = proof.z[0];
    let z2 = proof.z[1];
    let z3 = proof.z[2];
    let z4 = proof.z[3];
    let z5 = proof.z[4];

    transcript.append_message(b"X", &to_bytes!(va_commit)?);
    transcript.append_message(b"Y", &to_bytes!(vb_commit)?);
    transcript.append_message(b"Z", &to_bytes!(prod_commit)?);
    transcript.append_message(b"alpha", &to_bytes!(proof.commit_alpha)?);
    transcript.append_message(b"beta", &to_bytes!(proof.commit_beta)?);
    transcript.append_message(b"delta", &to_bytes!(proof.commit_delta)?);

    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"c", &mut buf);
    let c = random_bytes_to_fr::<G>(&buf);

    let rs1_lhs = proof.commit_alpha + va_commit.mul(c).into_affine();
    let rs1_rhs = poly_commit_vec::<G>(&params.generators, &vec![z1], &params.h, z2)?.commit;
    let rs1 = rs1_lhs == rs1_rhs;

    let rs2_lhs = proof.commit_beta + vb_commit.mul(c).into_affine();
    let rs2_rhs = poly_commit_vec::<G>(&params.generators, &vec![z3], &params.h, z4)?.commit;
    let rs2 = rs2_lhs == rs2_rhs;

    let rs3_lhs = proof.commit_delta + prod_commit.mul(c).into_affine();
    let rs3_rhs = poly_commit_vec::<G>(&vec![va_commit], &vec![z3], &params.h, z5)?.commit;
    let rs3 = rs3_lhs == rs3_rhs;

    Ok(rs1 && rs2 && rs3)
}

fn eq_verify<G: Curve>(
    params: &MultiCommitmentParameters<G>,
    commit1: G::Affine,
    commit2: G::Affine,
    proof: &EqProof<G>,
    transcript: &mut Transcript,
) -> Result<bool, SynthesisError> {
    transcript.append_message(b"C1", &to_bytes!(commit1)?);
    transcript.append_message(b"C2", &to_bytes!(commit2)?);
    transcript.append_message(b"alpha", &to_bytes!(proof.alpha)?);

    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"c", &mut buf);
    let c = random_bytes_to_fr::<G>(&buf);

    let commits = (commit1.into_projective() - &commit2.into_projective()).into_affine();

    let lhs = params.h.mul(proof.z);
    let rhs = commits.mul(c) + &proof.alpha.into_projective();

    Ok(lhs == rhs)
}

fn inner_product_verify<G: Curve>(
    params: &PolyCommitmentParameters<G>,
    ry: &Vec<G::Fr>,
    commits_witness: &Vec<G::Affine>,
    commit_ry: G::Affine,
    proof: &DotProductProof<G>,
    transcript: &mut Transcript,
) -> Result<bool, SynthesisError> {
    transcript.append_message(b"protocol-name", b"polynomial evaluation proof");

    let size = ry.len();
    // let l_size = (2usize).pow((size/2) as u32) ;
    // let r_size = (2usize).pow((size - size / 2) as u32);

    let l_eq_ry = eval_eq::<G>(&(ry[0..size / 2].to_vec()));
    let r_eq_ry = eval_eq::<G>(&ry[size / 2..size].to_vec());

    let commit_lz =
        poly_commit_vec::<G>(commits_witness, &l_eq_ry, &params.gen_1.h, G::Fr::zero())?.commit;

    transcript.append_message(b"Cx", &to_bytes!(commit_lz)?);
    transcript.append_message(b"Cy", &to_bytes!(commit_ry)?);

    let gamma = commit_lz + commit_ry;

    let (b_s, g_hat, gamma_hat) = bullet_inner_product_verify::<G>(
        &params.gen_n.generators,
        &proof.inner_product_proof,
        gamma,
        &r_eq_ry,
        transcript,
    )?;
    transcript.append_message(b"delta", &to_bytes!(proof.delta)?);
    transcript.append_message(b"beta", &to_bytes!(proof.beta)?);
    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"challenge_tau", &mut buf);
    let c = random_bytes_to_fr::<G>(&buf);
    let lhs = (gamma_hat.mul(c) + &proof.beta.into_projective()).mul(b_s.into())
        + &proof.delta.into_projective();
    let rhs = (g_hat + params.gen_1.generators[0].mul(b_s).into_affine())
        .mul(proof.z1)
        .into_affine()
        + (params.gen_1.h.mul(proof.z2)).into_affine();

    Ok(lhs == rhs.into_projective())
}

fn sparse_poly_eval_verify<G: Curve>(
    params: &R1CSEvalsParameters<G>,
    proof: &R1CSEvalsProof<G>,
    encode_commit: &EncodeCommit<G>,
    r: (&Vec<G::Fr>, &Vec<G::Fr>),
    evals: (G::Fr, G::Fr, G::Fr),
    transcript: &mut Transcript,
) -> Result<bool, SynthesisError> {
    transcript.append_message(b"protocol-name", b"sparse polynomial evaluation proof");

    let (rx, ry) = r;
    let (eval_a_r, eval_b_r, eval_c_r) = evals;

    // memory_row = [eq(0, rx), rq(1, rx)...]
    // memory_col= [eq(0, ry), rq(1, ry)...]
    let (rx, ry) = equalize_length::<G>(&rx, &ry)?;

    let (n, m) = (encode_commit.n, encode_commit.m);
    assert_eq!((2usize).pow(rx.len() as u32), m);

    transcript.append_message(
        b"comm_poly_row_col_ops_val",
        &to_bytes!(proof.derefs_commit)?,
    );

    // gamma1, gamma2
    let gamma = (0..2)
        .map(|_i| {
            let mut buf = [0u8; 31];
            transcript.challenge_bytes(b"challenge_gamma_hash", &mut buf);
            random_bytes_to_fr::<G>(&buf)
        })
        .collect::<Vec<_>>();

    let (claims_ops, claims_ops_dotp, ops_rands, claims_mem, _, mem_rands) =
        product_layer_verify::<G>(
            &proof.prod_layer_proof,
            n,
            m,
            &vec![eval_a_r, eval_b_r, eval_c_r],
            transcript,
        )?;
    assert_eq!(claims_mem.len(), 4);
    assert_eq!(claims_ops.len(), 12);
    assert_eq!(claims_ops_dotp.len(), 9);

    let claims_ops_row_read = claims_ops[0..3].to_vec();
    let claims_ops_row_write = claims_ops[3..6].to_vec();
    let claims_ops_col_read = claims_ops[6..9].to_vec();
    let claims_ops_col_write = claims_ops[9..12].to_vec();

    // proof.hash_layer_proof
    let result = hash_layer_verify::<G>(
        params,
        &proof.hash_layer_proof,
        (&rx, &ry),
        (&ops_rands, &mem_rands),
        (gamma[0], gamma[1]),
        (
            claims_mem[0],
            &claims_ops_row_read,
            &claims_ops_row_write,
            claims_mem[1],
        ),
        (
            claims_mem[2],
            &claims_ops_col_read,
            &claims_ops_col_write,
            claims_mem[3],
        ),
        claims_ops_dotp,
        encode_commit,
        &proof.derefs_commit,
        transcript,
    )
    .is_ok();
    assert!(result);

    Ok(true)
}

fn product_layer_verify<G>(
    proof: &ProductLayerProof<G>,
    n: usize,
    m: usize,
    evals: &Vec<G::Fr>,
    transcript: &mut Transcript,
) -> Result<
    (
        Vec<G::Fr>,
        Vec<G::Fr>,
        Vec<G::Fr>,
        Vec<G::Fr>,
        Vec<G::Fr>,
        Vec<G::Fr>,
    ),
    SynthesisError,
>
where
    G: Curve,
{
    transcript.append_message(b"protocol-name", b"Sparse polynomial product layer proof");
    let (row_init, row_read_list, row_write_list, row_audit) = &proof.eval_row;
    let (col_init, col_read_list, col_write_list, col_audit) = &proof.eval_col;
    let (eval_dotp_left_list, eval_dotp_right_list) = &proof.eval_dotp;

    assert_eq!(row_read_list.len(), 3);
    assert_eq!(row_write_list.len(), 3);
    assert_eq!(col_read_list.len(), 3);
    assert_eq!(col_write_list.len(), 3);
    assert_eq!(eval_dotp_left_list.len(), 3);
    assert_eq!(eval_dotp_right_list.len(), 3);
    assert_eq!(evals.len(), 3);

    let row_read: G::Fr = (0..row_read_list.len()).map(|i| row_read_list[i]).product();
    let row_write: G::Fr = (0..row_write_list.len())
        .map(|i| row_write_list[i])
        .product();
    assert_eq!(*row_init * &row_write, row_read * row_audit);

    transcript.append_message(b"claim_row_eval_init", &to_bytes!(row_init)?);
    transcript.append_message(b"claim_row_eval_read", &to_bytes!(row_read_list)?);
    transcript.append_message(b"claim_row_eval_write", &to_bytes!(row_write_list)?);
    transcript.append_message(b"claim_row_eval_audit", &to_bytes!(row_audit)?);

    let col_read: G::Fr = (0..col_read_list.len()).map(|i| col_read_list[i]).product();
    let col_write: G::Fr = (0..col_write_list.len())
        .map(|i| col_write_list[i])
        .product();
    assert_eq!(*col_init * &col_write, col_read * col_audit);

    transcript.append_message(b"claim_col_eval_init", &to_bytes!(col_init)?);
    transcript.append_message(b"claim_col_eval_read", &to_bytes!(col_read_list)?);
    transcript.append_message(b"claim_col_eval_write", &to_bytes!(col_write_list)?);
    transcript.append_message(b"claim_col_eval_audit", &to_bytes!(col_audit)?);

    let mut claims_dotp_circuit = Vec::new();
    for i in 0..eval_dotp_left_list.len() {
        assert_eq!(eval_dotp_left_list[i] + &eval_dotp_right_list[i], evals[i]);
        transcript.append_message(b"claim_eval_dotp_left", &to_bytes!(eval_dotp_left_list[i])?);
        transcript.append_message(
            b"claim_eval_dotp_right",
            &to_bytes!(eval_dotp_right_list[i])?,
        );
        claims_dotp_circuit.push(eval_dotp_left_list[i]);
        claims_dotp_circuit.push(eval_dotp_right_list[i]);
    }

    let mut claims_prod_circuit = Vec::new();
    claims_prod_circuit.extend(row_read_list);
    claims_prod_circuit.extend(row_write_list);
    claims_prod_circuit.extend(col_read_list);
    claims_prod_circuit.extend(col_write_list);

    let (claims_ops, claims_ops_dotp, ops_rands) = product_circuit_eval_verify::<G>(
        &proof.proof_ops,
        &claims_prod_circuit,
        &mut claims_dotp_circuit,
        n,
        transcript,
    )?;
    let (claims_mem, claims_mem_dotp, mem_rands) = product_circuit_eval_verify::<G>(
        &proof.proof_memory,
        &vec![*row_init, *row_audit, *col_init, *col_audit],
        &mut vec![],
        m,
        transcript,
    )?;

    Ok((
        claims_ops,
        claims_ops_dotp,
        ops_rands,
        claims_mem,
        claims_mem_dotp,
        mem_rands,
    ))
}

pub fn product_circuit_eval_verify<G: Curve>(
    proof: &ProductCircuitEvalProof<G>,
    claims_prod_circuit: &Vec<G::Fr>,
    claims_dotp_circuit: &Vec<G::Fr>,
    n: usize,
    transcript: &mut Transcript,
) -> Result<(Vec<G::Fr>, Vec<G::Fr>, Vec<G::Fr>), SynthesisError> {
    let layer_num = log2(n) as usize;
    let mut claims_to_verify = claims_prod_circuit.clone();

    assert_eq!(proof.layers_proof.len(), layer_num);

    let mut num_rounds = 0;
    let mut rands = Vec::new();
    let mut claims_to_verify_dotp = Vec::new();
    for i in 0..layer_num {
        if i == layer_num - 1 {
            claims_to_verify.extend(claims_dotp_circuit);
        }

        let coeffs = (0..claims_to_verify.len())
            .map(|_i| {
                let mut buf = [0u8; 31];
                transcript.challenge_bytes(b"rand_coeffs_next_layer", &mut buf);
                random_bytes_to_fr::<G>(&buf)
            })
            .collect::<Vec<_>>();

        let claim: G::Fr = (0..coeffs.len())
            .map(|i| claims_to_verify[i] * &coeffs[i])
            .sum();

        let (r, claim_final) = sum_check_cubic_verify::<G>(
            &proof.layers_proof[i].polys,
            num_rounds,
            claim,
            transcript,
        )?;
        let claim_prod_left = &proof.layers_proof[i].claim_prod_left;
        let claim_prod_right = &proof.layers_proof[i].claim_prod_right;
        assert_eq!(claim_prod_left.len(), claim_prod_right.len());
        assert_eq!(claim_prod_left.len(), claims_prod_circuit.len());
        for i in 0..claim_prod_left.len() {
            transcript.append_message(b"claim_prod_left", &to_bytes!(claim_prod_left[i])?);
            transcript.append_message(b"claim_prod_right", &to_bytes!(claim_prod_right[i])?);
        }

        assert_eq!(rands.len(), r.len());
        let eq: G::Fr = (0..r.len())
            .map(|i| r[i] * &rands[i] + &((G::Fr::one() - &r[i]) * &(G::Fr::one() - &rands[i])))
            .product();

        let mut claim_expected: G::Fr = (0..claim_prod_left.len())
            .map(|i| coeffs[i] * &(claim_prod_left[i] * &claim_prod_right[i] * &eq))
            .sum();

        if i == layer_num - 1 {
            let (claim_dotp_row, claim_dotp_col, claim_dotp_val) = &proof.claim_dotp;
            for i in 0..claim_dotp_row.len() {
                transcript.append_message(b"claim_dotp_row", &to_bytes!(claim_dotp_row[i])?);
                transcript.append_message(b"claim_dotp_col", &to_bytes!(claim_dotp_col[i])?);
                transcript.append_message(b"claim_dotp_val", &to_bytes!(claim_dotp_val[i])?);

                claim_expected += &(coeffs[claim_prod_left.len() + i]
                    * &claim_dotp_row[i]
                    * &claim_dotp_col[i]
                    * &claim_dotp_val[i]);
            }
        }

        assert_eq!(claim_expected, claim_final);
        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"challenge_r_layer", &mut buf);
        let r_layer = random_bytes_to_fr::<G>(&buf);

        claims_to_verify = (0..claim_prod_left.len())
            .map(|i| claim_prod_left[i] + &(r_layer * &(claim_prod_right[i] - &claim_prod_left[i])))
            .collect::<Vec<G::Fr>>();
        if i == layer_num - 1 {
            let (claim_dotp_row, claim_dotp_col, claim_dotp_val) = &proof.claim_dotp;
            for i in 0..claim_dotp_row.len() / 2 {
                let claim_row = claim_dotp_row[2 * i]
                    + &(r_layer * &(claim_dotp_row[2 * i + 1] - &claim_dotp_row[2 * i]));
                let claim_col = claim_dotp_col[2 * i]
                    + &(r_layer * &(claim_dotp_col[2 * i + 1] - &claim_dotp_col[2 * i]));
                let claim_val = claim_dotp_val[2 * i]
                    + &(r_layer * &(claim_dotp_val[2 * i + 1] - &claim_dotp_val[2 * i]));
                claims_to_verify_dotp.push(claim_row);
                claims_to_verify_dotp.push(claim_col);
                claims_to_verify_dotp.push(claim_val);
            }
        }
        num_rounds += 1;
        rands = vec![r_layer];
        rands.extend(r);
    }

    Ok((claims_to_verify, claims_to_verify_dotp, rands))
}

pub fn sum_check_cubic_verify<G: Curve>(
    proof_poly: &Vec<DensePolynomial<G::Fr>>,
    num_rounds: usize,
    claim: G::Fr,
    transcript: &mut Transcript,
) -> Result<(Vec<G::Fr>, G::Fr), SynthesisError> {
    let mut claim_per_round = claim;
    let mut r = Vec::new();

    assert_eq!(proof_poly.len(), num_rounds);
    for poly in proof_poly.iter() {
        transcript.append_message(b"comm_poly", &to_bytes!(poly.coeffs)?);
        assert_eq!(
            poly.evaluate(&G::Fr::zero()) + &poly.evaluate(&G::Fr::one()),
            claim_per_round
        );
        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let r_j = random_bytes_to_fr::<G>(&buf);
        claim_per_round = poly.evaluate(&r_j);
        r.push(r_j);
    }

    Ok((r, claim_per_round))
}

pub fn hash_layer_verify<G: Curve>(
    params: &R1CSEvalsParameters<G>,
    proof: &HashLayerProof<G>,
    r: (&Vec<G::Fr>, &Vec<G::Fr>),
    rands: (&Vec<G::Fr>, &Vec<G::Fr>),
    gamma: (G::Fr, G::Fr),
    claims_row: (G::Fr, &Vec<G::Fr>, &Vec<G::Fr>, G::Fr),
    claims_col: (G::Fr, &Vec<G::Fr>, &Vec<G::Fr>, G::Fr),
    claims_dotp: Vec<G::Fr>,
    encode_commit: &EncodeCommit<G>,
    derefs_commit: &Vec<G::Affine>,
    transcript: &mut Transcript,
) -> Result<(), SynthesisError> {
    transcript.append_message(b"protocol-name", b"Sparse polynomial hash layer proof");

    assert_eq!(claims_dotp.len(), 9);
    let (ops_rands, mem_rands) = rands;
    let (rx, ry) = r;
    // let (gamma1,gamma2) = gamma;
    // let  (claims_row_init, claims_row_read_list, claims_row_write_list, claims_row_audit) = claims_row;
    // let  (claims_col_init, claims_col_read_list, claims_col_write_list, claims_col_audit) = claims_col;

    let (eval_row_ops_val, eval_col_ops_val) = &proof.evals_derefs;
    assert_eq!(eval_row_ops_val.len(), eval_col_ops_val.len());
    assert_eq!(eval_row_ops_val.len(), 3);
    let mut evals = eval_row_ops_val.clone();
    evals.extend(eval_col_ops_val.clone());
    evals.resize(evals.len().next_power_of_two(), G::Fr::zero());
    transcript.append_message(b"protocol-name", b"Derefs evaluation proof");

    transcript.append_message(b"evals_ops_val", &to_bytes!(evals)?);

    let mut cs = (0..log2(evals.len()))
        .map(|_i| {
            let mut buf = [0u8; 31];
            transcript.challenge_bytes(b"challenge_combine_n_to_one", &mut buf);
            random_bytes_to_fr::<G>(&buf)
        })
        .collect::<Vec<_>>();

    for i in (0..cs.len()).rev() {
        bound_poly_var_bot::<G>(&mut evals, cs[i]);
    }
    assert_eq!(evals.len(), 1);
    let claim_eval = evals[0];
    // let mut rs = cs;
    cs.extend(ops_rands);
    transcript.append_message(b"joint_claim_eval", &to_bytes!(claim_eval)?);

    // derefs prove
    let claim_eval_commit = poly_commit_vec::<G>(
        &params.derefs_params.gen_1.generators,
        &vec![claim_eval],
        &params.derefs_params.gen_1.h,
        G::Fr::zero(),
    )?
    .commit;
    let result = inner_product_verify::<G>(
        &params.derefs_params,
        &cs,
        &derefs_commit,
        claim_eval_commit,
        &proof.proof_derefs,
        transcript,
    )?;
    assert!(result);
    let eval_val_list = &proof.evals_val;
    assert_eq!(eval_val_list.len(), 3);
    for i in 0..3 {
        assert_eq!(claims_dotp[i * 3], eval_row_ops_val[i]);
        assert_eq!(claims_dotp[i * 3 + 1], eval_col_ops_val[i]);
        assert_eq!(claims_dotp[i * 3 + 2], eval_val_list[i]);
    }

    let (row_eval_addr_ops_list, row_eval_read_ts_list, row_eval_audit_ts_val) =
        proof.evals_row.clone();
    let (col_eval_addr_ops_list, col_eval_read_ts_list, col_eval_audit_ts_val) =
        proof.evals_col.clone();

    let mut evals_ops: Vec<G::Fr> = Vec::new();
    evals_ops.extend(row_eval_addr_ops_list);
    evals_ops.extend(row_eval_read_ts_list);
    evals_ops.extend(col_eval_addr_ops_list);
    evals_ops.extend(col_eval_read_ts_list);
    evals_ops.extend(eval_val_list);
    evals_ops.resize(evals_ops.len().next_power_of_two(), G::Fr::zero());
    transcript.append_message(b"claim_evals_ops", &to_bytes!(evals_ops)?);

    let mut cs_ops = (0..log2(evals_ops.len()))
        .map(|_i| {
            let mut buf = [0u8; 31];
            transcript.challenge_bytes(b"challenge_combine_n_to_one", &mut buf);
            random_bytes_to_fr::<G>(&buf)
        })
        .collect::<Vec<_>>();

    for i in (0..cs_ops.len()).rev() {
        bound_poly_var_bot::<G>(&mut evals_ops, cs_ops[i]);
    }
    assert_eq!(evals_ops.len(), 1);
    let claim_eval_ops = evals_ops[0];
    // let mut rs_ops = cs_ops;
    cs_ops.extend(ops_rands);
    transcript.append_message(b"joint_claim_eval_ops", &to_bytes!(claim_eval_ops)?);
    // ops prove
    let claim_eval_commit = poly_commit_vec::<G>(
        &params.ops_params.gen_1.generators,
        &vec![claim_eval_ops],
        &params.ops_params.gen_1.h,
        G::Fr::zero(),
    )?
    .commit;
    let result = inner_product_verify::<G>(
        &params.ops_params,
        &cs_ops,
        &encode_commit.ops_commit,
        claim_eval_commit,
        &proof.proof_ops,
        transcript,
    )?;
    assert!(result);
    let mut evals_mem = vec![row_eval_audit_ts_val, col_eval_audit_ts_val];
    transcript.append_message(b"claim_evals_mem", &to_bytes!(evals_mem)?);
    let mut cs_mem = (0..log2(evals_mem.len()))
        .map(|_i| {
            let mut buf = [0u8; 31];
            transcript.challenge_bytes(b"challenge_combine_two_to_one", &mut buf);
            random_bytes_to_fr::<G>(&buf)
        })
        .collect::<Vec<_>>();

    for i in (0..cs_mem.len()).rev() {
        bound_poly_var_bot::<G>(&mut evals_mem, cs_mem[i]);
    }
    assert_eq!(evals_mem.len(), 1);
    let claim_eval_mem = evals_mem[0];
    // let mut rs_mem = cs_mem;
    cs_mem.extend(mem_rands);

    transcript.append_message(b"joint_claim_eval_mem", &to_bytes!(claim_eval_mem)?);

    // mem prove
    let claim_eval_commit = poly_commit_vec::<G>(
        &params.mem_params.gen_1.generators,
        &vec![claim_eval_mem],
        &params.mem_params.gen_1.h,
        G::Fr::zero(),
    )?
    .commit;
    let result = inner_product_verify::<G>(
        &params.mem_params,
        &cs_mem,
        &encode_commit.mem_commit,
        claim_eval_commit,
        &proof.proof_mem,
        transcript,
    )?;
    assert!(result);
    let (row_eval_addr_ops_list, row_eval_read_ts_list, row_eval_audit_ts_val) = &proof.evals_row;
    let result = behind_verify_for_timestamp::<G>(
        rands,
        claims_row,
        rx,
        &eval_row_ops_val,
        row_eval_addr_ops_list,
        row_eval_read_ts_list,
        row_eval_audit_ts_val,
        gamma,
    )
    .is_ok();
    assert!(result);
    let (col_eval_addr_ops_list, col_eval_read_ts_list, col_eval_audit_ts_val) = &proof.evals_col;
    let result = behind_verify_for_timestamp::<G>(
        rands,
        claims_col,
        ry,
        &eval_col_ops_val,
        col_eval_addr_ops_list,
        col_eval_read_ts_list,
        col_eval_audit_ts_val,
        gamma,
    )
    .is_ok();
    assert!(result);
    Ok(())
}

pub fn behind_verify_for_timestamp<G>(
    rands: (&Vec<G::Fr>, &Vec<G::Fr>),
    claims: (G::Fr, &Vec<G::Fr>, &Vec<G::Fr>, G::Fr),
    r: &Vec<G::Fr>,
    eval_ops_val: &Vec<G::Fr>,
    eval_addr_ops_list: &Vec<G::Fr>,
    eval_read_ts_list: &Vec<G::Fr>,
    eval_audit_ts_val: &G::Fr,
    gamma: (G::Fr, G::Fr),
) -> Result<bool, SynthesisError>
where
    G: Curve,
{
    let (_rands_ops, rands_mem) = rands;
    let (gamma1, gamma2) = gamma;
    let (claim_init, claim_read_list, claim_write_list, cliam_audit) = claims;

    let eval_init_addr: G::Fr = (0..rands_mem.len())
        .map(|i| {
            rands_mem[i]
                * &G::Fr::from_repr((2u64).pow((rands_mem.len() - i - 1) as u32).into()).unwrap()
        })
        .sum();

    let eval_init_val = eval_eq_x_y::<G>(&r, &rands_mem);
    let hash_init_at_rand_mem =
        eval_init_addr * &gamma1 * &gamma1 + &(eval_init_val * &gamma1) - &gamma2;
    assert_eq!(claim_init, hash_init_at_rand_mem);

    for i in 0..eval_addr_ops_list.len() {
        let hash_read_at_rand_ops = eval_addr_ops_list[i] * &gamma1 * &gamma1
            + &(eval_ops_val[i] * &gamma1)
            + &eval_read_ts_list[i]
            - &gamma2;
        assert_eq!(claim_read_list[i], hash_read_at_rand_ops);
    }

    for i in 0..eval_addr_ops_list.len() {
        let hash_write_at_rand_ops = eval_addr_ops_list[i] * &gamma1 * &gamma1
            + &(eval_ops_val[i] * &gamma1)
            + &(eval_read_ts_list[i] + &G::Fr::one())
            - &gamma2;
        assert_eq!(claim_write_list[i], hash_write_at_rand_ops);
    }

    let eval_audit_addr = eval_init_addr;
    let eval_audit_val = eval_init_val;
    let hash_audit_at_rand_mem =
        eval_audit_addr * &gamma1 * &gamma1 + &(eval_audit_val * &gamma1) + eval_audit_ts_val
            - &gamma2;
    assert_eq!(cliam_audit, hash_audit_at_rand_mem);

    Ok(true)
}
