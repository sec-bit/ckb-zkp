use crate::libra::circuit::Circuit;
use crate::libra::data_structure::{
    SumCheckCommitmentSetupParameters, ZKLayerProof, ZKLinearGKRProof,
};
use crate::libra::evaluate::{eval_output, eval_value, poly_commit_vec, random_bytes_to_fr};
use crate::libra::libra_linear_gkr::{initialize_phase_one, initialize_phase_two};
use crate::libra::sumcheck::{sum_check_eval_verify, zk_sumcheck_phase_one, zk_sumcheck_phase_two};
use math::{bytes::ToBytes, One, PairingEngine, Zero};
use merlin::Transcript;
use rand::Rng;

pub fn zk_linear_gkr_prover<E: PairingEngine, R: Rng>(
    params: &SumCheckCommitmentSetupParameters<E>,
    circuit: &Circuit<E>,
    rng: &mut R,
) -> (ZKLinearGKRProof<E>, Vec<E::Fr>) {
    let mut transcript = Transcript::new(b"libra - zk linear gkr");
    let circuit_evals = circuit.evaluate();

    let mut alpha = E::Fr::one();
    let mut beta = E::Fr::zero();
    // V_0(g^(0)), g^(0)
    let (mut result_u, mut gu) = eval_output::<E>(
        &circuit_evals[circuit_evals.len() - 1],
        circuit.layers[circuit.depth - 1].bit_size,
        &mut transcript,
    );
    let mut gv = vec![E::Fr::zero(); gu.len()];
    let mut result_v = E::Fr::zero();
    let mut proofs = Vec::new();
    let mut claim_blind = E::Fr::zero();

    // sumcheck
    for d in (1..circuit.depth).rev() {
        println!("linear_gkr_prover -- layer = {}", d);
        let mut claim = alpha * &result_u + &(beta * &result_v);
        let uv_size = circuit.layers[d - 1].bit_size;

        // phase1
        let (mul_hg_vec, add_hg_vec1, add_hg_vec2) = initialize_phase_one(
            &gu,
            &gv,
            &circuit.layers[d].gates,
            &circuit_evals[d - 1],
            uv_size,
            alpha,
            beta,
        );
        println!("initialize_phase_one...");
        let (proof_phase_one, ru) = zk_sumcheck_phase_one::<E, R>(
            params,
            &circuit_evals[d - 1],
            &(mul_hg_vec, add_hg_vec1, add_hg_vec2),
            uv_size,
            claim,
            claim_blind,
            rng,
            &mut transcript,
        );
        println!("sumcheck_phase_one...");

        let eval_ru = proof_phase_one.poly_value_at_r.clone();
        claim = eval_ru[0] * &eval_ru[1] + &(eval_ru[0] * &eval_ru[2]) + &eval_ru[3];

        // phase2
        let (mul_hg_vec, add_hg_vec, fu) = initialize_phase_two(
            &gu,
            &gv,
            &ru,
            &circuit.layers[d].gates,
            &circuit_evals[d - 1],
            uv_size,
            alpha,
            beta,
        );
        println!("initialize_phase_two...");

        let (proof_phase_two, rv) = zk_sumcheck_phase_two::<E, R>(
            params,
            &circuit_evals[d - 1],
            &(mul_hg_vec, add_hg_vec, fu),
            uv_size,
            claim,
            proof_phase_one.blind_eval,
            rng,
            &mut transcript,
        );
        println!("sumcheck_phase_two...");

        let eval_rv = proof_phase_two.poly_value_at_r.clone();
        // claim = eval_rv[1] * &eval_rv[0] * &fu + &(eval_rv[2] * &fu) + &(eval_rv[2] * &eval_rv[0]);

        if d > 1 {
            gu = ru.clone();
            gv = rv.clone();
            result_u = fu;
            result_v = eval_rv[0];
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_alpha", &mut buf);
            alpha = random_bytes_to_fr::<E>(&buf);
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_beta", &mut buf);
            beta = random_bytes_to_fr::<E>(&buf);
            claim_blind = proof_phase_two.blind_eval;
        }

        let proof = ZKLayerProof::<E> {
            proof_phase_one,
            proof_phase_two,
        };
        proofs.push(proof);
    }

    let proof = ZKLinearGKRProof { proofs };
    let output = circuit_evals[circuit_evals.len() - 1].clone();
    (proof, output)
}

pub fn zk_linear_gkr_verifier<E: PairingEngine>(
    params: &SumCheckCommitmentSetupParameters<E>,
    circuit: &Circuit<E>,
    output: &Vec<E::Fr>,
    input: &Vec<E::Fr>,
    proof: ZKLinearGKRProof<E>,
) -> bool {
    let mut transcript = Transcript::new(b"libra - zk linear gkr");

    let mut alpha = E::Fr::one();
    let mut beta = E::Fr::zero();
    let (mut result_u, _) = eval_output::<E>(
        &output,
        circuit.layers[circuit.depth - 1].bit_size,
        &mut transcript,
    );
    let mut result_v = E::Fr::zero();
    let mut eval_ru_x = E::Fr::zero();
    let mut eval_rv_y = E::Fr::zero();
    let mut ru_vec = Vec::new();
    let mut rv_vec = Vec::new();
    let mut claim_blind = E::Fr::zero();
    assert_eq!(circuit.depth - 1, proof.proofs.len());
    for (d, lproof) in proof.proofs.iter().enumerate() {
        let claim = alpha * &result_u + &(beta * &result_v);
        let mut comm_claim = poly_commit_vec::<E>(
            &params.gen_1.generators,
            &vec![claim],
            &params.gen_1.h,
            claim_blind,
        );
        println!(
            "linear_gkr_verifier - verifier...d = {}",
            circuit.depth - d - 1
        );
        let (proof1, proof2) = (&lproof.proof_phase_one, &lproof.proof_phase_two);
        let bit_size = circuit.layers[circuit.depth - d - 2].bit_size;
        ru_vec = Vec::new();
        rv_vec = Vec::new();
        // let mut comm_claim = comm_claim;
        for i in 0..bit_size {
            let comm_poly = proof1.comm_polys[i];
            transcript.append_message(b"comm_poly", &math::to_bytes!(comm_poly).unwrap());
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_nextround", &mut buf);
            let r_u = random_bytes_to_fr::<E>(&buf);

            let comm_eval = proof1.comm_evals[i];
            transcript.append_message(
                b"comm_claim_per_round",
                &math::to_bytes!(comm_claim).unwrap(),
            );
            transcript.append_message(b"comm_eval", &math::to_bytes!(comm_eval).unwrap());

            let result = sum_check_eval_verify::<E>(
                params,
                comm_poly,
                comm_eval,
                comm_claim,
                &proof1.proofs[i],
                r_u,
                3,
                &mut transcript,
            );
            assert!(result);

            ru_vec.push(r_u);
            comm_claim = comm_eval;
        }
        println!("linear_gkr_verifier - phase one...");

        let eval_ru_final = proof1.poly_value_at_r.clone();
        // transcript.append_message(b"claim_final", &math::to_bytes!(eval_ru_final).unwrap());
        //TODO
        let claim_final = eval_ru_final[0] * &eval_ru_final[1]
            + &(eval_ru_final[0] * &eval_ru_final[2])
            + &eval_ru_final[3];
        let final_comm_claim = poly_commit_vec::<E>(
            &params.gen_1.generators,
            &vec![claim_final],
            &params.gen_1.h,
            proof1.blind_eval,
        );
        assert_eq!(comm_claim, final_comm_claim);

        for i in 0..bit_size {
            let comm_poly = proof2.comm_polys[i];
            transcript.append_message(b"comm_poly", &math::to_bytes!(comm_poly).unwrap());
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_nextround", &mut buf);
            let r_v = random_bytes_to_fr::<E>(&buf);

            let comm_eval = proof2.comm_evals[i];
            transcript.append_message(
                b"comm_claim_per_round",
                &math::to_bytes!(comm_claim).unwrap(),
            );
            transcript.append_message(b"comm_eval", &math::to_bytes!(comm_eval).unwrap());

            let result = sum_check_eval_verify::<E>(
                params,
                comm_poly,
                comm_eval,
                comm_claim,
                &proof2.proofs[i],
                r_v,
                3,
                &mut transcript,
            );
            assert!(result);

            rv_vec.push(r_v);
            comm_claim = comm_eval;
        }
        println!("linear_gkr_verifier - phase two...");

        let eval_rv_final = proof2.poly_value_at_r.clone();
        // transcript.append_message(b"claim_final", &math::to_bytes!(eval_rv_final).unwrap());

        let claim_final = eval_rv_final[1] * &eval_rv_final[0] * &eval_ru_final[0]
            + &(eval_rv_final[2] * &eval_ru_final[0])
            + &(eval_rv_final[2] * &eval_rv_final[0]);
        let final_comm_claim = poly_commit_vec::<E>(
            &params.gen_1.generators,
            &vec![claim_final],
            &params.gen_1.h,
            proof2.blind_eval,
        );
        assert_eq!(comm_claim, final_comm_claim);

        if d < circuit.depth - 2 {
            result_u = eval_ru_final[0];
            result_v = eval_rv_final[0];
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_alpha", &mut buf);
            alpha = random_bytes_to_fr::<E>(&buf);
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge_beta", &mut buf);
            beta = random_bytes_to_fr::<E>(&buf);
            claim_blind = proof2.blind_eval
        } else {
            eval_ru_x = eval_ru_final[0];
            eval_rv_y = eval_rv_final[0];
        }
    }
    let eval_ru_input = eval_value::<E>(&input, &ru_vec);
    let eval_rv_input = eval_value::<E>(&input, &rv_vec);

    (eval_ru_x == eval_ru_input) && (eval_rv_y == eval_rv_input)
}
