use crate::libra::circuit::Circuit;
use crate::libra::commitment::{EqProof, LogDotProductProof, ProductProof};
use crate::libra::evaluate::{
    eval_output, eval_value, packing_poly_commit, poly_commit_vec, random_bytes_to_fr,
};
use crate::libra::libra_linear_gkr::{initialize_phase_one, initialize_phase_two};
use crate::libra::params::Parameters;
use crate::libra::sumcheck::ZKSumCheckProof;
use math::{bytes::ToBytes, AffineCurve, Curve, One, ProjectiveCurve, UniformRand, Zero};
use merlin::Transcript;
use rand::Rng;

pub struct ZKLayerProof<G: Curve> {
    pub proof_phase_one: ZKSumCheckProof<G>,
    pub proof_phase_two: ZKSumCheckProof<G>,
    pub comm_x: G::Affine,
    pub comm_y: G::Affine,
    pub comm_z: G::Affine,
    pub prod_proof: ProductProof<G>,
    pub eq_proof: EqProof<G>,
}

pub struct ZKLinearGKRProof<G: Curve> {
    pub comm_witness: Vec<G::Affine>,
    pub proofs: Vec<ZKLayerProof<G>>,
    pub prod_proof0: LogDotProductProof<G>,
    pub comm_y0: G::Affine,
    pub eq_proof0: EqProof<G>,
    pub prod_proof1: LogDotProductProof<G>,
    pub comm_y1: G::Affine,
    pub eq_proof1: EqProof<G>,
}

impl<G: Curve> ZKLinearGKRProof<G> {
    pub fn prover<R: Rng>(
        params: &Parameters<G>,
        circuit: &Circuit,
        inputs: &Vec<G::Fr>,
        witnesses: &Vec<G::Fr>,
        rng: &mut R,
    ) -> (Self, Vec<G::Fr>) {
        let mut transcript = Transcript::new(b"libra - zk linear gkr");
        let circuit_evals = circuit.evaluate::<G>(inputs, witnesses).unwrap();

        let (comm_witness, witness_blind) = packing_poly_commit::<G, R>(
            &params.pc_params.gen_n.generators,
            &witnesses,
            &params.pc_params.gen_n.h,
            rng,
            true,
        );
        transcript.append_message(b"comm_witness", &math::to_bytes!(comm_witness).unwrap());

        let mut alpha = G::Fr::one();
        let mut beta = G::Fr::zero();
        // V_0(g^(0)), g^(0)
        let (mut result_u, mut gu) = eval_output::<G>(
            &circuit_evals[circuit_evals.len() - 1],
            circuit.layers[circuit.depth - 1].bit_size,
            &mut transcript,
        );
        let mut gv = vec![G::Fr::zero(); gu.len()];
        let mut result_v = G::Fr::zero();
        let mut proofs = Vec::new();
        let mut claim_blind = G::Fr::zero();
        let mut final_x = G::Fr::zero();
        let mut final_y = G::Fr::zero();
        let mut final_blind_x = G::Fr::zero();
        let mut final_blind_y = G::Fr::zero();

        // sumcheck
        for d in (1..circuit.depth).rev() {
            let mut claim = alpha * &result_u + &(beta * &result_v);
            let uv_size = circuit.layers[d - 1].bit_size;
            // phase1
            let (mul_hg_vec, add_hg_vec1, add_hg_vec2) = initialize_phase_one::<G>(
                &gu,
                &gv,
                &circuit.layers[d].gates,
                &circuit_evals[d - 1],
                uv_size,
                alpha,
                beta,
            );
            let (proof_phase_one, eval_ru, blind_u, ru) = ZKSumCheckProof::phase_one_prover::<R>(
                &params.sc_params,
                &circuit_evals[d - 1],
                &(mul_hg_vec, add_hg_vec1, add_hg_vec2),
                uv_size,
                claim,
                claim_blind,
                rng,
                &mut transcript,
            );

            claim = eval_ru[0] * &eval_ru[1] + &(eval_ru[0] * &eval_ru[2]) + &eval_ru[3];
            let rx = G::Fr::rand(rng);
            let comm_x = poly_commit_vec::<G>(
                &params.sc_params.gen_1.generators,
                &vec![eval_ru[0]],
                &params.sc_params.gen_1.h,
                rx,
            );
            transcript.append_message(b"comm_x", &math::to_bytes!(comm_x).unwrap());
            // phase2
            let (mul_hg_vec, add_hg_vec, fu) = initialize_phase_two::<G>(
                &gu,
                &gv,
                &ru,
                &circuit.layers[d].gates,
                &circuit_evals[d - 1],
                uv_size,
                alpha,
                beta,
            );
            let (proof_phase_two, eval_rv, blind_v, rv) = ZKSumCheckProof::phase_two_prover::<R>(
                &params.sc_params,
                &circuit_evals[d - 1],
                &(mul_hg_vec, add_hg_vec, fu),
                uv_size,
                claim,
                blind_u,
                rng,
                &mut transcript,
            );
            let ry = G::Fr::rand(rng);
            let comm_y = poly_commit_vec::<G>(
                &params.sc_params.gen_1.generators,
                &vec![eval_rv[0]],
                &params.sc_params.gen_1.h,
                ry,
            );
            transcript.append_message(b"comm_y", &math::to_bytes!(comm_y).unwrap());

            let z = eval_ru[0] * &eval_rv[0];
            let rz = G::Fr::rand(rng);
            let (prod_proof, _, _, comm_z) = ProductProof::prover::<R>(
                &params.sc_params.gen_1,
                eval_ru[0],
                rx,
                eval_rv[0],
                ry,
                z,
                rz,
                rng,
                &mut transcript,
            );

            let eval = z * &eval_rv[1] + &((eval_ru[0] + &eval_rv[0]) * &eval_rv[2]);
            let eval_blind = rz * &eval_rv[1] + &((rx + &ry) * &eval_rv[2]);
            let eq_proof = EqProof::prover(
                &params.sc_params.gen_1,
                eval,
                eval_blind,
                eval,
                blind_v,
                rng,
                &mut transcript,
            );

            if d > 1 {
                gu = ru.clone();
                gv = rv.clone();
                result_u = fu;
                result_v = eval_rv[0];
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"challenge_alpha", &mut buf);
                alpha = random_bytes_to_fr::<G>(&buf);
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"challenge_beta", &mut buf);
                beta = random_bytes_to_fr::<G>(&buf);
                claim_blind = alpha * &rx + &(beta * &ry);
            } else {
                gu = ru.clone();
                gv = rv.clone();
                final_x = eval_ru[0];
                final_y = eval_rv[0];
                final_blind_x = rx;
                final_blind_y = ry;
            }
            let proof = ZKLayerProof::<G> {
                proof_phase_one,
                proof_phase_two,
                comm_x,
                comm_y,
                comm_z,
                prod_proof,
                eq_proof,
            };
            proofs.push(proof);
        }

        let blind_eval0 = G::Fr::rand(rng);
        let eval_w_rx = eval_value::<G>(&witnesses, &gu[1..].to_vec());
        let (prod_proof0, comm_y0) = LogDotProductProof::reduce_prover::<R>(
            &params.pc_params,
            &witnesses,
            &witness_blind,
            &gu[1..].to_vec(),
            blind_eval0,
            eval_w_rx,
            rng,
            &mut transcript,
        );
        let eval_at_zy_blind0 = (G::Fr::one() - &gu[0]) * &blind_eval0;

        let eq_proof0 = EqProof::prover(
            &params.pc_params.gen_1,
            final_x,
            final_blind_x,
            final_x,
            eval_at_zy_blind0,
            rng,
            &mut transcript,
        );

        let blind_eval1 = G::Fr::rand(rng);
        let eval_w_ry = eval_value::<G>(&witnesses, &gv[1..].to_vec());
        let (prod_proof1, comm_y1) = LogDotProductProof::reduce_prover::<R>(
            &params.pc_params,
            &witnesses,
            &witness_blind,
            &gv[1..].to_vec(),
            blind_eval1,
            eval_w_ry,
            rng,
            &mut transcript,
        );
        let eval_at_zy_blind1 = (G::Fr::one() - &gv[0]) * &blind_eval1;

        let eq_proof1 = EqProof::prover(
            &params.pc_params.gen_1,
            final_y,
            final_blind_y,
            final_y,
            eval_at_zy_blind1,
            rng,
            &mut transcript,
        );

        let proof = Self {
            proofs,
            comm_witness,
            comm_y0,
            prod_proof0,
            eq_proof0,
            comm_y1,
            prod_proof1,
            eq_proof1,
        };
        let output = circuit_evals[circuit_evals.len() - 1].clone();
        (proof, output)
    }

    pub fn verify(
        &self,
        params: &Parameters<G>,
        circuit: &Circuit,
        output: &Vec<G::Fr>,
        inputs: &Vec<G::Fr>,
    ) -> bool {
        let mut transcript = Transcript::new(b"libra - zk linear gkr");
        transcript.append_message(
            b"comm_witness",
            &math::to_bytes!(self.comm_witness).unwrap(),
        );

        let mut alpha = G::Fr::one();
        let mut beta = G::Fr::zero();
        let (result_u, gu) = eval_output::<G>(
            &output,
            circuit.layers[circuit.depth - 1].bit_size,
            &mut transcript,
        );
        let result_v = G::Fr::zero();
        let claim_blind = G::Fr::zero();
        let claim = alpha * &result_u + &(beta * &result_v);
        let mut comm_claim = poly_commit_vec::<G>(
            &params.pc_params.gen_1.generators,
            &vec![claim],
            &params.pc_params.gen_1.h,
            claim_blind,
        );

        let mut comm_x_final = comm_claim;
        let mut comm_y_final = comm_claim;
        let mut ru_vec = Vec::new();
        let mut rv_vec = Vec::new();
        let mut gu_vec = gu.clone();
        let mut gv_vec = gu.clone();
        assert_eq!(circuit.depth - 1, self.proofs.len());
        for (d, lproof) in self.proofs.iter().enumerate() {
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
                let r_i = random_bytes_to_fr::<G>(&buf);
                let comm_eval = proof1.comm_evals[i];
                transcript.append_message(
                    b"comm_claim_per_round",
                    &math::to_bytes!(comm_claim).unwrap(),
                );
                transcript.append_message(b"comm_eval", &math::to_bytes!(comm_eval).unwrap());
                let result = proof1.proofs[i].verify(
                    &params.sc_params,
                    comm_poly,
                    comm_eval,
                    comm_claim,
                    r_i,
                    3,
                    &mut transcript,
                );
                assert!(result);
                ru_vec.push(r_i);
                comm_claim = comm_eval;
            }
            transcript.append_message(b"comm_x", &math::to_bytes!(lproof.comm_x).unwrap());

            for i in 0..bit_size {
                let comm_poly = proof2.comm_polys[i];
                transcript.append_message(b"comm_poly", &math::to_bytes!(comm_poly).unwrap());
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"challenge_nextround", &mut buf);
                let r_i = random_bytes_to_fr::<G>(&buf);
                let comm_eval = proof2.comm_evals[i];
                transcript.append_message(
                    b"comm_claim_per_round",
                    &math::to_bytes!(comm_claim).unwrap(),
                );
                transcript.append_message(b"comm_eval", &math::to_bytes!(comm_eval).unwrap());
                let result = proof2.proofs[i].verify(
                    &params.sc_params,
                    comm_poly,
                    comm_eval,
                    comm_claim,
                    r_i,
                    3,
                    &mut transcript,
                );
                assert!(result);
                rv_vec.push(r_i);
                comm_claim = comm_eval;
            }
            transcript.append_message(b"comm_y", &math::to_bytes!(lproof.comm_y).unwrap());

            let result = lproof.prod_proof.verify(
                &params.sc_params.gen_1,
                lproof.comm_x,
                lproof.comm_y,
                lproof.comm_z,
                &mut transcript,
            );
            assert!(result);

            let (add_gate_eval, mult_gate_eval) = circuit.layers[circuit.depth - d - 1]
                .eval_operators::<G>(&gu_vec, &gv_vec, &ru_vec, &rv_vec, alpha, beta);
            let comm_final = ((lproof.comm_x + lproof.comm_y).mul(add_gate_eval)
                + &(lproof.comm_z.mul(mult_gate_eval)))
                .into_affine();
            let result = lproof.eq_proof.verify(
                &params.sc_params.gen_1,
                comm_final,
                comm_claim,
                &mut transcript,
            );
            assert!(result);

            gu_vec = ru_vec.clone();
            gv_vec = rv_vec.clone();

            if d < circuit.depth - 2 {
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"challenge_alpha", &mut buf);
                alpha = random_bytes_to_fr::<G>(&buf);
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"challenge_beta", &mut buf);
                beta = random_bytes_to_fr::<G>(&buf);
                comm_claim = (lproof.comm_x.mul(alpha) + &(lproof.comm_y.mul(beta))).into_affine();
            } else {
                comm_x_final = lproof.comm_x;
                comm_y_final = lproof.comm_y;
            }
        }

        let mut inputs = inputs.clone();
        inputs.extend(vec![
            G::Fr::zero();
            2usize.pow(circuit.layers[0].bit_size as u32 - 1)
                - inputs.len()
        ]);

        let rs = self.prod_proof0.reduce_verifier(
            &params.pc_params,
            &ru_vec[1..].to_vec(),
            &self.comm_witness,
            self.comm_y0,
            &mut transcript,
        );
        assert!(rs);

        let eval_input_tau = eval_value::<G>(&inputs, &ru_vec[1..].to_vec());
        let comm_input = poly_commit_vec::<G>(
            &params.pc_params.gen_1.generators,
            &vec![eval_input_tau],
            &params.pc_params.gen_1.h,
            G::Fr::zero(),
        );
        let comm_eval_z = (self.comm_y0.mul(G::Fr::one() - &ru_vec[0])
            + &(comm_input.mul(ru_vec[0])))
            .into_affine();

        let result = self.eq_proof0.verify(
            &params.pc_params.gen_1,
            comm_x_final,
            comm_eval_z,
            &mut transcript,
        );
        assert!(result);
        let rs = self.prod_proof1.reduce_verifier(
            &params.pc_params,
            &rv_vec[1..].to_vec(),
            &self.comm_witness,
            self.comm_y1,
            &mut transcript,
        );
        assert!(rs);

        let eval_input_tau = eval_value::<G>(&inputs, &rv_vec[1..].to_vec());
        let comm_input = poly_commit_vec::<G>(
            &params.pc_params.gen_1.generators,
            &vec![eval_input_tau],
            &params.pc_params.gen_1.h,
            G::Fr::zero(),
        );
        let comm_eval_z = (self.comm_y1.mul(G::Fr::one() - &rv_vec[0])
            + &(comm_input.mul(rv_vec[0])))
            .into_affine();

        let result = self.eq_proof1.verify(
            &params.pc_params.gen_1,
            comm_y_final,
            comm_eval_z,
            &mut transcript,
        );
        assert!(result);

        true
    }
}
