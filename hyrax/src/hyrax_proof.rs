use ark_ff::{to_bytes, One, UniformRand, Zero};
use ark_serialize::*;
use merlin::Transcript;
use rand::Rng;
use zkp_curve::{AffineCurve, Curve, ProjectiveCurve};

use crate::circuit::Circuit;
use crate::commitment::{EqProof, LogDotProductProof};
use crate::evaluate::{
    eval_outputs, eval_value, packing_poly_commit, poly_commit_vec, random_bytes_to_fr,
};
use crate::params::Parameters;
use crate::zk_sumcheck_proof::ZkSumcheckProof;
use crate::Vec;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct HyraxProof<G: Curve> {
    pub comm_witness: Vec<G::Affine>,
    pub proofs: Vec<ZkSumcheckProof<G>>,
    pub prod_proof0: LogDotProductProof<G>,
    pub comm_y0: G::Affine,
    pub eq_proof0: EqProof<G>,
    pub prod_proof1: LogDotProductProof<G>,
    pub comm_y1: G::Affine,
    pub eq_proof1: EqProof<G>,
}

impl<G: Curve> HyraxProof<G> {
    pub fn prover<R: Rng>(
        params: &Parameters<G>,
        witnesses: &Vec<Vec<G::Fr>>,
        inputs: &Vec<Vec<G::Fr>>,
        circuit: &Circuit,
        n: usize,
        rng: &mut R,
    ) -> (Self, Vec<Vec<G::Fr>>) {
        let mut transcript = Transcript::new(b"hyrax - linear gkr");
        circuit.insert_transcript(&mut transcript);

        let mut circuit_evals = Vec::new();
        let mut outputs = Vec::new();
        for i in 0..n {
            transcript.append_message(b"input_i", &to_bytes!(inputs[i]).unwrap());
            let circuit_eval = circuit.evaluate::<G>(&inputs[i], &witnesses[i]).unwrap();
            outputs.push(circuit_eval[0].clone());
            circuit_evals.push(circuit_eval.clone());
            transcript.append_message(b"output_i", &to_bytes!(circuit_eval[0]).unwrap());
        }

        assert_eq!(n.next_power_of_two(), n);
        assert!(n > 0);
        //1. PC.Commit(pp, ~w)
        let mut witness_vec = Vec::new();
        for i in 0..n {
            let witness = witnesses[i].clone();
            witness_vec.extend(witness);
            let wl = witnesses[i].len();
            witness_vec.extend(vec![G::Fr::zero(); wl.next_power_of_two() - wl]);
        }
        let (comm_witness, witness_blind) = packing_poly_commit::<G, R>(
            &params.pc_params.gen_n.generators,
            &witness_vec,
            &params.pc_params.gen_n.h,
            rng,
            true,
        );
        transcript.append_message(b"comm_witness", &to_bytes!(comm_witness).unwrap());

        let (result_u, mut q_aside_vec, mut ql_vec) = eval_outputs::<G>(&outputs, &mut transcript);
        let mut qr_vec = ql_vec.clone();
        let mut u0 = G::Fr::one();
        let mut u1 = G::Fr::zero();
        let mut rc0 = G::Fr::zero();
        let comm_a = poly_commit_vec::<G>(
            &params.sc_params.gen_1.generators,
            &vec![result_u],
            &params.sc_params.gen_1.h,
            G::Fr::zero(),
        );
        transcript.append_message(b"comm_claim_a0", &to_bytes!(comm_a).unwrap());

        let mut comm_claim = comm_a;
        let mut claim = result_u;
        let mut proofs = Vec::new();
        let mut x = G::Fr::zero();
        let mut y = G::Fr::zero();
        let mut rx = G::Fr::zero();
        let mut ry = G::Fr::zero();
        for d in 0..circuit.depth - 1 {
            let next_gate_num = circuit.layers[circuit.depth - d - 2].gates_count;
            let ng = next_gate_num.next_power_of_two();
            let mut layer_circuit_evals = (0..next_gate_num)
                .map(|i| {
                    let mut evals = (0..circuit_evals.len())
                        .map(|t| circuit_evals[t][d + 1][i])
                        .collect::<Vec<_>>();
                    evals.extend(vec![G::Fr::zero(); n - circuit_evals.len()]);
                    evals
                })
                .collect::<Vec<_>>();
            let tmp_evals = (next_gate_num..ng)
                .map(|_| vec![G::Fr::zero(); n])
                .collect::<Vec<_>>();
            layer_circuit_evals.extend(tmp_evals);

            let (proof, q_aside_vec_tmp, ql_vec_tmp, qr_vec_tmp, eval_vec, blind_vec) =
                ZkSumcheckProof::prover::<R>(
                    &params.sc_params,
                    claim,
                    comm_claim,
                    rc0,
                    (u0, u1),
                    (&q_aside_vec, &ql_vec, &qr_vec),
                    &circuit.layers[circuit.depth - d - 1].gates,
                    &layer_circuit_evals,
                    n,
                    ng,
                    rng,
                    &mut transcript,
                );

            q_aside_vec = q_aside_vec_tmp.clone();
            ql_vec = ql_vec_tmp.clone();
            qr_vec = qr_vec_tmp.clone();

            x = eval_vec[0];
            y = eval_vec[1];
            rx = blind_vec[0];
            ry = blind_vec[1];

            if d < circuit.depth - 2 {
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"u0", &mut buf);
                u0 = random_bytes_to_fr::<G>(&buf);
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"u1", &mut buf);
                u1 = random_bytes_to_fr::<G>(&buf);
                comm_claim = (proof.comm_x.mul(u0) + &proof.comm_y.mul(u1)).into_affine();
                rc0 = rx * &u0 + &(ry * &u1);
                claim = x * &u0 + &(y * &u1);
                transcript.append_message(b"comm_a_i", &to_bytes!(comm_claim).unwrap());
            }
            proofs.push(proof);
        }

        let mut rl_q_vec = q_aside_vec.clone();
        rl_q_vec.extend(ql_vec[1..ql_vec.len()].to_vec());
        let blind_eval0 = G::Fr::rand(rng);
        let eval_w_rl = eval_value::<G>(&witness_vec, &rl_q_vec);
        let (prod_proof0, comm_y0) = LogDotProductProof::reduce_prover::<R>(
            &params.pc_params,
            &witness_vec,
            &witness_blind,
            &rl_q_vec,
            blind_eval0,
            eval_w_rl,
            rng,
            &mut transcript,
        );
        let eval_at_zy_blind0 = (G::Fr::one() - &ql_vec[0]) * &blind_eval0;

        let eq_proof0 = EqProof::prover(
            &params.pc_params.gen_1,
            x,
            rx,
            x,
            eval_at_zy_blind0,
            rng,
            &mut transcript,
        );

        let mut rr_q_vec = q_aside_vec.clone();
        rr_q_vec.extend(qr_vec[1..qr_vec.len()].to_vec());
        let blind_eval1 = G::Fr::rand(rng);
        let eval_w_rr = eval_value::<G>(&witness_vec, &rr_q_vec);
        let (prod_proof1, comm_y1) = LogDotProductProof::reduce_prover::<R>(
            &params.pc_params,
            &witness_vec,
            &witness_blind,
            &rr_q_vec,
            blind_eval1,
            eval_w_rr,
            rng,
            &mut transcript,
        );
        let eval_at_zy_blind1 = (G::Fr::one() - &qr_vec[0]) * &blind_eval1;

        let eq_proof1 = EqProof::prover(
            &params.pc_params.gen_1,
            y,
            ry,
            y,
            eval_at_zy_blind1,
            rng,
            &mut transcript,
        );
        let proof = Self {
            comm_witness,
            proofs,
            prod_proof0,
            comm_y0,
            eq_proof0,
            prod_proof1,
            comm_y1,
            eq_proof1,
        };

        (proof, outputs)
    }

    pub fn verify(
        &self,
        params: &Parameters<G>,
        outputs: &Vec<Vec<G::Fr>>,
        inputs: &Vec<Vec<G::Fr>>,
        circuit: &Circuit,
    ) -> bool {
        let mut transcript = Transcript::new(b"hyrax - linear gkr");
        circuit.insert_transcript(&mut transcript);
        
        let n = outputs.len();
        assert_eq!(n.next_power_of_two(), n);
        assert!(n > 0);

        for i in 0..n {
            transcript.append_message(b"input_i", &to_bytes!(inputs[i]).unwrap());
            transcript.append_message(b"output_i", &to_bytes!(outputs[i]).unwrap());
        }

        transcript.append_message(b"comm_witness", &to_bytes!(self.comm_witness).unwrap());

        let (result_u, mut q_aside_vec, mut ql_vec) = eval_outputs::<G>(&outputs, &mut transcript);
        let mut qr_vec = ql_vec.clone();
        let mut comm_a = poly_commit_vec::<G>(
            &params.sc_params.gen_1.generators,
            &vec![result_u],
            &params.sc_params.gen_1.h,
            G::Fr::zero(),
        );
        transcript.append_message(b"comm_claim_a0", &to_bytes!(comm_a).unwrap());

        let mut comm_x = comm_a;
        let mut comm_y = comm_a;
        let mut u0 = G::Fr::one();
        let mut u1 = G::Fr::zero();
        for d in 0..circuit.depth - 1 {
            let next_gate_num = circuit.layers[circuit.depth - d - 2].gates_count;
            let ng = next_gate_num.next_power_of_two();
            let (comm_x_tmp, comm_y_tmp, q_aside_vec_tmp, ql_vec_tmp, qr_vec_tmp) = self.proofs[d]
                .verify(
                    &params.sc_params,
                    comm_a,
                    (u0, u1),
                    (&q_aside_vec, &ql_vec, &qr_vec),
                    &circuit.layers[circuit.depth - d - 1].gates,
                    n,
                    ng,
                    &mut transcript,
                );

            comm_x = comm_x_tmp;
            comm_y = comm_y_tmp;
            q_aside_vec = q_aside_vec_tmp;
            ql_vec = ql_vec_tmp;
            qr_vec = qr_vec_tmp;

            if d < circuit.depth - 2 {
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"u0", &mut buf);
                u0 = random_bytes_to_fr::<G>(&buf);
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"u1", &mut buf);
                u1 = random_bytes_to_fr::<G>(&buf);
                comm_a = (comm_x.mul(u0) + &comm_y.mul(u1)).into_affine();
                transcript.append_message(b"comm_a_i", &to_bytes!(comm_a).unwrap());
            }
        }

        let mut input_vec = Vec::new();
        for i in 0..n {
            let input = inputs[i].clone();
            input_vec.extend(input);
            let al = inputs[i].len();
            input_vec.extend(vec![G::Fr::zero(); al.next_power_of_two() - al]);
        }

        let mut rl_q_vec = q_aside_vec.clone();
        rl_q_vec.extend(ql_vec[1..ql_vec.len()].to_vec());
        let rs = self.prod_proof0.reduce_verifier(
            &params.pc_params,
            &rl_q_vec,
            &self.comm_witness,
            self.comm_y0,
            &mut transcript,
        );
        assert!(rs);

        let eval_input_tau = eval_value::<G>(&input_vec, &rl_q_vec);
        let comm_input = poly_commit_vec::<G>(
            &params.pc_params.gen_1.generators,
            &vec![eval_input_tau],
            &params.pc_params.gen_1.h,
            G::Fr::zero(),
        );
        let comm_eval_z = (self.comm_y0.mul(G::Fr::one() - &ql_vec[0])
            + &(comm_input.mul(ql_vec[0])))
            .into_affine();

        let result = self.eq_proof0.verify(
            &params.pc_params.gen_1,
            comm_x,
            comm_eval_z,
            &mut transcript,
        );
        assert!(result);

        let mut rr_q_vec = q_aside_vec.clone();
        rr_q_vec.extend(qr_vec[1..qr_vec.len()].to_vec());
        let rs = self.prod_proof1.reduce_verifier(
            &params.pc_params,
            &rr_q_vec,
            &self.comm_witness,
            self.comm_y1,
            &mut transcript,
        );
        assert!(rs);

        let eval_input_tau = eval_value::<G>(&input_vec, &rr_q_vec);
        let comm_input = poly_commit_vec::<G>(
            &params.pc_params.gen_1.generators,
            &vec![eval_input_tau],
            &params.pc_params.gen_1.h,
            G::Fr::zero(),
        );
        let comm_eval_z = (self.comm_y1.mul(G::Fr::one() - &qr_vec[0])
            + &(comm_input.mul(qr_vec[0])))
            .into_affine();

        let result = self.eq_proof1.verify(
            &params.pc_params.gen_1,
            comm_y,
            comm_eval_z,
            &mut transcript,
        );
        assert!(result);

        true
    }
}
