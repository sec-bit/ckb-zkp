use crate::libra::circuit::{Circuit, Gate};
use crate::libra::evaluate::{
    eval_eq, eval_fgu, eval_hg, eval_output, eval_value, random_bytes_to_fr,
};
use crate::libra::sumcheck::SumCheckProof;
use math::{bytes::ToBytes, Curve, One, Zero};
use merlin::Transcript;

pub struct LayerProof<G: Curve> {
    pub proof_phase_one: SumCheckProof<G>,
    pub proof_phase_two: SumCheckProof<G>,
}

pub struct LinearGKRProof<G: Curve> {
    pub proofs: Vec<LayerProof<G>>,
}

impl<G: Curve> LinearGKRProof<G> {
    pub fn prover(
        circuit: &Circuit,
        inputs: &Vec<G::Fr>,
        witnesses: &Vec<G::Fr>,
    ) -> (Self, Vec<G::Fr>) {
        let mut transcript = Transcript::new(b"libra - linear gkr");
        let circuit_evals = circuit.evaluate::<G>(inputs, witnesses).unwrap();
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
            let (proof_phase_one, ru) = SumCheckProof::phase_one_prover(
                &circuit_evals[d - 1],
                &(mul_hg_vec, add_hg_vec1, add_hg_vec2),
                uv_size,
                claim,
                &mut transcript,
            );
            let eval_ru = proof_phase_one.poly_value_at_r.clone();
            claim = eval_ru[0] * &eval_ru[1] + &(eval_ru[0] * &eval_ru[2]) + &eval_ru[3];
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
            let (proof_phase_two, rv) = SumCheckProof::phase_two_prover(
                &circuit_evals[d - 1],
                &(mul_hg_vec, add_hg_vec, fu),
                uv_size,
                claim,
                &mut transcript,
            );
            let eval_rv = proof_phase_two.poly_value_at_r.clone();
            // claim = eval_rv[1] * &eval_rv[0] * &fu + &(eval_rv[2] * &fu) + &(eval_rv[2] * &eval_rv[0]);
            let proof = LayerProof::<G> {
                proof_phase_one,
                proof_phase_two,
            };
            proofs.push(proof);
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
            }
        }
        let proof = Self { proofs };
        let output = circuit_evals[circuit_evals.len() - 1].clone();
        (proof, output)
    }

    pub fn verify(&self, circuit: &Circuit, output: &Vec<G::Fr>, input: &Vec<G::Fr>) -> bool {
        let mut transcript = Transcript::new(b"libra - linear gkr");
        let mut alpha = G::Fr::one();
        let mut beta = G::Fr::zero();
        let (mut result_u, _) = eval_output::<G>(
            &output,
            circuit.layers[circuit.depth - 1].bit_size,
            &mut transcript,
        );
        let mut result_v = G::Fr::zero();
        let mut eval_ru_x = G::Fr::zero();
        let mut eval_rv_y = G::Fr::zero();
        let mut ru_vec = Vec::new();
        let mut rv_vec = Vec::new();
        assert_eq!(circuit.depth - 1, self.proofs.len());
        for (d, lproof) in self.proofs.iter().enumerate() {
            let mut claim = alpha * &result_u + &(beta * &result_v);
            let (proof1, proof2) = (&lproof.proof_phase_one, &lproof.proof_phase_two);
            let bit_size = circuit.layers[circuit.depth - d - 2].bit_size;
            ru_vec = Vec::new();
            rv_vec = Vec::new();
            // let mut comm_claim = comm_claim;
            for i in 0..bit_size {
                let poly = &proof1.polys[i];
                assert_eq!(
                    poly.evaluate(G::Fr::zero()) + &poly.evaluate(G::Fr::one()),
                    claim
                );
                transcript.append_message(b"poly", &math::to_bytes!(poly).unwrap());
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"challenge_nextround", &mut buf);
                let r_u = random_bytes_to_fr::<G>(&buf);
                ru_vec.push(r_u);
                claim = poly.evaluate(r_u);
            }
            let eval_ru_final = proof1.poly_value_at_r.clone();
            transcript.append_message(b"claim_final", &math::to_bytes!(eval_ru_final).unwrap());
            let claim_final = eval_ru_final[0] * &eval_ru_final[1]
                + &(eval_ru_final[0] * &eval_ru_final[2])
                + &eval_ru_final[3];
            assert_eq!(claim, claim_final);
            for i in 0..bit_size {
                // let comm_eval = proof2.comm_evals[i];
                // let comm_poly = proof2.comm_polys[i];
                let poly = &proof2.polys[i];
                assert_eq!(
                    poly.evaluate(G::Fr::zero()) + &poly.evaluate(G::Fr::one()),
                    claim
                );
                transcript.append_message(b"poly", &math::to_bytes!(poly).unwrap());
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"challenge_nextround", &mut buf);
                let r_v = random_bytes_to_fr::<G>(&buf);
                rv_vec.push(r_v);
                claim = poly.evaluate(r_v);
            }
            let eval_rv_final = proof2.poly_value_at_r.clone();
            transcript.append_message(b"claim_final", &math::to_bytes!(eval_rv_final).unwrap());
            let claim_final = eval_rv_final[1] * &eval_rv_final[0] * &eval_ru_final[0]
                + &(eval_rv_final[2] * &eval_ru_final[0])
                + &(eval_rv_final[2] * &eval_rv_final[0]);
            assert_eq!(claim, claim_final);
            if d < circuit.depth - 2 {
                result_u = eval_ru_final[0];
                result_v = eval_rv_final[0];
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"challenge_alpha", &mut buf);
                alpha = random_bytes_to_fr::<G>(&buf);
                let mut buf = [0u8; 32];
                transcript.challenge_bytes(b"challenge_beta", &mut buf);
                beta = random_bytes_to_fr::<G>(&buf);
            } else {
                eval_ru_x = eval_ru_final[0];
                eval_rv_y = eval_rv_final[0];
            }
        }
        let eval_ru_input = eval_value::<G>(&input, &ru_vec);
        let eval_rv_input = eval_value::<G>(&input, &rv_vec);
        (eval_ru_x == eval_ru_input) && (eval_rv_y == eval_rv_input)
    }
}

pub fn initialize_phase_one<G: Curve>(
    gu: &Vec<G::Fr>,
    gv: &Vec<G::Fr>,
    gates: &Vec<Gate>,
    v_vec: &Vec<G::Fr>,
    bit_size: usize,
    alpha: G::Fr,
    beta: G::Fr,
) -> (Vec<G::Fr>, Vec<G::Fr>, Vec<G::Fr>) {
    let evals_gu_vec = eval_eq::<G>(&gu);
    let evals_gv_vec = eval_eq::<G>(&gv);

    let evals_g_vec = (0..evals_gu_vec.len())
        .map(|i| alpha * &evals_gu_vec[i] + &(beta * &evals_gv_vec[i]))
        .collect::<Vec<_>>();

    let (mul_hg_vec, add_hg_vec1, add_hg_vec2) = eval_hg::<G>(&evals_g_vec, v_vec, gates, bit_size);

    (mul_hg_vec, add_hg_vec1, add_hg_vec2)
}

pub fn initialize_phase_two<G: Curve>(
    gu: &Vec<G::Fr>,
    gv: &Vec<G::Fr>,
    ru: &Vec<G::Fr>,
    gates: &Vec<Gate>,
    v_vec: &Vec<G::Fr>,
    bit_size: usize,
    alpha: G::Fr,
    beta: G::Fr,
) -> (Vec<G::Fr>, Vec<G::Fr>, G::Fr) {
    let evals_gu_vec = eval_eq::<G>(&gu);
    let evals_gv_vec = eval_eq::<G>(&gv);
    let evals_ru_vec = eval_eq::<G>(&ru);
    assert_eq!(v_vec.len(), evals_ru_vec.len());
    let eval_ru: G::Fr = (0..v_vec.len()).map(|i| v_vec[i] * &evals_ru_vec[i]).sum();

    let evals_g_vec = (0..evals_gu_vec.len())
        .map(|i| alpha * &evals_gu_vec[i] + &(beta * &evals_gv_vec[i]))
        .collect::<Vec<_>>();

    let (mul_hg_vec, add_hg_vec) = eval_fgu::<G>(&evals_g_vec, &evals_ru_vec, gates, bit_size);
    (mul_hg_vec, add_hg_vec, eval_ru)
}
