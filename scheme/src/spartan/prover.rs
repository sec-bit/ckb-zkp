use crate::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable,
};
use crate::spartan::commitments::{packing_poly_commit, poly_commit_vec};
use crate::spartan::data_structure::{
    random_bytes_to_fr, AddrTimestamps, EncodeMemory, KnowledgeProductCommit,
    MultiCommitmentParameters, NizkParameters, PolyCommitmentParameters, ProdForMemoryChecking,
    ProductCircuit, R1CSEvalsParameters, R1CSSatisfiedParameters, SnarkParameters,
    SumCheckCommitmentParameters,
};
use crate::spartan::data_structure::{
    DotProductProof, EqProof, HashLayerProof, KnowledgeProductProof, KnowledgeProof,
    LayerProductCircuitProof, NIZKProof, ProductCircuitEvalProof, ProductLayerProof, ProductProof,
    R1CSEvalsProof, R1CSSatProof, SNARKProof, SumCheckEvalProof, SumCheckProof,
};
use crate::spartan::inner_product::bullet_inner_product_proof;
use crate::spartan::polynomial::{
    bound_poly_var_bot, combine_with_r, eval_eq, evaluate_matrix_vec, evaluate_matrix_vec_col,
    evaluate_mle,
};
use crate::spartan::r1cs::R1CSInstance;
use crate::spartan::spark::{
    circuit_eval_opt, equalize_length, evaluate_dot_product_circuit, evaluate_product_circuit,
};
use crate::{String, Vec};
use core::{
    cmp,
    ops::{Deref, Neg},
};
use math::fft::DensePolynomial as Polynomial;
use math::{
    bytes::ToBytes, log2, AffineCurve, Field, One, PairingEngine, ProjectiveCurve, UniformRand,
    Zero,
};
use merlin::Transcript;
use rand::Rng;

pub struct ProvingAssignment<E: PairingEngine> {
    pub num_constraints: usize,
    pub input_assignment: Vec<E::Fr>,
    pub aux_assignment: Vec<E::Fr>,
}

impl<E: PairingEngine> ConstraintSystem<E::Fr> for ProvingAssignment<E> {
    type Root = Self;

    #[inline]
    fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.aux_assignment.len();
        self.aux_assignment.push(f()?);
        Ok(Variable::new_unchecked(Index::Aux(index)))
    }

    #[inline]
    fn alloc_input<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.input_assignment.len();
        self.input_assignment.push(f()?);
        Ok(Variable::new_unchecked(Index::Input(index)))
    }

    #[inline]
    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, _: LA, _: LB, _: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
        LB: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
        LC: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
    {
        self.num_constraints += 1;
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }

    fn num_constraints(&self) -> usize {
        self.num_constraints
    }
}

pub fn create_nizk_proof<E, C, R>(
    params: &NizkParameters<E>,
    r1cs: &R1CSInstance<E>,
    circuit: C,
    rng: &mut R,
) -> Result<NIZKProof<E>, SynthesisError>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: Rng,
{
    let mut transcript = Transcript::new(b"Spartan NIZK proof");

    let (r1cs_sat_proof, (rx, ry)) = r1cs_satisfied_prover::<E, C, R>(
        &params.r1cs_satisfied_params,
        r1cs,
        circuit,
        rng,
        &mut transcript,
    )
    .unwrap();
    let proof = NIZKProof::<E> {
        r1cs_satisfied_proof: r1cs_sat_proof,
        r: (rx, ry),
    };
    Ok(proof)
}

pub fn create_snark_proof<E, C, R>(
    params: &SnarkParameters<E>,
    r1cs: &R1CSInstance<E>,
    circuit: C,
    encode: &EncodeMemory<E>,
    rng: &mut R,
) -> Result<SNARKProof<E>, SynthesisError>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: Rng,
{
    let mut transcript = Transcript::new(b"Spartan SNARK proof");

    let (r1cs_sat_proof, (rx, ry)) = r1cs_satisfied_prover::<E, C, R>(
        &params.r1cs_satisfied_params,
        r1cs,
        circuit,
        rng,
        &mut transcript,
    )
    .unwrap();

    let eval_a_r = evaluate_mle::<E>(&r1cs.a_matrix, &rx, &ry);
    let eval_b_r = evaluate_mle::<E>(&r1cs.b_matrix, &rx, &ry);
    let eval_c_r = evaluate_mle::<E>(&r1cs.c_matrix, &rx, &ry);
    transcript.append_message(b"Ar_claim", &math::to_bytes!(eval_a_r).unwrap());
    transcript.append_message(b"Br_claim", &math::to_bytes!(eval_b_r).unwrap());
    transcript.append_message(b"Cr_claim", &math::to_bytes!(eval_c_r).unwrap());
    let evals = (eval_a_r, eval_b_r, eval_c_r);
    let r1cs_evals_proof = sparse_poly_eval_proof::<E, R>(
        &params.r1cs_eval_params,
        (&rx, &ry),
        evals,
        encode,
        rng,
        &mut transcript,
    )
    .unwrap();

    let proof = SNARKProof::<E> {
        r1cs_satisfied_proof: r1cs_sat_proof,
        matrix_evals: evals,
        r1cs_evals_proof: r1cs_evals_proof,
    };
    Ok(proof)
}

pub fn r1cs_satisfied_prover<E, C, R>(
    params: &R1CSSatisfiedParameters<E>,
    r1cs: &R1CSInstance<E>,
    circuit: C,
    rng: &mut R,
    transcript: &mut Transcript,
) -> Result<(R1CSSatProof<E>, (Vec<E::Fr>, Vec<E::Fr>)), SynthesisError>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: Rng,
{
    let mut prover = ProvingAssignment::<E> {
        num_constraints: 0,
        input_assignment: vec![],
        aux_assignment: vec![],
    };
    prover.alloc_input(|| "", || Ok(E::Fr::one()))?;

    // Synthesize the circuit.
    circuit.generate_constraints(&mut prover)?;

    assert_eq!(
        r1cs.num_constraints,
        (2usize).pow(log2(prover.num_constraints))
    );
    prover.num_constraints = r1cs.num_constraints;

    let t = cmp::max(r1cs.num_aux, r1cs.num_inputs).next_power_of_two();
    prover
        .aux_assignment
        .extend(&vec![E::Fr::zero(); t - prover.aux_assignment.len()]);
    prover
        .input_assignment
        .extend(&vec![E::Fr::zero(); t - prover.input_assignment.len()]);
    // combine z
    let mut z = prover.aux_assignment.clone();
    z.extend(prover.input_assignment.clone());

    //1. PC.Commit(pp, ~w)
    let (commit_witness, witness_blinds) = packing_poly_commit::<E, R>(
        &params.pc_params.gen_n.generators,
        &prover.aux_assignment,
        &params.pc_params.gen_n.h,
        rng,
        true,
    )
    .unwrap();
    transcript.append_message(
        b"poly_commitment",
        &math::to_bytes!(commit_witness).unwrap(),
    );
    let n = r1cs.num_constraints;
    let num_rounds_x = log2(n) as usize;
    let num_rounds_y = log2(t) as usize + 1;
    // assert_eq!(num_rounds_x, num_rounds_y);
    //2. calculate τ
    let tau = (0..num_rounds_x)
        .map(|_i| {
            let mut buf = [0u8; 31];
            transcript.challenge_bytes(b"challenge_tau", &mut buf);
            random_bytes_to_fr::<E>(&buf)
        })
        .collect::<Vec<_>>();
    // calculate multilinear A(x), B(x), C(x), eq(x, τ)
    // g(x) = (A(x) * B(x) - C(x)) * eq(x, τ)
    let eq_tau_arr = eval_eq::<E>(&tau);
    let ma = evaluate_matrix_vec::<E>(r1cs.a_matrix.clone(), z.clone());
    let mb = evaluate_matrix_vec::<E>(r1cs.b_matrix.clone(), z.clone());
    let mc = evaluate_matrix_vec::<E>(r1cs.c_matrix.clone(), z.clone());
    //5. sumcheck #1: ex = G_τ(rx)
    let (proof_sc1, rx, polys_value_at_rx, blinds_eval1) = sum_check_proof_phase_one::<E, R>(
        num_rounds_x,
        &params.sc_params,
        E::Fr::zero(),
        &ma,
        &mb,
        &mc,
        &eq_tau_arr,
        rng,
        transcript,
    )
    .unwrap();
    //6. compute va, vb, vc with proofs
    let (v_a, v_b, v_c, eq_tau) = polys_value_at_rx;
    let prod = v_a * &v_b;

    let blind_a = E::Fr::rand(rng);
    let blind_b = E::Fr::rand(rng);
    let blind_c = E::Fr::rand(rng);
    let blind_prod_ab = E::Fr::rand(rng);

    let (vc_proof, vc_commit) =
        knowledge_proof::<E, R>(&params.sc_params.gen_1, v_c, blind_c, rng, transcript).unwrap();
    let (prod_proof, va_commit, vb_commit, prod_commit) = product_proof::<E, R>(
        &params.sc_params.gen_1,
        v_a,
        blind_a,
        v_b,
        blind_b,
        prod,
        blind_prod_ab,
        rng,
        transcript,
    )
    .unwrap();

    transcript.append_message(b"comm_Az_claim", &math::to_bytes!(va_commit).unwrap());
    transcript.append_message(b"comm_Bz_claim", &math::to_bytes!(vb_commit).unwrap());
    transcript.append_message(b"comm_Cz_claim", &math::to_bytes!(vc_commit).unwrap());
    transcript.append_message(
        b"comm_prod_Az_Bz_claims",
        &math::to_bytes!(prod_commit).unwrap(),
    );

    let knowledge_product_commit = KnowledgeProductCommit::<E> {
        va_commit,
        vb_commit,
        vc_commit,
        prod_commit,
    };
    let knowledge_product_proof = KnowledgeProductProof::<E> {
        knowledge_proof: vc_proof,
        product_proof: prod_proof,
    };
    // 7. ex ?= (va * vb - vc) * eq(rx, τ) with proof
    let blind_claim_sc1 = eq_tau * &(blind_prod_ab - &blind_c);
    let claim_sc1 = eq_tau * &(prod - &v_c);
    let sc1_eq_proof = eq_proof::<E, R>(
        &params.sc_params.gen_1,
        claim_sc1,
        blind_claim_sc1,
        claim_sc1,
        blinds_eval1,
        rng,
        transcript,
    )
    .unwrap();
    // sumcheck #2
    // 8. sample ra, rb, rc
    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"challenege_Az", &mut buf);
    let r_a = random_bytes_to_fr::<E>(&buf);

    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"challenege_Bz", &mut buf);
    let r_b = random_bytes_to_fr::<E>(&buf);

    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"challenege_Cz", &mut buf);
    let r_c = random_bytes_to_fr::<E>(&buf);
    // 9. Let T2 = ra * va + rb * vb + rc * vc
    let claim_phase2 = (v_a * &r_a) + &(v_b * &r_b) + &(v_c * &r_c);
    let claim_phase2_blind = (blind_a * &r_a) + &(blind_b * &r_b) + &(blind_c * &r_c);

    let evals_rx = eval_eq::<E>(&rx);
    let evals_a = evaluate_matrix_vec_col::<E>(r1cs.a_matrix.clone(), evals_rx.clone(), z.len());
    let evals_b = evaluate_matrix_vec_col::<E>(r1cs.b_matrix.clone(), evals_rx.clone(), z.len());
    let evals_c = evaluate_matrix_vec_col::<E>(r1cs.c_matrix.clone(), evals_rx.clone(), z.len());
    assert_eq!(evals_a.len(), evals_b.len());
    assert_eq!(evals_a.len(), evals_c.len());
    let evals = (0..evals_a.len())
        .map(|i| r_a * &evals_a[i] + &(r_b * &evals_b[i]) + &(r_c * &evals_c[i]))
        .collect::<Vec<E::Fr>>();
    //11. sumcheck #2
    let (proof_sc2, ry, polys_value_at_ry, blinds_eval2) = sum_check_proof_phase_two::<E, R>(
        num_rounds_y,
        &params.sc_params,
        claim_phase2,
        claim_phase2_blind,
        &evals,
        &z,
        rng,
        transcript,
    )
    .unwrap();

    let (vs, vz) = polys_value_at_ry;
    let claim_sc2 = vs * &vz;

    // 12. w(ry[1...])
    let eq_ry_arr = eval_eq::<E>(&ry[1..].to_vec());
    let eval_w_ry = (0..prover.aux_assignment.len())
        .map(|i| prover.aux_assignment[i] * &eq_ry_arr[i])
        .sum();
    let blind_eval = E::Fr::rand(rng);
    let (wproof, commit_ry) = inner_product_proof::<E, R>(
        &params.pc_params,
        &prover.aux_assignment,
        &witness_blinds,
        &ry[1..].to_vec(),
        blind_eval,
        eval_w_ry,
        rng,
        transcript,
    )
    .unwrap();
    let eval_at_zy_blind = (E::Fr::one() - &ry[0]) * &blind_eval;
    let eval_at_zy_blind_claim = eval_at_zy_blind * &vs;

    let sc2_eq_proof = eq_proof::<E, R>(
        &params.pc_params.gen_1,
        claim_sc2,
        eval_at_zy_blind_claim,
        claim_sc2,
        blinds_eval2,
        rng,
        transcript,
    )
    .unwrap();
    let proof = R1CSSatProof::<E> {
        commit_witness: commit_witness,
        proof_one: proof_sc1,
        proof_two: proof_sc2,
        w_ry: eval_w_ry,
        product_proof: wproof,
        knowledge_product_commit,
        knowledge_product_proof,
        sc1_eq_proof,
        sc2_eq_proof,
        commit_ry,
    };

    Ok((proof, (rx, ry)))
}

fn sum_check_proof_phase_one<E: PairingEngine, R: Rng>(
    num_rounds: usize,
    params: &SumCheckCommitmentParameters<E>,
    claim: E::Fr,
    poly_a: &Vec<E::Fr>,
    poly_b: &Vec<E::Fr>,
    poly_c: &Vec<E::Fr>,
    poly_eq: &Vec<E::Fr>,
    rng: &mut R,
    transcript: &mut Transcript,
) -> Result<
    (
        SumCheckProof<E>,
        Vec<E::Fr>,
        (E::Fr, E::Fr, E::Fr, E::Fr),
        E::Fr,
    ),
    SynthesisError,
> {
    let mut poly_a = poly_a.clone();
    let mut poly_b = poly_b.clone();
    let mut poly_c = poly_c.clone();
    let mut poly_eq = poly_eq.clone();
    assert_eq!(poly_a.len(), poly_b.len());
    assert_eq!(poly_b.len(), poly_c.len());
    assert_eq!(poly_c.len(), poly_eq.len());

    let mut blinds_poly = Vec::new();
    let mut blinds_evals = Vec::new();
    for _ in 0..num_rounds {
        blinds_poly.push(E::Fr::rand(rng));
        blinds_evals.push(E::Fr::rand(rng));
    }

    let mut blind_poly_eval = E::Fr::zero();

    let mut claim = claim;
    let mut commit_claim = poly_commit_vec::<E>(
        &params.gen_1.generators,
        &vec![claim],
        &params.gen_1.h,
        E::Fr::zero(),
    )
    .unwrap()
    .commit;

    let mut rx: Vec<E::Fr> = Vec::new();
    let mut comm_polys: Vec<E::G1Affine> = Vec::new();
    let mut comm_evals: Vec<E::G1Affine> = Vec::new();
    let mut proofs: Vec<SumCheckEvalProof<E>> = Vec::new();

    for i in 0..num_rounds {
        let size = poly_eq.len() / 2;
        // g_i(0) = eval_0
        let eval_0 = (0..size)
            .map(|j| poly_eq[j] * &(poly_a[j] * &poly_b[j] - &poly_c[j]))
            .sum();
        // g_i(1) = eval_1
        let eval_1 = claim - &eval_0;

        // g_i(2) = eval_2 = 2eval_1 + (1-2)eval_0;
        let poly_a_tmp = combine_with_r::<E>(&poly_a.to_vec(), E::Fr::from(2));
        let poly_b_tmp = combine_with_r::<E>(&poly_b.to_vec(), E::Fr::from(2));
        let poly_c_tmp = combine_with_r::<E>(&poly_c.to_vec(), E::Fr::from(2));
        let poly_eq_tmp = combine_with_r::<E>(&poly_eq.to_vec(), E::Fr::from(2));
        let eval_2: E::Fr = (0..size)
            .map(|j| poly_eq_tmp[j] * &(poly_a_tmp[j] * &poly_b_tmp[j] - &poly_c_tmp[j]))
            .sum();
        // g_i(3) = eval_3 = 3eval_1 + (1-3)eval_0;
        let poly_a_tmp = combine_with_r::<E>(&poly_a.to_vec(), E::Fr::from(3));
        let poly_b_tmp = combine_with_r::<E>(&poly_b.to_vec(), E::Fr::from(3));
        let poly_c_tmp = combine_with_r::<E>(&poly_c.to_vec(), E::Fr::from(3));
        let poly_eq_tmp = combine_with_r::<E>(&poly_eq.to_vec(), E::Fr::from(3));
        let eval_3: E::Fr = (0..size)
            .map(|j| poly_eq_tmp[j] * &(poly_a_tmp[j] * &poly_b_tmp[j] - &poly_c_tmp[j]))
            .sum();

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
        let poly = Polynomial::from_coefficients_vec(vec![d_coeff, c_coeff, b_coeff, a_coeff]);
        let commit_poly = poly_commit_vec::<E>(
            &params.gen_4.generators,
            &poly.deref().to_vec(),
            &params.gen_4.h,
            blinds_poly[i],
        )
        .unwrap()
        .commit;

        transcript.append_message(b"comm_poly", &math::to_bytes!(commit_poly).unwrap());

        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let r_i = random_bytes_to_fr::<E>(&buf);
        poly_a = combine_with_r::<E>(&poly_a.to_vec(), r_i);
        poly_b = combine_with_r::<E>(&poly_b.to_vec(), r_i);
        poly_c = combine_with_r::<E>(&poly_c.to_vec(), r_i);
        poly_eq = combine_with_r::<E>(&poly_eq.to_vec(), r_i);

        let eval_ri = poly.evaluate(r_i);
        let commit_eval = poly_commit_vec::<E>(
            &params.gen_1.generators,
            &vec![eval_ri],
            &params.gen_1.h,
            blinds_evals[i],
        )
        .unwrap()
        .commit;

        transcript.append_message(
            b"comm_claim_per_round",
            &math::to_bytes!(commit_claim).unwrap(),
        );
        transcript.append_message(b"comm_eval", &math::to_bytes!(commit_eval).unwrap());

        let mut blind_claim = E::Fr::zero();
        if i > 0 {
            blind_claim = blinds_evals[i - 1];
        }
        let proof = sum_check_eval_prover::<E, R>(
            &params.gen_1,
            &params.gen_4,
            &poly.deref().to_vec(),
            commit_poly,
            blinds_poly[i],
            claim,
            blind_claim,
            eval_ri,
            blinds_evals[i],
            4,
            r_i,
            rng,
            transcript,
        )
        .unwrap();

        rx.push(r_i);
        comm_polys.push(commit_poly);
        comm_evals.push(commit_eval);
        proofs.push(proof);

        commit_claim = commit_eval.clone();
        blind_poly_eval = blinds_evals[i];
        claim = eval_ri;
    }

    assert_eq!(poly_a.len(), 1);
    assert_eq!(poly_b.len(), 1);
    assert_eq!(poly_c.len(), 1);
    assert_eq!(poly_eq.len(), 1);
    let polys_value_at_rx = (poly_a[0], poly_b[0], poly_c[0], poly_eq[0]);
    let proof = SumCheckProof::<E> {
        comm_polys: comm_polys,
        comm_evals: comm_evals,
        proofs: proofs,
    };

    Ok((proof, rx, polys_value_at_rx, blind_poly_eval))
}

fn sum_check_proof_phase_two<E: PairingEngine, R: Rng>(
    num_rounds: usize,
    params: &SumCheckCommitmentParameters<E>,
    claim: E::Fr,
    blind_claim: E::Fr,
    poly_abc: &Vec<E::Fr>,
    poly_z: &Vec<E::Fr>,
    rng: &mut R,
    transcript: &mut Transcript,
) -> Result<(SumCheckProof<E>, Vec<E::Fr>, (E::Fr, E::Fr), E::Fr), SynthesisError> {
    let mut poly_abc = poly_abc.clone();
    let mut poly_z = poly_z.clone();
    assert_eq!(poly_abc.len(), poly_z.len());

    let mut blinds_poly = Vec::new();
    let mut blinds_evals = Vec::new();
    for _ in 0..num_rounds {
        blinds_poly.push(E::Fr::rand(rng));
        blinds_evals.push(E::Fr::rand(rng));
    }

    let mut claim = claim;
    let mut commit_claim = poly_commit_vec::<E>(
        &params.gen_1.generators,
        &vec![claim],
        &params.gen_1.h,
        blind_claim,
    )
    .unwrap()
    .commit;
    let mut blind_poly_eval = E::Fr::zero();
    let mut ry: Vec<E::Fr> = Vec::new();
    let mut comm_polys: Vec<E::G1Affine> = Vec::new();
    let mut comm_evals: Vec<E::G1Affine> = Vec::new();
    let mut proofs: Vec<SumCheckEvalProof<E>> = Vec::new();

    let mut size = poly_z.len();
    assert_eq!(size, (2usize).pow(num_rounds as u32));
    for i in 0..num_rounds {
        size /= 2;
        // g_i(0) = eval_0
        let eval_0: E::Fr = (0..size).map(|j| poly_z[j] * &poly_abc[j]).sum();
        // g_i(1) = eval_1
        let eval_1 = claim - &eval_0;

        // g_i(2) = eval_2 = 2eval_1 + (1-2)eval_0;
        let poly_abc_tmp = combine_with_r::<E>(&poly_abc, E::Fr::from(2));
        let poly_z_tmp = combine_with_r::<E>(&poly_z, E::Fr::from(2));
        let eval_2 = (0..size).map(|j| poly_abc_tmp[j] * &poly_z_tmp[j]).sum();

        // degree = 2
        // f(x) = ax^2 + bx + c
        // a = (eval_0 - 2eval_1 + eval_2)/2
        let a_coeff = (eval_0 - &eval_1.double() + &eval_2) * &E::Fr::from(2).inverse().unwrap();
        // c = eval_0
        let c_coeff = eval_0;
        // b = eval_1 - a - c
        let b_coeff = eval_1 - &a_coeff - &c_coeff;

        let poly = Polynomial::from_coefficients_vec(vec![c_coeff, b_coeff, a_coeff]);
        let commit_poly = poly_commit_vec::<E>(
            &params.gen_3.generators,
            &poly.deref().to_vec(),
            &params.gen_3.h,
            blinds_poly[i],
        )
        .unwrap()
        .commit;
        transcript.append_message(b"comm_poly", &math::to_bytes!(commit_poly).unwrap());

        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let r_j = random_bytes_to_fr::<E>(&buf);

        let eval_rj = poly.evaluate(r_j);
        let commit_eval = poly_commit_vec::<E>(
            &params.gen_1.generators,
            &vec![eval_rj],
            &params.gen_1.h,
            blinds_evals[i],
        )
        .unwrap()
        .commit;
        transcript.append_message(
            b"comm_claim_per_round",
            &math::to_bytes!(commit_claim).unwrap(),
        );
        transcript.append_message(b"comm_eval", &math::to_bytes!(commit_eval).unwrap());

        poly_abc = combine_with_r::<E>(&poly_abc, r_j);
        poly_z = combine_with_r::<E>(&poly_z, r_j);

        let mut blind_claim = blind_claim;
        if i > 0 {
            blind_claim = blinds_evals[i - 1];
        }
        let proof = sum_check_eval_prover::<E, R>(
            &params.gen_1,
            &params.gen_3,
            &poly.deref().to_vec(),
            commit_poly,
            blinds_poly[i],
            claim,
            blind_claim,
            eval_rj,
            blinds_evals[i],
            3,
            r_j,
            rng,
            transcript,
        )
        .unwrap();
        ry.push(r_j);
        comm_polys.push(commit_poly);
        comm_evals.push(commit_eval);
        proofs.push(proof);
        blind_poly_eval = blinds_evals[i];
        claim = eval_rj;
        commit_claim = commit_eval;
    }

    let polys_value_at_ry = (poly_abc[0], poly_z[0]);

    let proof = SumCheckProof::<E> {
        comm_polys: comm_polys,
        comm_evals: comm_evals,
        proofs: proofs,
    };

    Ok((proof, ry, polys_value_at_ry, blind_poly_eval))
}

fn sum_check_eval_prover<E: PairingEngine, R: Rng>(
    params_gen_1: &MultiCommitmentParameters<E>,
    params_gen_n: &MultiCommitmentParameters<E>,
    poly: &Vec<E::Fr>,
    poly_commit: E::G1Affine,
    blind_poly: E::Fr,
    claim: E::Fr,
    blind_claim: E::Fr,
    eval: E::Fr,
    blind_eval: E::Fr,
    size: usize,
    r: E::Fr,
    rng: &mut R,
    transcript: &mut Transcript,
) -> Result<SumCheckEvalProof<E>, SynthesisError> {
    let w = (0..2)
        .map(|_i| {
            let mut buf = [0u8; 31];
            transcript.challenge_bytes(b"combine_two_claims_to_one", &mut buf);
            random_bytes_to_fr::<E>(&buf)
        })
        .collect::<Vec<_>>();

    let mut polynomial = vec![E::Fr::zero(); size];
    for i in 0..poly.len() {
        polynomial[i] = poly[i];
    }
    // (degree = 4)
    // claim_value = w0 * claim + w1 * eval
    //             = w0 * [poly(0) + poly(1)] + w1 * poly(ri)
    //             = w0 * [(poly_0 + poly_1 * 0 + poly_2 * 0 + poly_3 * 0) + (poly_0 + poly_1 * 1 + poly_2 * 1 + poly_3 * 1)]
    //              + w1 *  (poly_0 + poly_1 * ri + poly_2 * ri^2 + poly_3 * ri^3)
    //             = (w0 * 2 + w1) * poly_0 + (w0 + w1 * ri) * poly_1 + (w0 + w1 * ri^2) * poly_2 + (w0 + w1 * ri^3) * poly_3
    // coeffs = [w0 * 2 + w1, w0 + w1 * ri, w0 + w1 * ri^2, w0 + w1 * ri^3]
    //
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
    for _ in 0..size {
        coeffs.push(w[0] + &(w[1] * &rc));
        rc *= &r;
    }
    coeffs[0] += &w[0];

    transcript.append_message(b"Cx", &math::to_bytes!(poly_commit).unwrap());

    let commit_claim_value: E::G1Affine = poly_commit_vec::<E>(
        &params_gen_1.generators,
        &vec![claim_value],
        &params_gen_1.h,
        blind,
    )
    .unwrap()
    .commit;
    transcript.append_message(b"Cy", &math::to_bytes!(commit_claim_value).unwrap());

    let mut d_vec = Vec::new();
    for _ in 0..size {
        d_vec.push(E::Fr::rand(rng));
    }

    let r_delta = E::Fr::rand(rng);
    let d_commit = poly_commit_vec::<E>(&params_gen_n.generators, &d_vec, &params_gen_n.h, r_delta)
        .unwrap()
        .commit;
    transcript.append_message(b"delta", &math::to_bytes!(d_commit).unwrap());
    // dot_cd[i] = coeffs[i] * d_vec[i]
    let r_beta = E::Fr::rand(rng);
    let dot_cd = (0..coeffs.len()).map(|i| coeffs[i] * &d_vec[i]).sum();
    let dot_cd_commit = poly_commit_vec::<E>(
        &params_gen_1.generators,
        &vec![dot_cd],
        &params_gen_1.h,
        r_beta,
    )
    .unwrap()
    .commit;
    transcript.append_message(b"beta", &math::to_bytes!(dot_cd_commit).unwrap());
    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"c", &mut buf);
    let c = random_bytes_to_fr::<E>(&buf);

    // z[i] = c * poly[i] + d_vec[i]
    let z = (0..size)
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

    Ok(proof)
}

fn knowledge_proof<E: PairingEngine, R: Rng>(
    params: &MultiCommitmentParameters<E>,
    claim: E::Fr,
    blind: E::Fr,
    rng: &mut R,
    transcript: &mut Transcript,
) -> Result<(KnowledgeProof<E>, E::G1Affine), SynthesisError> {
    let t1 = E::Fr::rand(rng);
    let t2 = E::Fr::rand(rng);

    let claim_commit = poly_commit_vec::<E>(&params.generators, &vec![claim], &params.h, blind)
        .unwrap()
        .commit;
    transcript.append_message(b"C", &math::to_bytes!(claim_commit).unwrap());

    let t_commit = poly_commit_vec::<E>(&params.generators, &vec![t1], &params.h, t2)
        .unwrap()
        .commit;
    transcript.append_message(b"alpha", &math::to_bytes!(t_commit).unwrap());

    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"c", &mut buf);
    let c = random_bytes_to_fr::<E>(&buf);

    let z1 = claim * &c + &t1;
    let z2 = blind * &c + &t2;

    let proof = KnowledgeProof::<E> {
        t_commit: t_commit,
        z1: z1,
        z2: z2,
    };

    Ok((proof, claim_commit))
}

fn product_proof<E: PairingEngine, R: Rng>(
    params: &MultiCommitmentParameters<E>,
    claim_a: E::Fr,
    blind_a: E::Fr,
    claim_b: E::Fr,
    blind_b: E::Fr,
    prod: E::Fr,
    blind_prod: E::Fr,
    rng: &mut R,
    transcript: &mut Transcript,
) -> Result<(ProductProof<E>, E::G1Affine, E::G1Affine, E::G1Affine), SynthesisError> {
    let b1 = E::Fr::rand(rng);
    let b2 = E::Fr::rand(rng);
    let b3 = E::Fr::rand(rng);
    let b4 = E::Fr::rand(rng);
    let b5 = E::Fr::rand(rng);

    let a_commit = poly_commit_vec::<E>(&params.generators, &vec![claim_a], &params.h, blind_a)
        .unwrap()
        .commit;
    transcript.append_message(b"X", &math::to_bytes!(a_commit).unwrap());

    let b_commit = poly_commit_vec::<E>(&params.generators, &vec![claim_b], &params.h, blind_b)
        .unwrap()
        .commit;
    transcript.append_message(b"Y", &math::to_bytes!(b_commit).unwrap());

    let prod_commit = poly_commit_vec::<E>(&params.generators, &vec![prod], &params.h, blind_prod)
        .unwrap()
        .commit;
    transcript.append_message(b"Z", &math::to_bytes!(prod_commit).unwrap());

    let commit_alpha = poly_commit_vec::<E>(&params.generators, &vec![b1], &params.h, b2)
        .unwrap()
        .commit;
    transcript.append_message(b"alpha", &math::to_bytes!(commit_alpha).unwrap());

    let commit_beta = poly_commit_vec::<E>(&params.generators, &vec![b3], &params.h, b4)
        .unwrap()
        .commit;
    transcript.append_message(b"beta", &math::to_bytes!(commit_beta).unwrap());

    let commit_delta = poly_commit_vec::<E>(&vec![a_commit], &vec![b3], &params.h, b5)
        .unwrap()
        .commit;
    transcript.append_message(b"delta", &math::to_bytes!(commit_delta).unwrap());

    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"c", &mut buf);
    let c = random_bytes_to_fr::<E>(&buf);

    let z1 = b1 + &(c * &claim_a);
    let z2 = b2 + &(c * &blind_a);
    let z3 = b3 + &(c * &claim_b);
    let z4 = b4 + &(c * &blind_b);
    let z5 = b5 + &(c * &(blind_prod - &(blind_a * &claim_b)));
    let z = [z1, z2, z3, z4, z5];

    let proof = ProductProof::<E> {
        commit_alpha,
        commit_beta,
        commit_delta,
        z: z.to_vec(),
    };
    Ok((proof, a_commit, b_commit, prod_commit))
}

fn eq_proof<E: PairingEngine, R: Rng>(
    params: &MultiCommitmentParameters<E>,
    claim1: E::Fr,
    blind1: E::Fr,
    claim2: E::Fr,
    blind2: E::Fr,
    rng: &mut R,
    transcript: &mut Transcript,
) -> Result<EqProof<E>, SynthesisError> {
    let r = E::Fr::rand(rng);

    let c1 = poly_commit_vec::<E>(&params.generators, &vec![claim1], &params.h, blind1)
        .unwrap()
        .commit;
    transcript.append_message(b"C1", &math::to_bytes!(c1).unwrap());

    let c2 = poly_commit_vec::<E>(&params.generators, &vec![claim2], &params.h, blind2)
        .unwrap()
        .commit;
    transcript.append_message(b"C2", &math::to_bytes!(c2).unwrap());

    let alpha = params.h.mul(r).into_affine();
    transcript.append_message(b"alpha", &math::to_bytes!(alpha).unwrap());

    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"c", &mut buf);
    let c = random_bytes_to_fr::<E>(&buf);

    let z = c * &(blind1 - &blind2) + &r;

    let proof = EqProof::<E> { alpha, z };

    Ok(proof)
}
fn inner_product_proof<E: PairingEngine, R: Rng>(
    params: &PolyCommitmentParameters<E>,
    poly: &Vec<E::Fr>,
    blind_poly: &Vec<E::Fr>,
    ry: &Vec<E::Fr>,
    ry_blind: E::Fr,
    eval: E::Fr,
    rng: &mut R,
    transcript: &mut Transcript,
) -> Result<(DotProductProof<E>, E::G1Affine), SynthesisError> {
    transcript.append_message(b"protocol-name", b"polynomial evaluation proof");

    let n = poly.len();
    let size = log2(n) as usize;
    assert_eq!(ry.len(), size);

    let l_size = (2usize).pow((size / 2) as u32);
    let r_size = (2usize).pow((size - size / 2) as u32);
    let mut blinds = blind_poly.clone();
    if blind_poly.len() == 0 {
        blinds = vec![E::Fr::zero(); l_size];
    }
    assert_eq!(l_size, blinds.len());

    let l_eq_ry = eval_eq::<E>(&(ry[0..size / 2].to_vec()));
    let r_eq_ry = eval_eq::<E>(&ry[size / 2..size].to_vec());

    let lz = (0..r_size)
        .map(|j| {
            (0..l_size)
                .map(|i| l_eq_ry[i] * &poly[i * r_size + j])
                .sum()
        })
        .collect::<Vec<E::Fr>>();

    let lz_blind: E::Fr = (0..l_size).map(|i| l_eq_ry[i] * &blinds[i]).sum();
    let d = E::Fr::rand(rng);
    let r_delta = E::Fr::rand(rng);
    let r_beta = E::Fr::rand(rng);
    let blind_vec = (0..log2(r_size))
        .map(|_i| {
            let v1 = E::Fr::rand(rng);
            let v2 = E::Fr::rand(rng);
            (v1, v2)
        })
        .collect::<Vec<(E::Fr, E::Fr)>>();

    let commit_lz = poly_commit_vec::<E>(
        &params.gen_n.generators,
        &lz.clone(),
        &params.gen_n.h,
        lz_blind,
    )
    .unwrap()
    .commit;
    transcript.append_message(b"Cx", &math::to_bytes!(commit_lz).unwrap());

    let commit_ry = poly_commit_vec::<E>(
        &params.gen_1.generators,
        &vec![eval],
        &params.gen_1.h,
        ry_blind,
    )
    .unwrap()
    .commit;
    transcript.append_message(b"Cy", &math::to_bytes!(commit_ry).unwrap());

    let blind_gamma = lz_blind + &ry_blind;
    let (proof, a, b, g, blind_fin) = bullet_inner_product_proof::<E>(
        &params.gen_n.generators.clone(),
        params.gen_1.generators[0],
        params.gen_n.h,
        &lz,
        &r_eq_ry,
        blind_gamma,
        &blind_vec,
        transcript,
    )
    .unwrap();

    let delta = poly_commit_vec::<E>(&[g].to_vec(), &vec![d], &params.gen_1.h, r_delta)
        .unwrap()
        .commit;
    transcript.append_message(b"delta", &math::to_bytes!(delta).unwrap());

    let beta = poly_commit_vec::<E>(&params.gen_1.generators, &vec![d], &params.gen_1.h, r_beta)
        .unwrap()
        .commit;
    transcript.append_message(b"beta", &math::to_bytes!(beta).unwrap());
    let mut buf = [0u8; 31];
    transcript.challenge_bytes(b"challenge_tau", &mut buf);
    let c = random_bytes_to_fr::<E>(&buf);
    let z1 = d + &(c * &(a * &b));
    let z2 = b * &(c * &blind_fin + &r_beta) + &r_delta;

    let proof = DotProductProof::<E> {
        inner_product_proof: proof,
        delta,
        beta,
        z1,
        z2,
    };
    Ok((proof, commit_ry))
}

fn sparse_poly_eval_proof<E, R>(
    params: &R1CSEvalsParameters<E>,
    r: (&Vec<E::Fr>, &Vec<E::Fr>),
    evals: (E::Fr, E::Fr, E::Fr),
    encode: &EncodeMemory<E>,
    rng: &mut R,
    transcript: &mut Transcript,
) -> Result<R1CSEvalsProof<E>, SynthesisError>
where
    E: PairingEngine,
    R: Rng,
{
    transcript.append_message(b"protocol-name", b"sparse polynomial evaluation proof");

    let (rx, ry) = r;
    let (eval_a_r, eval_b_r, eval_c_r) = evals;

    // memory_row = [eq(0, rx), eq(1, rx)...]
    // memory_col= [eq(0, ry), eq(1, ry)...]
    let (rows, cols) = equalize_length::<E>(rx, ry).unwrap();
    let mem_row = eval_eq::<E>(&rows);
    let mem_col = eval_eq::<E>(&cols);

    // e_row = [mem_row[addr[i]]]
    // e_col = [mem_col[addr[i]]]
    // commit(e_row + e_col)
    let e_row = (0..encode.row_addr_ts.addr_index.len())
        .map(|i| {
            (0..encode.row_addr_ts.addr_index[i].len())
                .map(|j| mem_row[encode.row_addr_ts.addr_index[i][j]])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let e_col = (0..encode.col_addr_ts.addr_index.len())
        .map(|i| {
            (0..encode.col_addr_ts.addr_index[i].len())
                .map(|j| mem_col[encode.col_addr_ts.addr_index[i][j]])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let mut e_list = Vec::new();
    for list in e_row.iter().chain(e_col.iter()).into_iter() {
        e_list.extend(list);
    }
    e_list.resize(e_list.len().next_power_of_two(), E::Fr::zero());

    let (derefs_commit, _) = packing_poly_commit::<E, R>(
        &params.derefs_params.gen_n.generators,
        &e_list,
        &params.derefs_params.gen_n.h,
        rng,
        false,
    )
    .unwrap();
    transcript.append_message(
        b"comm_poly_row_col_ops_val",
        &math::to_bytes!(derefs_commit).unwrap(),
    );
    // gamma1, gamma2
    let gamma = (0..2)
        .map(|_i| {
            let mut buf = [0u8; 31];
            transcript.challenge_bytes(b"challenge_gamma_hash", &mut buf);
            random_bytes_to_fr::<E>(&buf)
        })
        .collect::<Vec<_>>();
    // evals & circuit
    let (row_layer, col_layer) = circuit_eval_opt::<E>(
        encode,
        (gamma[0], gamma[1]),
        (&e_row, &e_col),
        (&mem_row, &mem_col),
    )
    .unwrap();
    let (prod_layer_proof, ops_rands, mem_rands) = product_layer_prover::<E>(
        encode,
        (&e_row, &e_col),
        (row_layer.prod, col_layer.prod),
        &vec![eval_a_r, eval_b_r, eval_c_r],
        transcript,
    )
    .unwrap();
    let hash_layer_proof = hash_layer_prover::<E, R>(
        params,
        encode,
        (&ops_rands, &mem_rands),
        (&e_row, &e_col, &e_list),
        rng,
        transcript,
    )
    .unwrap();

    let proof = R1CSEvalsProof::<E> {
        prod_layer_proof,
        hash_layer_proof,
        derefs_commit,
    };
    Ok(proof)
}

pub fn product_layer_prover<E: PairingEngine>(
    encode: &EncodeMemory<E>,
    e_list: (&Vec<Vec<E::Fr>>, &Vec<Vec<E::Fr>>),
    prod_list: (ProdForMemoryChecking<E>, ProdForMemoryChecking<E>),
    evals: &Vec<E::Fr>,
    transcript: &mut Transcript,
) -> Result<(ProductLayerProof<E>, Vec<E::Fr>, Vec<E::Fr>), SynthesisError> {
    transcript.append_message(b"protocol-name", b"Sparse polynomial product layer proof");

    let (e_row, e_col) = e_list;
    let (row_prod, col_prod) = prod_list;

    // check product
    let row_init = evaluate_product_circuit::<E>(&row_prod.init_prod).unwrap();
    let row_read_list = (0..row_prod.read_ts_prod_list.len())
        .map(|i| evaluate_product_circuit::<E>(&row_prod.read_ts_prod_list[i]).unwrap())
        .collect::<Vec<E::Fr>>();
    let row_read: E::Fr = (0..row_read_list.len()).map(|i| row_read_list[i]).product();
    let row_write_list = (0..row_prod.write_ts_prod_list.len())
        .map(|i| evaluate_product_circuit::<E>(&row_prod.write_ts_prod_list[i]).unwrap())
        .collect::<Vec<E::Fr>>();
    let row_write: E::Fr = (0..row_write_list.len())
        .map(|i| row_write_list[i])
        .product();
    let row_audit = evaluate_product_circuit::<E>(&row_prod.audit_ts_prod).unwrap();
    assert_eq!(row_init * &row_write, row_read * &row_audit);

    transcript.append_message(b"claim_row_eval_init", &math::to_bytes!(row_init).unwrap());
    transcript.append_message(
        b"claim_row_eval_read",
        &math::to_bytes!(row_read_list).unwrap(),
    );
    transcript.append_message(
        b"claim_row_eval_write",
        &math::to_bytes!(row_write_list).unwrap(),
    );
    transcript.append_message(
        b"claim_row_eval_audit",
        &math::to_bytes!(row_audit).unwrap(),
    );
    let col_init = evaluate_product_circuit::<E>(&col_prod.init_prod).unwrap();
    let col_read_list = (0..col_prod.read_ts_prod_list.len())
        .map(|i| evaluate_product_circuit::<E>(&col_prod.read_ts_prod_list[i]).unwrap())
        .collect::<Vec<E::Fr>>();
    let col_read: E::Fr = (0..col_read_list.len()).map(|i| col_read_list[i]).product();
    let col_write_list = (0..col_prod.write_ts_prod_list.len())
        .map(|i| evaluate_product_circuit::<E>(&col_prod.write_ts_prod_list[i]).unwrap())
        .collect::<Vec<E::Fr>>();
    let col_write: E::Fr = (0..col_write_list.len())
        .map(|i| col_write_list[i])
        .product();
    let col_audit = evaluate_product_circuit::<E>(&col_prod.audit_ts_prod).unwrap();
    assert_eq!(col_init * &col_write, col_read * &col_audit);

    transcript.append_message(b"claim_col_eval_init", &math::to_bytes!(col_init).unwrap());
    transcript.append_message(
        b"claim_col_eval_read",
        &math::to_bytes!(col_read_list).unwrap(),
    );
    transcript.append_message(
        b"claim_col_eval_write",
        &math::to_bytes!(col_write_list).unwrap(),
    );
    transcript.append_message(
        b"claim_col_eval_audit",
        &math::to_bytes!(col_audit).unwrap(),
    );
    assert_eq!(e_row.len(), evals.len());
    assert_eq!(e_row.len(), e_col.len());
    assert_eq!(e_row.len(), encode.val_list.len());

    // split (row, col, val) to (left, right)
    let mut dotp_circuit_left_list = Vec::new();
    let mut dotp_circuit_right_list = Vec::new();
    let mut eval_dotp_left_list = Vec::new();
    let mut eval_dotp_right_list = Vec::new();
    for i in 0..e_row.len() {
        let row = &e_row[i];
        let col = &e_col[i];
        let val = &encode.val_list[i];

        let idx = row.len() / 2;
        assert_eq!(col.len(), row.len());
        assert_eq!(val.len(), row.len());
        let (row_left, row_right) = (row[0..idx].to_vec(), row[idx..row.len()].to_vec());
        let (col_left, col_right) = (col[0..idx].to_vec(), col[idx..col.len()].to_vec());
        let (val_left, val_right) = (val[0..idx].to_vec(), val[idx..val.len()].to_vec());

        let eval_dotp_left: E::Fr = (0..row_left.len())
            .map(|i| row_left[i] * &col_left[i] * &val_left[i])
            .sum();
        let eval_dotp_right: E::Fr = (0..row_right.len())
            .map(|i| row_right[i] * &col_right[i] * &val_right[i])
            .sum();

        dotp_circuit_left_list.push((row_left, col_left, val_left));
        dotp_circuit_right_list.push((row_right, col_right, val_right));

        transcript.append_message(
            b"claim_eval_dotp_left",
            &math::to_bytes!(eval_dotp_left).unwrap(),
        );
        transcript.append_message(
            b"claim_eval_dotp_right",
            &math::to_bytes!(eval_dotp_right).unwrap(),
        );

        assert_eq!(eval_dotp_left + &eval_dotp_right, evals[i]);

        eval_dotp_left_list.push(eval_dotp_left);
        eval_dotp_right_list.push(eval_dotp_right);
    }

    let mut ops_prod_circuit_list = Vec::new();
    for ops in row_prod
        .read_ts_prod_list
        .iter()
        .chain(row_prod.write_ts_prod_list.iter())
        .chain(col_prod.read_ts_prod_list.iter())
        .chain(col_prod.write_ts_prod_list.iter())
        .into_iter()
    {
        ops_prod_circuit_list.push(ops.clone());
    }

    let mut dotp_circuit_list = Vec::new();
    dotp_circuit_list.push(dotp_circuit_left_list[0].clone());
    dotp_circuit_list.push(dotp_circuit_right_list[0].clone());
    dotp_circuit_list.push(dotp_circuit_left_list[1].clone());
    dotp_circuit_list.push(dotp_circuit_right_list[1].clone());
    dotp_circuit_list.push(dotp_circuit_left_list[2].clone());
    dotp_circuit_list.push(dotp_circuit_right_list[2].clone());

    let (proof_ops, ops_rands) =
        product_circuit_eval_prover::<E>(ops_prod_circuit_list, dotp_circuit_list, transcript)
            .unwrap();
    let mut mem_prod_circuit_list = Vec::new();
    mem_prod_circuit_list.push(row_prod.init_prod);
    mem_prod_circuit_list.push(row_prod.audit_ts_prod);
    mem_prod_circuit_list.push(col_prod.init_prod);
    mem_prod_circuit_list.push(col_prod.audit_ts_prod);

    let (proof_memory, mem_rands) =
        product_circuit_eval_prover::<E>(mem_prod_circuit_list, vec![], transcript).unwrap();

    let proof = ProductLayerProof::<E> {
        proof_memory,
        proof_ops,
        eval_dotp: (eval_dotp_left_list, eval_dotp_right_list),
        eval_row: (row_init, row_read_list, row_write_list, row_audit),
        eval_col: (col_init, col_read_list, col_write_list, col_audit),
    };

    Ok((proof, ops_rands, mem_rands))
}

pub fn product_circuit_eval_prover<E: PairingEngine>(
    prod_circuit_vec: Vec<ProductCircuit<E>>,
    dotp_circuit_vec: Vec<(Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>)>,
    transcript: &mut Transcript,
) -> Result<(ProductCircuitEvalProof<E>, Vec<E::Fr>), SynthesisError> {
    // hyrax
    assert!(prod_circuit_vec.len() > 0);

    let layer_num = prod_circuit_vec[0].left_vec.len();

    let mut claims_to_verify = (0..prod_circuit_vec.len())
        .map(|i| evaluate_product_circuit::<E>(&prod_circuit_vec[i]).unwrap())
        .collect::<Vec<E::Fr>>();
    let mut layers_proof = Vec::new();
    let mut rands = Vec::new();
    let mut final_claim_dotp: (Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>) =
        (Vec::new(), Vec::new(), Vec::new());

    for i in (0..layer_num).rev() {
        let mut poly_left_batched_par = Vec::new();
        let mut poly_right_batched_par = Vec::new();
        for prod_circuit in prod_circuit_vec.iter() {
            assert_eq!(
                prod_circuit.left_vec[i].len(),
                prod_circuit.right_vec[i].len()
            );
            poly_left_batched_par.push(prod_circuit.left_vec[i].clone());
            poly_right_batched_par.push(prod_circuit.right_vec[i].clone());
        }

        let poly_rand_par = eval_eq::<E>(&rands).to_vec();
        assert_eq!(poly_rand_par.len(), prod_circuit_vec[0].left_vec[i].len());
        assert_eq!(
            prod_circuit_vec[0].left_vec[i].len(),
            prod_circuit_vec[0].right_vec[i].len()
        );
        let poly_vec_par = (
            poly_left_batched_par,
            poly_right_batched_par,
            poly_rand_par.clone(),
        );
        let mut poly_row_batched_seq = Vec::new();
        let mut poly_col_batched_seq = Vec::new();
        let mut poly_val_batched_seq = Vec::new();
        if i == 0 && dotp_circuit_vec.len() > 0 {
            for dotp_circuit in dotp_circuit_vec.iter() {
                let (row, col, val) = dotp_circuit.clone();
                let sum = evaluate_dot_product_circuit::<E>(&row, &col, &val).unwrap();
                assert_eq!(poly_rand_par.len(), row.len());
                assert_eq!(poly_rand_par.len(), col.len());
                assert_eq!(poly_rand_par.len(), val.len());
                poly_row_batched_seq.push(row);
                poly_col_batched_seq.push(col);
                poly_val_batched_seq.push(val);

                claims_to_verify.push(sum);
            }
        }
        let poly_vec_seq = (
            poly_row_batched_seq,
            poly_col_batched_seq,
            poly_val_batched_seq,
        );

        let coeffs = (0..claims_to_verify.len())
            .map(|_i| {
                let mut buf = [0u8; 31];
                transcript.challenge_bytes(b"rand_coeffs_next_layer", &mut buf);
                random_bytes_to_fr::<E>(&buf)
            })
            .collect::<Vec<_>>();

        let claim: E::Fr = (0..coeffs.len())
            .map(|j| claims_to_verify[j] * &coeffs[j])
            .sum();
        let num_rounds = log2(poly_rand_par.len()) as usize;

        let (polys, rand_prod, claim_prod, claim_dotp) = sum_check_cubic_prover::<E>(
            num_rounds,
            claim,
            &poly_vec_par,
            &poly_vec_seq,
            &coeffs,
            transcript,
        )
        .unwrap();

        let (claim_prod_left, claim_prod_right, _) = claim_prod;
        for j in 0..claim_prod_left.len() {
            transcript.append_message(
                b"claim_prod_left",
                &math::to_bytes!(claim_prod_left[j]).unwrap(),
            );
            transcript.append_message(
                b"claim_prod_right",
                &math::to_bytes!(claim_prod_right[j]).unwrap(),
            );
        }

        if i == 0 && dotp_circuit_vec.len() > 0 {
            final_claim_dotp = claim_dotp.clone();
            let (claim_dotp_row, claim_dotp_col, claim_dotp_val) = claim_dotp;
            for i in 0..claim_dotp_row.len() {
                transcript.append_message(
                    b"claim_dotp_row",
                    &math::to_bytes!(claim_dotp_row[i]).unwrap(),
                );
                transcript.append_message(
                    b"claim_dotp_col",
                    &math::to_bytes!(claim_dotp_col[i]).unwrap(),
                );
                transcript.append_message(
                    b"claim_dotp_val",
                    &math::to_bytes!(claim_dotp_val[i]).unwrap(),
                );
            }
        }

        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"challenge_r_layer", &mut buf);
        let r_layer = random_bytes_to_fr::<E>(&buf);

        claims_to_verify = (0..claim_prod_left.len())
            .map(|j| claim_prod_left[j] + &(r_layer * &(claim_prod_right[j] - &claim_prod_left[j])))
            .collect::<Vec<E::Fr>>();

        rands = vec![r_layer];
        rands.extend(rand_prod);

        let proof = LayerProductCircuitProof::<E> {
            polys,
            claim_prod_left,
            claim_prod_right,
        };
        layers_proof.push(proof);
    }

    let proof = ProductCircuitEvalProof::<E> {
        layers_proof,
        claim_dotp: final_claim_dotp,
    };
    Ok((proof, rands))
}

pub fn sum_check_cubic_prover<E: PairingEngine>(
    num_rounds: usize,
    claim: E::Fr,
    poly_vec_par: &(Vec<Vec<E::Fr>>, Vec<Vec<E::Fr>>, Vec<E::Fr>),
    poly_vec_seq: &(Vec<Vec<E::Fr>>, Vec<Vec<E::Fr>>, Vec<Vec<E::Fr>>),
    coeffs: &Vec<E::Fr>,
    transcript: &mut Transcript,
) -> Result<
    (
        Vec<Polynomial<E::Fr>>,
        Vec<E::Fr>,
        (Vec<E::Fr>, Vec<E::Fr>, E::Fr),
        (Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>),
    ),
    SynthesisError,
> {
    let (mut poly_a_batched_par, mut poly_b_batched_par, mut poly_c_par) = poly_vec_par.clone();
    let (mut poly_a_batched_seq, mut poly_b_batched_seq, mut poly_c_batched_seq) =
        poly_vec_seq.clone();

    let mut claim_per_round = claim;
    let mut r = Vec::new();
    let mut cubic_polys = Vec::new();
    for _ in 0..num_rounds {
        let mut evals = Vec::new();

        assert_eq!(poly_a_batched_par.len(), poly_b_batched_par.len());
        for (poly_a_par, poly_b_par) in poly_a_batched_par.iter().zip(poly_b_batched_par.iter()) {
            let mut eval_0 = E::Fr::zero();
            let mut eval_2 = E::Fr::zero();
            let mut eval_3 = E::Fr::zero();

            assert_eq!(poly_a_par.len(), poly_b_par.len());
            assert_eq!(poly_a_par.len(), poly_c_par.len());

            let slen = poly_a_par.len() / 2;
            for i in 0..slen {
                eval_0 += &(poly_a_par[i] * &poly_b_par[i] * &poly_c_par[i]);

                let tmp_poly_a_par = poly_a_par[slen + i].double() - &poly_a_par[i];
                let tmp_poly_right_par = poly_b_par[slen + i].double() - &poly_b_par[i];
                let tmp_poly_rand_par = poly_c_par[slen + i].double() - &poly_c_par[i];
                eval_2 += &(tmp_poly_a_par * &tmp_poly_right_par * &tmp_poly_rand_par);

                let tmp_poly_a_par =
                    poly_a_par[slen + i].double() + &poly_a_par[slen + i] - &poly_a_par[i].double();
                let tmp_poly_right_par =
                    poly_b_par[slen + i].double() + &poly_b_par[slen + i] - &poly_b_par[i].double();
                let tmp_poly_rand_par =
                    poly_c_par[slen + i].double() + &poly_c_par[slen + i] - &poly_c_par[i].double();
                eval_3 += &(tmp_poly_a_par * &tmp_poly_right_par * &tmp_poly_rand_par);
            }
            evals.push((eval_0, eval_2, eval_3));
        }

        for ((poly_a_seq, poly_b_seq), poly_c_seq) in poly_a_batched_seq
            .iter()
            .zip(poly_b_batched_seq.iter())
            .zip(poly_c_batched_seq.iter())
        {
            let mut eval_0 = E::Fr::zero();
            let mut eval_2 = E::Fr::zero();
            let mut eval_3 = E::Fr::zero();

            assert_eq!(poly_a_seq.len(), poly_b_seq.len());
            assert_eq!(poly_a_seq.len(), poly_c_seq.len());

            let slen = poly_a_seq.len() / 2;
            for i in 0..slen {
                eval_0 += &(poly_a_seq[i] * &poly_b_seq[i] * &poly_c_seq[i]);

                let tmp_poly_a_par = poly_a_seq[slen + i].double() - &poly_a_seq[i];
                let tmp_poly_right_par = poly_b_seq[slen + i].double() - &poly_b_seq[i];
                let tmp_poly_rand_par = poly_c_seq[slen + i].double() - &poly_c_seq[i];
                eval_2 += &(tmp_poly_a_par * &tmp_poly_right_par * &tmp_poly_rand_par);

                let tmp_poly_a_par =
                    poly_a_seq[slen + i].double() + &poly_a_seq[slen + i] - &poly_a_seq[i].double();
                let tmp_poly_right_par =
                    poly_b_seq[slen + i].double() + &poly_b_seq[slen + i] - &poly_b_seq[i].double();
                let tmp_poly_rand_par =
                    poly_c_seq[slen + i].double() + &poly_c_seq[slen + i] - &poly_c_seq[i].double();
                eval_3 += &(tmp_poly_a_par * &tmp_poly_right_par * &tmp_poly_rand_par);
            }
            evals.push((eval_0, eval_2, eval_3));
        }
        assert_eq!(coeffs.len(), evals.len());
        let evals_sum_0: E::Fr = (0..coeffs.len()).map(|i| evals[i].0 * &coeffs[i]).sum();
        let evals_sum_1: E::Fr = claim_per_round - &evals_sum_0;
        let evals_sum_2: E::Fr = (0..coeffs.len()).map(|i| evals[i].1 * &coeffs[i]).sum();
        let evals_sum_3: E::Fr = (0..coeffs.len()).map(|i| evals[i].2 * &coeffs[i]).sum();
        // degree = 3
        // f(x) = ax^3 + bx^2 + cx + d
        // a = (-eval_0 + 3eval_1 - 3eval_2 + eval_3)/6
        let a_coeff = (evals_sum_0.neg() + &evals_sum_1.double() + &evals_sum_1
            - &evals_sum_2.double()
            - &evals_sum_2
            + &evals_sum_3)
            * &E::Fr::from(6).inverse().unwrap();
        // b = (2eval_0 - 5eval_1 + 4eval_2 - eval_3)/2
        let b_coeff = (evals_sum_0.double() - &(evals_sum_1.double().double()) - &evals_sum_1
            + &evals_sum_2.double().double()
            - &evals_sum_3)
            * &E::Fr::from(2).inverse().unwrap();
        // c = eval_1 - eval_0 - a - b
        let c_coeff = evals_sum_1 - &evals_sum_0 - &a_coeff - &b_coeff;
        // d = eval_0
        let d_coeff = evals_sum_0;

        // degree = 3
        let poly = Polynomial::from_coefficients_vec(vec![d_coeff, c_coeff, b_coeff, a_coeff]);
        transcript.append_message(b"comm_poly", &math::to_bytes!(poly.coeffs).unwrap());

        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        let r_j = random_bytes_to_fr::<E>(&buf);
        poly_c_par = combine_with_r::<E>(&poly_c_par.to_vec(), r_j);
        let mut poly_a_batched_par_tmp = Vec::new();
        for poly_a in poly_a_batched_par.iter() {
            let poly_a_tmp = combine_with_r::<E>(&poly_a.to_vec(), r_j);
            poly_a_batched_par_tmp.push(poly_a_tmp);
        }
        poly_a_batched_par = poly_a_batched_par_tmp.clone();

        let mut poly_b_batched_par_tmp = Vec::new();
        for poly_b in poly_b_batched_par.iter() {
            let poly_b_tmp = combine_with_r::<E>(&poly_b.to_vec(), r_j);
            poly_b_batched_par_tmp.push(poly_b_tmp);
        }
        poly_b_batched_par = poly_b_batched_par_tmp.clone();

        let mut poly_a_batched_seq_tmp = Vec::new();
        for poly_a in poly_a_batched_seq.iter() {
            let poly_a_tmp = combine_with_r::<E>(&poly_a.to_vec(), r_j);
            poly_a_batched_seq_tmp.push(poly_a_tmp);
        }
        poly_a_batched_seq = poly_a_batched_seq_tmp.clone();

        let mut poly_b_batched_seq_tmp = Vec::new();
        for poly_b in poly_b_batched_seq.iter() {
            let poly_b_tmp = combine_with_r::<E>(&poly_b.to_vec(), r_j);
            poly_b_batched_seq_tmp.push(poly_b_tmp);
        }
        poly_b_batched_seq = poly_b_batched_seq_tmp.clone();

        let mut poly_c_batched_seq_tmp = Vec::new();
        for poly_c in poly_c_batched_seq.iter() {
            let poly_c_tmp = combine_with_r::<E>(&poly_c.to_vec(), r_j);
            poly_c_batched_seq_tmp.push(poly_c_tmp);
        }
        poly_c_batched_seq = poly_c_batched_seq_tmp.clone();

        claim_per_round = poly.evaluate(r_j);

        r.push(r_j);
        cubic_polys.push(poly);
    }

    let poly_a_par_final = (0..poly_a_batched_par.len())
        .map(|i| poly_a_batched_par[i][0])
        .collect::<Vec<E::Fr>>();
    let poly_b_par_final = (0..poly_b_batched_par.len())
        .map(|i| poly_b_batched_par[i][0])
        .collect::<Vec<E::Fr>>();
    let claim_prod = (poly_a_par_final, poly_b_par_final, poly_c_par[0]);

    let poly_a_seq_final = (0..poly_a_batched_seq.len())
        .map(|i| poly_a_batched_seq[i][0])
        .collect::<Vec<E::Fr>>();
    let poly_b_seq_final = (0..poly_b_batched_seq.len())
        .map(|i| poly_b_batched_seq[i][0])
        .collect::<Vec<E::Fr>>();
    let poly_c_seq_final = (0..poly_c_batched_seq.len())
        .map(|i| poly_c_batched_seq[i][0])
        .collect::<Vec<E::Fr>>();
    let claim_dotp = (poly_a_seq_final, poly_b_seq_final, poly_c_seq_final);

    Ok((cubic_polys, r, claim_prod, claim_dotp))
}

pub fn hash_layer_prover<E: PairingEngine, R: Rng>(
    params: &R1CSEvalsParameters<E>,
    encode: &EncodeMemory<E>,
    rands: (&Vec<E::Fr>, &Vec<E::Fr>),
    e_list: (&Vec<Vec<E::Fr>>, &Vec<Vec<E::Fr>>, &Vec<E::Fr>),
    rng: &mut R,
    transcript: &mut Transcript,
) -> Result<HashLayerProof<E>, SynthesisError> {
    transcript.append_message(b"protocol-name", b"Sparse polynomial hash layer proof");

    let (ops_rands, mem_rands) = rands;
    let (e_row, e_col, e_comb_list) = e_list;

    let eq_ops_rands = eval_eq::<E>(ops_rands);
    let eval_row_ops_val = (0..e_row.len())
        .map(|i| {
            (0..e_row[i].len())
                .map(|j| e_row[i][j] * &eq_ops_rands[j])
                .sum()
        })
        .collect::<Vec<E::Fr>>();

    let eval_col_ops_val = (0..e_col.len())
        .map(|i| {
            (0..e_col[i].len())
                .map(|j| e_col[i][j] * &eq_ops_rands[j])
                .sum()
        })
        .collect::<Vec<E::Fr>>();

    let mut evals = eval_row_ops_val.clone();
    evals.extend(eval_col_ops_val.clone());
    evals.resize(evals.len().next_power_of_two(), E::Fr::zero());

    assert_eq!(
        log2(e_comb_list.len()) as usize,
        ops_rands.len() + log2(evals.len()) as usize
    );
    transcript.append_message(b"protocol-name", b"Derefs evaluation proof");
    transcript.append_message(b"evals_ops_val", &math::to_bytes!(evals).unwrap());

    let cs = (0..log2(evals.len()))
        .map(|_i| {
            let mut buf = [0u8; 31];
            transcript.challenge_bytes(b"challenge_combine_n_to_one", &mut buf);
            random_bytes_to_fr::<E>(&buf)
        })
        .collect::<Vec<_>>();
    let mut poly_evals = evals.clone();
    for i in (0..cs.len()).rev() {
        poly_evals = bound_poly_var_bot::<E>(&poly_evals, cs[i]);
    }
    assert_eq!(poly_evals.len(), 1);
    let claim_eval = poly_evals[0];
    let mut rs = cs.clone();
    rs.extend(ops_rands);

    transcript.append_message(b"joint_claim_eval", &math::to_bytes!(claim_eval).unwrap());
    let (proof_derefs, _) = inner_product_proof::<E, R>(
        &params.derefs_params,
        &e_comb_list,
        &vec![],
        &rs,
        E::Fr::zero(),
        claim_eval,
        rng,
        transcript,
    )
    .unwrap();
    let evals_derefs = (eval_row_ops_val, eval_col_ops_val);

    let (row_eval_addr_ops_list, row_eval_read_ts_list, row_eval_audit_ts_val) =
        pre_prover_for_timestamp::<E>(rands, &encode.row_addr_ts).unwrap();
    let (col_eval_addr_ops_list, col_eval_read_ts_list, col_eval_audit_ts_val) =
        pre_prover_for_timestamp::<E>(rands, &encode.col_addr_ts).unwrap();
    let eval_val_list = (0..encode.val_list.len())
        .map(|i| {
            (0..encode.val_list[i].len())
                .map(|j| encode.val_list[i][j] * &eq_ops_rands[j])
                .sum()
        })
        .collect::<Vec<E::Fr>>();

    let mut evals_ops: Vec<E::Fr> = Vec::new();
    evals_ops.extend(row_eval_addr_ops_list.clone());
    evals_ops.extend(row_eval_read_ts_list.clone());
    evals_ops.extend(col_eval_addr_ops_list.clone());
    evals_ops.extend(col_eval_read_ts_list.clone());
    evals_ops.extend(eval_val_list.clone());
    evals_ops.resize(evals_ops.len().next_power_of_two(), E::Fr::zero());
    transcript.append_message(b"claim_evals_ops", &math::to_bytes!(evals_ops).unwrap());

    let cs_ops = (0..log2(evals_ops.len()))
        .map(|_i| {
            let mut buf = [0u8; 31];
            transcript.challenge_bytes(b"challenge_combine_n_to_one", &mut buf);
            random_bytes_to_fr::<E>(&buf)
        })
        .collect::<Vec<_>>();
    let mut poly_evals_ops = evals_ops.clone();
    for i in (0..cs_ops.len()).rev() {
        poly_evals_ops = bound_poly_var_bot::<E>(&poly_evals_ops, cs_ops[i]);
    }
    assert_eq!(poly_evals_ops.len(), 1);
    let claim_eval_ops = poly_evals_ops[0];
    let mut rs_ops = cs_ops.clone();
    rs_ops.extend(ops_rands);

    transcript.append_message(
        b"joint_claim_eval_ops",
        &math::to_bytes!(claim_eval_ops).unwrap(),
    );
    let (proof_ops, _) = inner_product_proof::<E, R>(
        &params.ops_params,
        &encode.ops_list,
        &vec![],
        &rs_ops,
        E::Fr::zero(),
        claim_eval_ops,
        rng,
        transcript,
    )
    .unwrap();

    let evals_mem = vec![row_eval_audit_ts_val, col_eval_audit_ts_val];
    transcript.append_message(b"claim_evals_mem", &math::to_bytes!(evals_mem).unwrap());
    let cs_mem = (0..log2(evals_mem.len()))
        .map(|_i| {
            let mut buf = [0u8; 31];
            transcript.challenge_bytes(b"challenge_combine_two_to_one", &mut buf);
            random_bytes_to_fr::<E>(&buf)
        })
        .collect::<Vec<_>>();

    let mut poly_evals_mem = evals_mem.clone();
    for i in (0..cs_mem.len()).rev() {
        poly_evals_mem = bound_poly_var_bot::<E>(&poly_evals_mem, cs_mem[i]);
    }
    assert_eq!(poly_evals_mem.len(), 1);
    let claim_eval_mem = poly_evals_mem[0];
    let mut rs_mem = cs_mem.clone();
    rs_mem.extend(mem_rands);

    transcript.append_message(
        b"joint_claim_eval_mem",
        &math::to_bytes!(claim_eval_mem).unwrap(),
    );
    let (proof_mem, _) = inner_product_proof::<E, R>(
        &params.mem_params,
        &encode.mem_list,
        &vec![],
        &rs_mem,
        E::Fr::zero(),
        claim_eval_mem,
        rng,
        transcript,
    )
    .unwrap();

    let proof = HashLayerProof::<E> {
        proof_derefs,
        proof_ops,
        proof_mem,
        evals_derefs,
        evals_row: (
            row_eval_addr_ops_list,
            row_eval_read_ts_list,
            row_eval_audit_ts_val,
        ),
        evals_col: (
            col_eval_addr_ops_list,
            col_eval_read_ts_list,
            col_eval_audit_ts_val,
        ),
        evals_val: eval_val_list,
    };

    Ok(proof)
}

pub fn pre_prover_for_timestamp<E: PairingEngine>(
    rands: (&Vec<E::Fr>, &Vec<E::Fr>),
    ts: &AddrTimestamps<E>,
) -> Result<(Vec<E::Fr>, Vec<E::Fr>, E::Fr), SynthesisError> {
    let (ops_rands, mem_rands) = rands;
    let eq_ops_rands = eval_eq::<E>(ops_rands);
    let eq_mem_rands = eval_eq::<E>(mem_rands);

    let eval_addr_ops_list = (0..ts.addrs.len())
        .map(|i| {
            (0..ts.addrs[i].len())
                .map(|j| ts.addrs[i][j] * &eq_ops_rands[j])
                .sum()
        })
        .collect::<Vec<E::Fr>>();

    let eval_read_ts_list = (0..ts.read_ts_list.len())
        .map(|i| {
            (0..ts.read_ts_list[i].len())
                .map(|j| ts.read_ts_list[i][j] * &eq_ops_rands[j])
                .sum()
        })
        .collect::<Vec<E::Fr>>();

    let eval_audit_ts_val: E::Fr = (0..ts.audit_ts.len())
        .map(|j| ts.audit_ts[j] * &eq_mem_rands[j])
        .sum();

    Ok((eval_addr_ops_list, eval_read_ts_list, eval_audit_ts_val))
}
