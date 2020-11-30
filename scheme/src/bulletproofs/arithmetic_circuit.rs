#![allow(non_snake_case)]
use core::cmp;
use math::{AffineCurve, Curve, Field, One, ProjectiveCurve, ToBytes, UniformRand, Zero};
use merlin::Transcript;
use rand::Rng;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;

#[cfg(feature = "std")]
use std::collections::BTreeMap;

use crate::{String, Vec};

use crate::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable,
};

use super::{
    hadamard_product, inner_product, inner_product_proof, push_constraints, quick_multiexp,
    random_bytes_to_fr, vector_map_product, vector_matrix_product, vector_matrix_product_t,
    vector_product, VecPoly5,
};

// use rayon::prelude::*; // TODO: use rayon to accelerate

pub struct ProvingAssignment<F: Field> {
    // Constraints
    pub(crate) at: Vec<Vec<(F, Index)>>,
    pub(crate) bt: Vec<Vec<(F, Index)>>,
    pub(crate) ct: Vec<Vec<(F, Index)>>,

    // Assignments of variables
    pub(crate) input_assignment: Vec<F>,
    pub(crate) aux_assignment: Vec<F>,
}

impl<F: Field> ConstraintSystem<F> for ProvingAssignment<F> {
    type Root = Self;

    #[inline]
    fn alloc<FN, A, AR>(&mut self, _: A, f: FN) -> Result<Variable, SynthesisError>
    where
        FN: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.aux_assignment.len();
        self.aux_assignment.push(f()?);
        Ok(Variable::new_unchecked(Index::Aux(index)))
    }

    #[inline]
    fn alloc_input<FN, A, AR>(&mut self, _: A, f: FN) -> Result<Variable, SynthesisError>
    where
        FN: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.input_assignment.len();
        self.input_assignment.push(f()?);
        Ok(Variable::new_unchecked(Index::Input(index)))
    }

    #[inline]
    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    {
        let num_constraints = self.num_constraints();

        self.at.push(Vec::new());
        self.bt.push(Vec::new());
        self.ct.push(Vec::new());

        push_constraints(a(LinearCombination::zero()), &mut self.at, num_constraints);

        push_constraints(b(LinearCombination::zero()), &mut self.bt, num_constraints);

        push_constraints(c(LinearCombination::zero()), &mut self.ct, num_constraints);
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
        self.at.len()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Generators<G: Curve> {
    g_vec_N: Vec<G::Affine>,
    h_vec_N: Vec<G::Affine>,
    g: G::Affine,
    h: G::Affine,
    u: G::Affine,
    n: usize,
    N: usize,
    k: usize,
    n_w: usize,
}

#[derive(Serialize, Deserialize)]
pub struct R1csCircuit<G: Curve> {
    pub CL: Vec<Vec<G::Fr>>,
    pub CR: Vec<Vec<G::Fr>>,
    pub CO: Vec<Vec<G::Fr>>,
    pub CL_T: BTreeMap<(u32, u32), G::Fr>,
    pub CR_T: BTreeMap<(u32, u32), G::Fr>,
    pub CO_T: BTreeMap<(u32, u32), G::Fr>,
}

impl<G: Curve> R1csCircuit<G> {
    fn matrix_to_map(mut self) -> Self {
        let m = self.CL.len();
        if self.CL.len() != 0 {
            let n = self.CL[0].len();
            let zero = G::Fr::zero();

            for i in 0..m {
                for j in 0..n {
                    if self.CL[i][j] != zero {
                        self.CL_T.insert((i as u32, j as u32), self.CL[i][j]);
                    }
                    if self.CR[i][j] != zero {
                        self.CR_T.insert((i as u32, j as u32), self.CR[i][j]);
                    }
                    if self.CO[i][j] != zero {
                        self.CO_T.insert((i as u32, j as u32), self.CO[i][j]);
                    }
                }
            }
        }

        self
    }
}

#[derive(Serialize, Deserialize)]
pub struct Assignment<G: Curve> {
    pub aL: Vec<G::Fr>,
    aR: Vec<G::Fr>,
    aO: Vec<G::Fr>,
    pub s: Vec<G::Fr>,
    pub w: Vec<G::Fr>,
}

#[derive(Serialize, Deserialize)]
pub struct Proof<G: Curve> {
    A_I: G::Affine,
    A_O: G::Affine,
    A_W: G::Affine,
    S: G::Affine,
    T_2: G::Affine,
    T_3: G::Affine,
    T_5: G::Affine,
    T_6: G::Affine,
    T_7: G::Affine,
    T_8: G::Affine,
    T_9: G::Affine,
    T_10: G::Affine,
    mu: G::Fr,
    tau_x: G::Fr,
    l_x: Vec<G::Fr>,
    r_x: Vec<G::Fr>,
    t_x: G::Fr,
    IPP: inner_product_proof::Proof<G>,
    IPP_P: G::Projective,
}

// very basic support for R1CS ConstraintSystem
// TODO: refactor this then we do not need to return Generators, R1csCircuit, and Assignment.
pub fn create_random_proof<G, C, R>(
    circuit: C,
    rng: &mut R,
) -> Result<(Generators<G>, R1csCircuit<G>, Proof<G>), SynthesisError>
where
    G: Curve,
    C: ConstraintSynthesizer<G::Fr>,
    R: Rng,
{
    let mut prover = ProvingAssignment::<G::Fr> {
        at: vec![],
        bt: vec![],
        ct: vec![],
        input_assignment: vec![],
        aux_assignment: vec![],
    };

    // Allocate the "one" input variable
    prover.alloc_input(|| "", || Ok(G::Fr::one()))?;

    // Synthesize the circuit.
    circuit.generate_constraints(&mut prover)?; // TODO: maybe we should move this out becasue we do not need a trusted setup for bp

    let num_constraints = prover.at.len();
    assert_eq!(num_constraints, prover.bt.len());
    assert_eq!(num_constraints, prover.ct.len());

    let f = [&prover.input_assignment[..], &prover.aux_assignment[..]].concat();
    let num_inputs = prover.input_assignment.len();
    let num_assignments = f.len();
    // println!(
    //     "num_constraints = {}, num_inputs = {}, num_assignments = {}",
    //     num_constraints, num_inputs, num_assignments
    // );

    let mut CL: Vec<Vec<G::Fr>> = vec![vec![G::Fr::zero(); num_assignments]; num_constraints];
    let mut CR: Vec<Vec<G::Fr>> = vec![vec![G::Fr::zero(); num_assignments]; num_constraints];
    let mut CO: Vec<Vec<G::Fr>> = vec![vec![G::Fr::zero(); num_assignments]; num_constraints];

    // Convert vec with index to full matrix
    // TODO: compute with at, bt, ct directly
    for i in 0..num_constraints {
        for &(ref coeff, index) in prover.at[i].iter() {
            let index = match index {
                Index::Input(i) => i,
                Index::Aux(i) => num_inputs + i,
            };
            CL[i][index] = *coeff;
        }
        for &(ref coeff, index) in prover.bt[i].iter() {
            let index = match index {
                Index::Input(i) => i,
                Index::Aux(i) => num_inputs + i,
            };
            CR[i][index] = *coeff;
        }
        for &(ref coeff, index) in prover.ct[i].iter() {
            let index = match index {
                Index::Input(i) => i,
                Index::Aux(i) => num_inputs + i,
            };
            CO[i][index] = *coeff;
        }
    }

    let r1cs_circuit = R1csCircuit {
        CL,
        CR,
        CO,
        CL_T: Default::default(),
        CR_T: Default::default(),
        CO_T: Default::default(),
    };

    let aL = vector_matrix_product_t::<G::Fr>(&f, &r1cs_circuit.CL);
    let aR = vector_matrix_product_t::<G::Fr>(&f, &r1cs_circuit.CR);
    let aO = vector_matrix_product_t::<G::Fr>(&f, &r1cs_circuit.CO);

    let input = Assignment {
        aL: aL,
        aR: aR,
        aO: aO,
        s: prover.input_assignment,
        w: prover.aux_assignment,
    };

    // create generators
    // n_max
    let n_max = cmp::max(input.aL.len(), input.w.len());
    let N = n_max.next_power_of_two(); // N must be greater than or equal to n & n_w
    let g_vec_N = create_generators::<G, _>(rng, N);
    let h_vec_N = create_generators::<G, _>(rng, N);
    let gh = create_generators::<G, _>(rng, 2);
    let g = gh[0];
    let h = gh[1];
    let u = G::Projective::rand(rng).into_affine();

    let n = num_constraints;
    let k = input.s.len();
    let n_w = input.w.len();
    let generators = Generators {
        g_vec_N,
        h_vec_N,
        g,
        h,
        u,
        n,
        N,
        k,
        n_w,
    };

    let proof = prove(&generators, &r1cs_circuit, &input, rng);

    Ok((generators, r1cs_circuit.matrix_to_map(), proof))
}

// bulletproofs arithmetic circuit proof with R1CS format
pub fn prove<G, R>(
    gens: &Generators<G>,
    r1cs_circuit: &R1csCircuit<G>,
    input: &Assignment<G>,
    rng: &mut R,
) -> Proof<G>
where
    G: Curve,
    R: Rng,
{
    let mut transcript = Transcript::new(b"protocol3");

    let n = input.aL.len();
    assert_eq!(n, input.aR.len());
    assert_eq!(n, input.aO.len());

    let k = input.s.len();
    let n_w = input.w.len();

    // generators
    let mut g_vec: Vec<G::Affine> = vec![G::Affine::default(); n];
    let mut h_vec: Vec<G::Affine> = vec![G::Affine::default(); n];
    g_vec.copy_from_slice(&gens.g_vec_N[0..n]);
    h_vec.copy_from_slice(&gens.h_vec_N[0..n]);
    let g: G::Affine = gens.g;
    let h: G::Affine = gens.h;
    let mut g_vec_w: Vec<G::Affine> = vec![G::Affine::default(); n_w];
    g_vec_w.copy_from_slice(&gens.g_vec_N[0..n_w]);

    // choose blinding vectors sL, sR
    let n_max = cmp::max(n, n_w);
    let N = n_max.next_power_of_two(); // N must be greater than or equal to n & n_w
    transcript.append_u64(b"n", n as u64);
    transcript.append_u64(b"N", N as u64);
    let mut sL: Vec<G::Fr> = (0..n_max).map(|_| G::Fr::rand(rng)).collect();
    let mut sR: Vec<G::Fr> = (0..n_max).map(|_| G::Fr::rand(rng)).collect();

    // alpha, beta, rou, gamma
    let aIBlinding = G::Fr::rand(rng);
    let aOBlinding = G::Fr::rand(rng);
    let sBlinding = G::Fr::rand(rng);
    let gamma = G::Fr::rand(rng); // w blinding

    // commit aL, aR, aO, sL, sR
    // A_I = h^alpha g_vec^aL h_vec^aR
    let A_I_projective: G::Projective = quick_multiexp::<G>(&vec![aIBlinding], &vec![h])
        + &quick_multiexp::<G>(&input.aL, &g_vec)
        + &quick_multiexp::<G>(&input.aR, &h_vec);
    let A_O_projective: G::Projective =
        quick_multiexp::<G>(&vec![aOBlinding], &vec![h]) + &quick_multiexp::<G>(&input.aO, &g_vec);
    let A_W_projective: G::Projective =
        quick_multiexp::<G>(&vec![gamma], &vec![h]) + &quick_multiexp::<G>(&input.w, &g_vec_w);
    let A_I: G::Affine = A_I_projective.into_affine();
    let A_O: G::Affine = A_O_projective.into_affine();
    let A_W: G::Affine = A_W_projective.into_affine();

    let mut g_vec_max: Vec<G::Affine> = vec![G::Affine::default(); n_max];
    let mut h_vec_max: Vec<G::Affine> = vec![G::Affine::default(); n_max];
    g_vec_max.copy_from_slice(&gens.g_vec_N[0..n_max]);
    h_vec_max.copy_from_slice(&gens.h_vec_N[0..n_max]);

    let S_projective: G::Projective = quick_multiexp::<G>(&vec![sBlinding], &vec![h])
        + &quick_multiexp::<G>(&sL, &g_vec_max)
        + &quick_multiexp::<G>(&sR, &h_vec_max);
    let S: G::Affine = S_projective.into_affine();

    transcript.append_message(b"A_I", &math::to_bytes!(A_I).unwrap());
    transcript.append_message(b"A_O", &math::to_bytes!(A_O).unwrap());
    transcript.append_message(b"A_W", &math::to_bytes!(A_W).unwrap());
    transcript.append_message(b"S", &math::to_bytes!(S).unwrap());

    // V challenge y, z
    let mut buf_y = [0u8; 31];
    let mut buf_z = [0u8; 31];
    transcript.challenge_bytes(b"y", &mut buf_y);
    transcript.challenge_bytes(b"z", &mut buf_z);
    let y = random_bytes_to_fr::<G::Fr>(&buf_y);
    let z = random_bytes_to_fr::<G::Fr>(&buf_z);

    // padding
    let mut aL = input.aL.clone();
    let mut aR = input.aR.clone();
    let mut aO = input.aO.clone();
    let mut witness = input.w.clone();
    aL.resize_with(N, Default::default); // padding with G::Fr::zero()
    aR.resize_with(N, Default::default);
    aO.resize_with(N, Default::default);
    witness.resize_with(N, Default::default);
    sL.resize_with(N, Default::default);
    sR.resize_with(N, Default::default);

    // compute y, z vectors
    let mut y_n: Vec<G::Fr> = vec![G::Fr::zero(); N]; // challenge per witness
    for i in 0..N {
        if i == 0 {
            y_n[i] = G::Fr::one();
        } else {
            y_n[i] = y_n[i - 1] * &y;
        }
    }

    let mut y_n_inv: Vec<G::Fr> = vec![G::Fr::zero(); N];
    for i in 0..N {
        y_n_inv[i] = y_n[i].inverse().unwrap();
    }

    let mut z_Q: Vec<G::Fr> = vec![G::Fr::zero(); n]; // challenge per constraint
    for i in 0..n {
        if i == 0 {
            z_Q[i] = z;
        } else {
            z_Q[i] = z_Q[i - 1] * &z;
        }
    }

    // WL, WR, WO with padding
    let mut WL: Vec<Vec<G::Fr>> = vec![vec![G::Fr::zero(); N]; n]; // Qxn, Q=n, n=N
    let mut WR: Vec<Vec<G::Fr>> = vec![vec![G::Fr::zero(); N]; n]; // Qxn, Q=n, n=N
    let mut WO: Vec<Vec<G::Fr>> = vec![vec![G::Fr::zero(); N]; n]; // Qxn, Q=n, n=N
    let zn = z_Q[n - 1];
    let zn_sq = zn * &zn;
    for i in 0..n {
        WL[i][i] = G::Fr::one();
        WR[i][i] = zn * &(G::Fr::one());
        WO[i][i] = zn_sq * &(G::Fr::one());
    }

    // c, WV
    let m = k + n_w;
    let mut C1: Vec<Vec<G::Fr>> = vec![vec![G::Fr::zero(); k]; n];
    let mut WV = vec![vec![G::Fr::zero(); N]; n]; // C2
    for i in 0..n {
        for j in 0..k {
            C1[i][j] = r1cs_circuit.CL[i][j]
                + &(zn * &r1cs_circuit.CR[i][j])
                + &(zn_sq * &r1cs_circuit.CO[i][j]);
        }
        for j in k..m {
            WV[i][j - k] = r1cs_circuit.CL[i][j]
                + &(zn * &r1cs_circuit.CR[i][j])
                + &(zn_sq * &r1cs_circuit.CO[i][j]);
        }
    }
    // let c = vector_matrix_product_t::<E>(&input.s, &C1);

    // zQ * WL, zQ * WR
    let zQ_WL: Vec<G::Fr> = vector_matrix_product::<G::Fr>(&z_Q, &WL);
    let zQ_WR: Vec<G::Fr> = vector_matrix_product::<G::Fr>(&z_Q, &WR);
    let zQ_WO: Vec<G::Fr> = vector_matrix_product::<G::Fr>(&z_Q, &WO);
    let zQ_WV: Vec<G::Fr> = vector_matrix_product::<G::Fr>(&z_Q, &WV);

    let ynInvZQWR: Vec<G::Fr> = hadamard_product::<G::Fr>(&y_n_inv, &zQ_WR);

    let yn_HP_aR: Vec<G::Fr> = hadamard_product::<G::Fr>(&y_n, &aR);
    let yn_HP_sR: Vec<G::Fr> = hadamard_product::<G::Fr>(&y_n, &sR);

    // P compute l(X), r(X)
    let mut l_poly = VecPoly5::<G::Fr>::zero(N);
    let mut r_poly = VecPoly5::<G::Fr>::zero(N);
    for i in 0..N {
        l_poly.2[i] = aL[i] + &ynInvZQWR[i];
        l_poly.3[i] = aO[i];
        l_poly.4[i] = witness[i];
        l_poly.5[i] = sL[i];

        r_poly.2[i] = yn_HP_aR[i] + &zQ_WL[i];
        r_poly.1[i] = -y_n[i] + &zQ_WO[i];
        r_poly.0[i] = -zQ_WV[i];
        r_poly.5[i] = yn_HP_sR[i];
    }

    let t_poly = VecPoly5::<G::Fr>::special_inner_product(&l_poly, &r_poly);

    // generate blinding factors for ti
    let tau_2 = G::Fr::rand(rng);
    let tau_3 = G::Fr::rand(rng);
    let tau_5 = G::Fr::rand(rng);
    let tau_6 = G::Fr::rand(rng);
    let tau_7 = G::Fr::rand(rng);
    let tau_8 = G::Fr::rand(rng);
    let tau_9 = G::Fr::rand(rng);
    let tau_10 = G::Fr::rand(rng);

    // commit t_i
    let T_2 = quick_multiexp::<G>(&vec![t_poly.t2, tau_2], &vec![g, h]).into_affine();
    let T_3 = quick_multiexp::<G>(&vec![t_poly.t3, tau_3], &vec![g, h]).into_affine();
    let T_5 = quick_multiexp::<G>(&vec![t_poly.t5, tau_5], &vec![g, h]).into_affine();
    let T_6 = quick_multiexp::<G>(&vec![t_poly.t6, tau_6], &vec![g, h]).into_affine();
    let T_7 = quick_multiexp::<G>(&vec![t_poly.t7, tau_7], &vec![g, h]).into_affine();
    let T_8 = quick_multiexp::<G>(&vec![t_poly.t8, tau_8], &vec![g, h]).into_affine();
    let T_9 = quick_multiexp::<G>(&vec![t_poly.t9, tau_9], &vec![g, h]).into_affine();
    let T_10 = quick_multiexp::<G>(&vec![t_poly.t10, tau_10], &vec![g, h]).into_affine();

    transcript.append_message(b"T_2", &math::to_bytes!(T_2).unwrap());
    transcript.append_message(b"T_3", &math::to_bytes!(T_3).unwrap());
    transcript.append_message(b"T_5", &math::to_bytes!(T_5).unwrap());
    transcript.append_message(b"T_6", &math::to_bytes!(T_6).unwrap());
    transcript.append_message(b"T_7", &math::to_bytes!(T_7).unwrap());
    transcript.append_message(b"T_8", &math::to_bytes!(T_8).unwrap());
    transcript.append_message(b"T_9", &math::to_bytes!(T_9).unwrap());
    transcript.append_message(b"T_10", &math::to_bytes!(T_10).unwrap());

    // V challenge x
    let mut buf_x = [0u8; 31];
    transcript.challenge_bytes(b"x", &mut buf_x);
    let x = random_bytes_to_fr::<G::Fr>(&buf_x);

    // P computes:
    let l_x: Vec<G::Fr> = l_poly.eval(x);
    let r_x: Vec<G::Fr> = r_poly.eval(x);

    let t_x = inner_product::<G::Fr>(&l_x, &r_x);

    let xx = x * &x;
    let xxxx = xx * &xx;
    // blinding value for t_x
    let tau_x = tau_2 * &xx
        + &(tau_3 * &(xx * &x))
        + &(tau_5 * &(xxxx * &x))
        + &(tau_6 * &(xxxx * &xx))
        + &(tau_7 * &(xxxx * &(xx * &x)))
        + &(tau_8 * &(xxxx * &xxxx))
        + &(tau_9 * &(xxxx * &(xxxx * &x)))
        + &(tau_10 * &(xxxx * &(xxxx * &xx)));

    // blinding value for P
    let mu = aIBlinding * &xx
        + &(aOBlinding * &(xx * &x))
        + &(gamma * &xxxx)
        + &(sBlinding * &(xxxx * &x));

    // IPP
    transcript.append_message(b"t_x", &math::to_bytes!(t_x).unwrap());
    transcript.append_message(b"tau_x", &math::to_bytes!(tau_x).unwrap());
    transcript.append_message(b"mu", &math::to_bytes!(mu).unwrap());

    let mut buf_x_1 = [0u8; 31];
    transcript.challenge_bytes(b"x_1", &mut buf_x_1); // notice: challenge x in protocol1 to avoid cheating from prover
    let x_1 = random_bytes_to_fr::<G::Fr>(&buf_x_1);
    let ux = (gens.u.mul(x_1)).into_affine();

    let IPP_P = quick_multiexp::<G>(&l_x, &gens.g_vec_N)
        + &quick_multiexp::<G>(&r_x, &gens.h_vec_N)
        + &ux.mul(t_x);

    let IPP = inner_product_proof::prove(
        gens.g_vec_N.clone(),
        gens.h_vec_N.clone(),
        ux,
        l_x.clone(),
        r_x.clone(),
    );

    // let bp_circuit = BpCircuit {
    //     n,
    //     N,
    //     WL,
    //     WR,
    //     WO,
    //     WV,
    //     c,
    // };

    let proof = Proof {
        A_I,
        A_O,
        A_W,
        S,
        T_2,
        T_3,
        T_5,
        T_6,
        T_7,
        T_8,
        T_9,
        T_10,
        mu,
        tau_x,
        l_x,
        r_x,
        t_x,
        // V,
        IPP,
        IPP_P,
    };

    proof
}

pub fn verify_proof<G: Curve>(
    gens: &Generators<G>,
    proof: &Proof<G>,
    r1cs_circuit: &R1csCircuit<G>,
    public_inputs: &[G::Fr],
) -> Result<bool, SynthesisError> {
    let mut transcript = Transcript::new(b"protocol3");
    let zero = G::Fr::zero();
    let one = G::Fr::one();

    // generators
    let g_vec: Vec<G::Affine> = gens.g_vec_N.clone();
    let h_vec: Vec<G::Affine> = gens.h_vec_N.clone();
    let g = gens.g.clone();
    let h = gens.h.clone();

    transcript.append_u64(b"n", gens.n as u64);
    transcript.append_u64(b"N", gens.N as u64);

    transcript.append_message(b"A_I", &math::to_bytes!(proof.A_I).unwrap());
    transcript.append_message(b"A_O", &math::to_bytes!(proof.A_O).unwrap());
    transcript.append_message(b"A_W", &math::to_bytes!(proof.A_W).unwrap());
    transcript.append_message(b"S", &math::to_bytes!(proof.S).unwrap());

    // V challenge y, z
    let mut buf_y = [0u8; 31];
    let mut buf_z = [0u8; 31];
    transcript.challenge_bytes(b"y", &mut buf_y);
    transcript.challenge_bytes(b"z", &mut buf_z);
    let y = random_bytes_to_fr::<G::Fr>(&buf_y);
    let z = random_bytes_to_fr::<G::Fr>(&buf_z);

    // compute y, z vectors, and delta(y, z)
    let mut y_n: Vec<G::Fr> = vec![zero; gens.N]; // challenge per witness
    for i in 0..gens.N {
        if i == 0 {
            y_n[i] = one;
        } else {
            y_n[i] = y_n[i - 1] * &y;
        }
    }

    let mut y_n_inv: Vec<G::Fr> = vec![zero; gens.N];
    for i in 0..gens.N {
        y_n_inv[i] = y_n[i].inverse().unwrap();
    }

    let mut z_Q: Vec<G::Fr> = vec![zero; gens.n]; // challenge per constraint
    for i in 0..gens.n {
        if i == 0 {
            z_Q[i] = z;
        } else {
            z_Q[i] = z_Q[i - 1] * &z;
        }
    }

    let z_Q_neg: Vec<G::Fr> = (0..gens.n).map(|i| -one * &z_Q[i]).collect();

    //println!("gens.N: {}, gens.n: {}", gens.N, gens.n);
    // WL, WR, WO with padding
    //let mut WL: Vec<Vec<G::Fr>> = vec![vec![G::Fr::zero(); gens.N]; gens.n]; // Qxn, Q=n, n=N
    //let mut WR: Vec<Vec<G::Fr>> = vec![vec![G::Fr::zero(); gens.N]; gens.n]; // Qxn, Q=n, n=N
    //let mut WO: Vec<Vec<G::Fr>> = vec![vec![G::Fr::zero(); gens.N]; gens.n]; // Qxn, Q=n, n=Nw
    let mut WL: Vec<G::Fr> = vec![zero; gens.n]; // Qxn, Q=n, n=N
    let mut WR: Vec<G::Fr> = vec![zero; gens.n]; // Qxn, Q=n, n=N
    let mut WO: Vec<G::Fr> = vec![zero; gens.n]; // Qxn, Q=n, n=N

    let zn = z_Q[gens.n - 1];
    let zn_sq = zn * &zn;
    for i in 0..gens.n {
        //WL[i][i] = G::Fr::one();
        //WR[i][i] = zn * &(G::Fr::one());
        //WO[i][i] = zn_sq * &(G::Fr::one());
        WL[i] = one;
        WR[i] = zn * &one;
        WO[i] = zn_sq * &one;
    }

    // c, WV
    let m = gens.k + gens.n_w;
    let mut C1: Vec<Vec<G::Fr>> = vec![vec![zero; gens.k]; gens.n];
    //let mut WV: Vec<Vec<G::Fr>> = vec![vec![zero; gens.N]; gens.n]; // C2
    let mut WV: BTreeMap<(u32, u32), G::Fr> = BTreeMap::new();

    for i in 0..gens.n {
        for j in 0..gens.k {
            let cl = r1cs_circuit
                .CL_T
                .get(&(i as u32, j as u32))
                .unwrap_or(&zero);
            let cr = r1cs_circuit
                .CR_T
                .get(&(i as u32, j as u32))
                .unwrap_or(&zero);
            let co = r1cs_circuit
                .CO_T
                .get(&(i as u32, j as u32))
                .unwrap_or(&zero);
            C1[i][j] = *cl + &(zn * cr) + &(zn_sq * co);
        }
        for j in gens.k..m {
            let cl = r1cs_circuit
                .CL_T
                .get(&(i as u32, j as u32))
                .unwrap_or(&zero);
            let cr = r1cs_circuit
                .CR_T
                .get(&(i as u32, j as u32))
                .unwrap_or(&zero);
            let co = r1cs_circuit
                .CO_T
                .get(&(i as u32, j as u32))
                .unwrap_or(&zero);

            //WV[i][j - gens.k] = *cl + &(zn * cr) + &(zn_sq * co);
            let res = *cl + &(zn * cr) + &(zn_sq * co);
            if res != zero {
                WV.insert((i as u32, (j - gens.k) as u32), res);
            }
        }
    }
    let mut r1_public_inputs = vec![G::Fr::one()];
    r1_public_inputs.extend(public_inputs);
    let c = vector_matrix_product_t::<G::Fr>(&r1_public_inputs, &C1);

    // zQ * WL, zQ * WR
    let zQ_WL: Vec<G::Fr> = vector_product::<G::Fr>(&z_Q, &WL, gens.N, gens.n);
    let zQ_WR: Vec<G::Fr> = vector_product::<G::Fr>(&z_Q, &WR, gens.N, gens.n);
    let zQ_WO: Vec<G::Fr> = vector_product::<G::Fr>(&z_Q, &WO, gens.N, gens.n);
    let zQ_neg_WV: Vec<G::Fr> = vector_map_product::<G::Fr>(&z_Q_neg, &WV, gens.N);

    let ynInvZQWR: Vec<G::Fr> = hadamard_product::<G::Fr>(&y_n_inv, &zQ_WR);
    let delta_yz = inner_product::<G::Fr>(&ynInvZQWR, &zQ_WL);

    // V challenge x
    transcript.append_message(b"T_2", &math::to_bytes!(proof.T_2).unwrap());
    transcript.append_message(b"T_3", &math::to_bytes!(proof.T_3).unwrap());
    transcript.append_message(b"T_5", &math::to_bytes!(proof.T_5).unwrap());
    transcript.append_message(b"T_6", &math::to_bytes!(proof.T_6).unwrap());
    transcript.append_message(b"T_7", &math::to_bytes!(proof.T_7).unwrap());
    transcript.append_message(b"T_8", &math::to_bytes!(proof.T_8).unwrap());
    transcript.append_message(b"T_9", &math::to_bytes!(proof.T_9).unwrap());
    transcript.append_message(b"T_10", &math::to_bytes!(proof.T_10).unwrap());

    // V challenge x
    let mut buf_x = [0u8; 31];
    transcript.challenge_bytes(b"x", &mut buf_x);
    let x = random_bytes_to_fr::<G::Fr>(&buf_x);

    // V computes and checks:
    let h_vec_inv: Vec<G::Affine> = (0..gens.N)
        .map(|i| h_vec[i].mul(y_n_inv[i]).into_affine())
        .collect();

    let wL: G::Projective = quick_multiexp::<G>(&zQ_WL, &h_vec_inv);
    let wR: G::Projective = quick_multiexp::<G>(&ynInvZQWR, &g_vec);
    let wO: G::Projective = quick_multiexp::<G>(&zQ_WO, &h_vec_inv);
    let wV: G::Projective = quick_multiexp::<G>(&zQ_neg_WV, &h_vec_inv);

    transcript.append_message(b"t_x", &math::to_bytes!(proof.t_x).unwrap());
    transcript.append_message(b"tau_x", &math::to_bytes!(proof.tau_x).unwrap());
    transcript.append_message(b"mu", &math::to_bytes!(proof.mu).unwrap());
    let mut buf_x_1 = [0u8; 31];
    transcript.challenge_bytes(b"x_1", &mut buf_x_1); // notice: challenge x in protocol1 to avoid cheating from prover
    let x_1 = random_bytes_to_fr::<G::Fr>(&buf_x_1);
    let ux = (gens.u.mul(x_1)).into_affine();

    // check tx ?= <lx, rx>
    // USE IPP here
    // assert_eq!(proof.t_x, inner_product::<G::Fr>(&proof.l_x, &proof.r_x));
    if !inner_product_proof::verify(
        gens.g_vec_N.clone(),
        gens.h_vec_N.clone(),
        ux,
        &proof.IPP_P,
        &proof.IPP,
    ) {
        return Ok(false);
    }

    // check ti
    let checkT_lhs: G::Projective = quick_multiexp::<G>(&vec![proof.t_x, proof.tau_x], &vec![g, h]);

    let zQ_c = inner_product::<G::Fr>(&z_Q, &c);

    let xx = x * &x;
    let xxxx = xx * &xx;
    let checkT_rhs: G::Projective =
        quick_multiexp::<G>(&vec![xxxx * &(delta_yz + &zQ_c)], &vec![g])
            + &proof.T_2.mul(xx)
            + &proof.T_3.mul(xx * &x)
            + &proof.T_5.mul(xxxx * &x)
            + &proof.T_6.mul(xxxx * &xx)
            + &proof.T_7.mul(xxxx * &(xx * &x))
            + &proof.T_8.mul(xxxx * &xxxx)
            + &proof.T_9.mul(xxxx * &(xxxx * &x))
            + &proof.T_10.mul(xxxx * &(xxxx * &xx));

    assert_eq!(checkT_lhs, checkT_rhs);

    let y_n_neg: Vec<G::Fr> = (0..gens.N).map(|i| -one * &y_n[i]).collect();
    let P = proof.A_I.mul(xx)
        + &proof.A_O.mul(xx * &x)
        + &proof.A_W.mul(xxxx)
        + &(quick_multiexp::<G>(&y_n_neg, &h_vec_inv).mul(x))
        + &wL.mul(xx)
        + &wR.mul(xx)
        + &wO.mul(x)
        + &wV
        + &proof.S.mul(xxxx * &x);
    let checkP = h.mul(proof.mu)
        + &quick_multiexp::<G>(&proof.l_x, &g_vec)
        + &quick_multiexp::<G>(&proof.r_x, &h_vec_inv);

    Ok(P == checkP)
}

pub fn create_generators<G: Curve, R: Rng>(rng: &mut R, len: usize) -> Vec<G::Affine> {
    let mut generators = Vec::new();
    for _ in 0..len {
        generators.push(G::Projective::rand(rng).into_affine());
    }
    generators
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve::{Bls12_381, Bn_256};

    fn run_protocol3_r1cs_helper<G: Curve>(
        CL: Vec<Vec<G::Fr>>,
        CR: Vec<Vec<G::Fr>>,
        CO: Vec<Vec<G::Fr>>,
        statement: Vec<G::Fr>,
        witness: Vec<G::Fr>,
    ) {
        let rng = &mut math::test_rng();

        let r1cs_circuit = R1csCircuit {
            CL,
            CR,
            CO,
            CL_T: Default::default(),
            CR_T: Default::default(),
            CO_T: Default::default(),
        }
        .matrix_to_map();

        let f = [&statement[..], &witness[..]].concat();
        let aL = vector_matrix_product_t::<G::Fr>(&f, &r1cs_circuit.CL);
        let aR = vector_matrix_product_t::<G::Fr>(&f, &r1cs_circuit.CR);
        let aO = vector_matrix_product_t::<G::Fr>(&f, &r1cs_circuit.CO);

        let input = Assignment {
            aL: aL,
            aR: aR,
            aO: aO,
            s: statement,
            w: witness,
        };

        // create generators
        // n_max
        let n_max = cmp::max(input.aL.len(), input.w.len());
        let N = n_max.next_power_of_two(); // N must be greater than or equal to n & n_w
        let g_vec_N = create_generators::<G, _>(rng, N);
        let h_vec_N = create_generators::<G, _>(rng, N);
        let gh = create_generators::<G, _>(rng, 2);
        let g = gh[0];
        let h = gh[1];
        let u = G::Projective::rand(rng).into_affine();

        let n = input.aL.len();
        let k = input.s.len();
        let n_w = input.w.len();
        let generators = Generators::<G> {
            g_vec_N,
            h_vec_N,
            g,
            h,
            u,
            n,
            N,
            k,
            n_w,
        };

        let proof = prove(&generators, &r1cs_circuit, &input, rng);

        assert!(verify_proof(&generators, &proof, &r1cs_circuit, &input.s).unwrap());
    }

    #[test]
    fn run_vitalik_problem_r1cs_bn256() {
        vitalik_problem_r1cs_succeed::<Bn_256>();
    }

    #[test]
    fn run_vitalik_problem_r1cs_bls12_381() {
        vitalik_problem_r1cs_succeed::<Bls12_381>();
    }

    // x^3 + x + 5 = 35
    fn vitalik_problem_r1cs_succeed<G: Curve>() {
        let zer = G::Fr::zero();
        let one = G::Fr::one();

        let CL = vec![
            vec![zer, zer, one, zer, zer, zer],
            vec![zer, zer, zer, one, zer, zer],
            vec![zer, zer, one, zer, one, zer],
            vec![G::Fr::from(5u8), zer, zer, zer, zer, one],
        ];
        let CR = vec![
            vec![zer, zer, one, zer, zer, zer],
            vec![zer, zer, one, zer, zer, zer],
            vec![one, zer, zer, zer, zer, zer],
            vec![one, zer, zer, zer, zer, zer],
        ];
        let CO = vec![
            vec![zer, zer, zer, one, zer, zer],
            vec![zer, zer, zer, zer, one, zer],
            vec![zer, zer, zer, zer, zer, one],
            vec![zer, one, zer, zer, zer, zer],
        ];
        let statement = vec![one, G::Fr::from(35u8)];
        let witness = vec![
            G::Fr::from(3u8),
            G::Fr::from(9u8),
            G::Fr::from(27u8),
            G::Fr::from(30u8),
        ];

        run_protocol3_r1cs_helper::<G>(CL, CR, CO, statement, witness);
    }

    // test cases from Dalek
    #[test]
    fn run_mul_circuit_1_r1cs_bn256() {
        mul_circuit_1_r1cs_succeed::<Bn_256>();
    }

    #[test]
    fn run_mul_circuit_1_r1cs_bls12_381() {
        mul_circuit_1_r1cs_succeed::<Bls12_381>();
    }

    // Test that a basic multiplication circuit on inputs (with linear contraints) succeeds
    // LINEAR CONSTRAINTS:
    // a_L[0] = 2
    // a_R[0] = 3
    // a_O[0] = 6
    // MUL CONSTRAINTS (implicit):
    // a_L[0] * a_R[0] = a_O[0]
    fn mul_circuit_1_r1cs_succeed<G: Curve>() {
        let zer = G::Fr::zero();
        let one = G::Fr::one();

        let CL = vec![vec![zer, one, zer, zer]];
        let CR = vec![vec![zer, zer, one, zer]];
        let CO = vec![vec![zer, zer, zer, one]];
        let statement = vec![one];
        let witness = vec![G::Fr::from(2u8), G::Fr::from(3u8), G::Fr::from(6u8)];

        run_protocol3_r1cs_helper::<G>(CL, CR, CO, statement, witness);
    }

    #[test]
    fn run_mul_circuit_3_r1cs_bn256() {
        mul_circuit_3_r1cs_succeed::<Bn_256>();
    }

    #[test]
    fn run_mul_circuit_3_r1cs_bls12_381() {
        mul_circuit_3_r1cs_succeed::<Bls12_381>();
    }

    // Test that a basic multiplication circuit on inputs (with linear contraints) succeeds
    // LINEAR CONSTRAINTS:
    // a_L[0] = 2, a_R[0] = 3, a_O[0] = 6
    // a_L[1] = 1, a_R[1] = 4, a_O[1] = 4
    // a_L[2] = 3, a_R[2] = 5, a_O[2] = 15
    // MUL CONSTRAINTS (implicit):
    // a_L[0] * a_R[0] = a_O[0]
    // a_L[1] * a_R[1] = a_O[1]
    // a_L[2] * a_R[2] = a_O[2]
    fn mul_circuit_3_r1cs_succeed<G: Curve>() {
        let zer = G::Fr::zero();
        let one = G::Fr::one();

        let CL = vec![
            vec![zer, one, zer, zer, zer, zer, zer, zer, zer, zer],
            vec![zer, zer, zer, zer, one, zer, zer, zer, zer, zer],
            vec![zer, zer, zer, zer, zer, zer, zer, one, zer, zer],
        ];
        let CR = vec![
            vec![zer, zer, one, zer, zer, zer, zer, zer, zer, zer],
            vec![zer, zer, zer, zer, zer, one, zer, zer, zer, zer],
            vec![zer, zer, zer, zer, zer, zer, zer, zer, one, zer],
        ];
        let CO = vec![
            vec![zer, zer, zer, one, zer, zer, zer, zer, zer, zer],
            vec![zer, zer, zer, zer, zer, zer, one, zer, zer, zer],
            vec![zer, zer, zer, zer, zer, zer, zer, zer, zer, one],
        ];
        let statement = vec![one];
        let witness = vec![
            G::Fr::from(2u8),
            G::Fr::from(3u8),
            G::Fr::from(6u8),
            one,
            G::Fr::from(4u8),
            G::Fr::from(4u8),
            G::Fr::from(3u8),
            G::Fr::from(5u8),
            G::Fr::from(15u8),
        ];

        run_protocol3_r1cs_helper::<G>(CL, CR, CO, statement, witness);
    }

    #[test]
    fn run_shuffle_circuit_r1cs_bn256() {
        shuffle_circuit_r1cs_succeed::<Bn_256>();
    }

    #[test]
    fn run_shuffle_circuit_r1cs_bls12_381() {
        shuffle_circuit_r1cs_succeed::<Bls12_381>();
    }

    // Test that a 2 in 2 out shuffle circuit succeeds
    // LINEAR CONSTRAINTS:
    // a_O[0] = a_O[1]
    // a_L[0] = V[0] - z
    // a_L[1] = V[2] - z
    // a_R[0] = V[1] - z
    // a_R[1] = V[3] - z
    // MUL CONSTRAINTS:
    // a_L[0] * a_R[0] = a_O[0]
    // a_L[1] * a_R[1] = a_O[1]
    fn shuffle_circuit_r1cs_succeed<G: Curve>() {
        let rng = &mut math::test_rng();

        let zer = G::Fr::zero();
        let one = G::Fr::one();
        let zx = G::Fr::rand(rng);
        // (a - x)(b - x) = (c - x)(d - x)
        let CL = vec![
            vec![-zx, one, zer, zer, zer, zer, zer],
            vec![-zx, zer, zer, one, zer, zer, zer],
            vec![zer, zer, zer, zer, zer, one, -one],
        ];
        let CR = vec![
            vec![-zx, zer, one, zer, zer, zer, zer],
            vec![-zx, zer, zer, zer, one, zer, zer],
            vec![one, zer, zer, zer, zer, zer, zer],
        ];
        let CO = vec![
            vec![zer, zer, zer, zer, zer, one, zer],
            vec![zer, zer, zer, zer, zer, zer, one],
            vec![zer, zer, zer, zer, zer, zer, zer],
        ];
        let statement = vec![one];
        let three = G::Fr::from(3u8);
        let seven = G::Fr::from(7u8);
        let witness = vec![
            three,
            seven,
            seven,
            three,
            (three - &zx) * &(seven - &zx),
            (seven - &zx) * &(three - &zx),
        ];

        run_protocol3_r1cs_helper::<G>(CL, CR, CO, statement, witness);
    }

    #[test]
    fn run_add_circuit_bn256() {
        add_circuit_succeed::<Bn_256>();
    }

    #[test]
    fn run_add_circuit_bls12_381() {
        add_circuit_succeed::<Bls12_381>();
    }

    // Test that a basic addition circuit (without multiplication gates) succeeds
    // LINEAR CONSTRAINTS:
    // V[0] + V[1] = V[2]
    // MUL CONSTRAINTS: none
    fn add_circuit_succeed<G: Curve>() {
        let zer = G::Fr::zero();
        let one = G::Fr::one();

        let CL = vec![vec![zer, one, one, zer]];
        let CR = vec![vec![one, zer, zer, zer]];
        let CO = vec![vec![zer, zer, zer, one]];
        let statement = vec![one];
        let witness = vec![G::Fr::from(4u8), G::Fr::from(5u8), G::Fr::from(9u8)];

        run_protocol3_r1cs_helper::<G>(CL, CR, CO, statement, witness);
    }
}
