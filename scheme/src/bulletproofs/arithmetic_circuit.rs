#![allow(non_snake_case)]
use core::cmp;
use math::{
    bytes::{FromBytes, ToBytes},
    io::Result as IoResult,
    serialize::*,
    AffineCurve, Field, One, PairingEngine, ProjectiveCurve, UniformRand, Zero,
};
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

pub struct ProvingAssignment<E: PairingEngine> {
    // Constraints
    pub(crate) at: Vec<Vec<(E::Fr, Index)>>,
    pub(crate) bt: Vec<Vec<(E::Fr, Index)>>,
    pub(crate) ct: Vec<Vec<(E::Fr, Index)>>,

    // Assignments of variables
    pub(crate) input_assignment: Vec<E::Fr>,
    pub(crate) aux_assignment: Vec<E::Fr>,
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
    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
        LB: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
        LC: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
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

pub struct Generators<E: PairingEngine> {
    g_vec_N: Vec<E::G1Affine>,
    h_vec_N: Vec<E::G1Affine>,
    g: E::G1Affine,
    h: E::G1Affine,
    u: E::G1Affine,
    n: usize,
    N: usize,
    k: usize,
    n_w: usize,
}

impl<E: PairingEngine> ToBytes for Generators<E> {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        (self.g_vec_N.len() as u64).write(&mut writer)?;
        for q in &self.g_vec_N {
            q.write(&mut writer)?;
        }

        (self.h_vec_N.len() as u64).write(&mut writer)?;
        for q in &self.h_vec_N {
            q.write(&mut writer)?;
        }

        self.g.write(&mut writer)?;
        self.h.write(&mut writer)?;
        self.u.write(&mut writer)?;

        (self.n as u64).write(&mut writer)?;
        (self.N as u64).write(&mut writer)?;
        (self.k as u64).write(&mut writer)?;
        (self.n_w as u64).write(&mut writer)?;

        Ok(())
    }
}

impl<E: PairingEngine> FromBytes for Generators<E> {
    #[inline]
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let g_len = u64::read(&mut reader)?;
        let mut g_vec_N = vec![];
        for _ in 0..g_len {
            let v = E::G1Affine::read(&mut reader)?;
            g_vec_N.push(v);
        }

        let h_len = u64::read(&mut reader)?;
        let mut h_vec_N = vec![];
        for _ in 0..h_len {
            let v = E::G1Affine::read(&mut reader)?;
            h_vec_N.push(v);
        }

        let g = E::G1Affine::read(&mut reader)?;
        let h = E::G1Affine::read(&mut reader)?;
        let u = E::G1Affine::read(&mut reader)?;

        let n = u64::read(&mut reader)? as usize;
        let N = u64::read(&mut reader)? as usize;
        let k = u64::read(&mut reader)? as usize;
        let n_w = u64::read(&mut reader)? as usize;

        Ok(Self {
            g_vec_N,
            h_vec_N,
            g,
            h,
            u,
            n,
            N,
            k,
            n_w,
        })
    }
}

// pub struct BpCircuit<E: PairingEngine> {
//     n: usize,
//     N: usize,
//     WL: Vec<Vec<E::Fr>>,
//     WR: Vec<Vec<E::Fr>>,
//     WO: Vec<Vec<E::Fr>>,
//     WV: Vec<Vec<E::Fr>>,
//     c: Vec<E::Fr>,
// }

pub struct R1csCircuit<E: PairingEngine> {
    pub CL: Vec<Vec<E::Fr>>,
    pub CR: Vec<Vec<E::Fr>>,
    pub CO: Vec<Vec<E::Fr>>,
    pub CL_T: BTreeMap<(u32, u32), E::Fr>,
    pub CR_T: BTreeMap<(u32, u32), E::Fr>,
    pub CO_T: BTreeMap<(u32, u32), E::Fr>,
}

impl<E: PairingEngine> ToBytes for R1csCircuit<E> {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        let zero = E::Fr::zero();

        let x = self.CL.len();
        let y = if x > 0 { self.CL[0].len() } else { 0 };

        (x as u32).write(&mut writer)?;
        (y as u32).write(&mut writer)?;

        let mut cl_bytes = Vec::new();
        let mut cr_bytes = Vec::new();
        let mut co_bytes = Vec::new();

        let mut l_i = 0u32;
        let mut r_i = 0u32;
        let mut o_i = 0u32;

        for i in 0..x {
            let mut l_n = 0u32;
            let mut l_bytes = Vec::new();

            let mut r_n = 0u32;
            let mut r_bytes = Vec::new();

            let mut o_n = 0u32;
            let mut o_bytes = Vec::new();

            for j in 0..y {
                let l_t = self.CL[i][j];
                let r_t = self.CR[i][j];
                let o_t = self.CO[i][j];

                if l_t != zero {
                    (j as u32).write(&mut l_bytes)?;
                    l_t.write(&mut l_bytes)?;
                    l_n += 1
                }

                if r_t != zero {
                    (j as u32).write(&mut r_bytes)?;
                    r_t.write(&mut r_bytes)?;
                    r_n += 1
                }

                if o_t != zero {
                    (j as u32).write(&mut o_bytes)?;
                    o_t.write(&mut o_bytes)?;
                    o_n += 1
                }
            }

            if l_n > 0 {
                l_i += 1;
                (i as u32).write(&mut cl_bytes)?;
                l_n.write(&mut cl_bytes)?;
                l_bytes.write(&mut cl_bytes)?;
            }

            if r_n > 0 {
                r_i += 1;
                (i as u32).write(&mut cr_bytes)?;
                r_n.write(&mut cr_bytes)?;
                r_bytes.write(&mut cr_bytes)?;
            }

            if o_n > 0 {
                o_i += 1;
                (i as u32).write(&mut co_bytes)?;
                o_n.write(&mut co_bytes)?;
                o_bytes.write(&mut co_bytes)?;
            }
        }

        l_i.write(&mut writer)?;
        cl_bytes.write(&mut writer)?;

        r_i.write(&mut writer)?;
        cr_bytes.write(&mut writer)?;

        o_i.write(&mut writer)?;
        co_bytes.write(&mut writer)?;

        Ok(())
    }
}

impl<E: PairingEngine> FromBytes for R1csCircuit<E> {
    #[inline]
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        //let zero = E::Fr::zero();
        let _x = u32::read(&mut reader)? as usize;
        let _y = u32::read(&mut reader)? as usize;
        //println!("x: {}, y: {}", _x, _y);

        let mut CL_T = BTreeMap::new();
        let mut CR_T = BTreeMap::new();
        let mut CO_T = BTreeMap::new();

        let l_i = u32::read(&mut reader)?;
        for _ in 0..l_i {
            let i = u32::read(&mut reader)? as usize;
            let i_n = u32::read(&mut reader)?;
            for _ in 0..i_n {
                let j = u32::read(&mut reader)? as usize;
                CL_T.insert((i as u32, j as u32), E::Fr::read(&mut reader)?);
            }
        }

        let r_i = u32::read(&mut reader)?;
        for _ in 0..r_i {
            let i = u32::read(&mut reader)? as usize;
            let i_n = u32::read(&mut reader)?;
            for _ in 0..i_n {
                let j = u32::read(&mut reader)? as usize;
                CR_T.insert((i as u32, j as u32), E::Fr::read(&mut reader)?);
            }
        }

        let o_i = u32::read(&mut reader)?;
        for _ in 0..o_i {
            let i = u32::read(&mut reader)? as usize;
            let i_n = u32::read(&mut reader)?;
            for _ in 0..i_n {
                let j = u32::read(&mut reader)? as usize;
                CO_T.insert((i as u32, j as u32), E::Fr::read(&mut reader)?);
            }
        }

        Ok(Self {
            CL_T,
            CR_T,
            CO_T,
            CL: Default::default(),
            CR: Default::default(),
            CO: Default::default(),
        })
    }
}

pub struct Assignment<E: PairingEngine> {
    pub aL: Vec<E::Fr>,
    aR: Vec<E::Fr>,
    aO: Vec<E::Fr>,
    pub s: Vec<E::Fr>,
    pub w: Vec<E::Fr>,
}

impl<E: PairingEngine> ToBytes for Assignment<E> {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        (self.aL.len() as u64).write(&mut writer)?;
        for i in &self.aL {
            i.write(&mut writer)?;
        }

        (self.aR.len() as u64).write(&mut writer)?;
        for i in &self.aR {
            i.write(&mut writer)?;
        }

        (self.aO.len() as u64).write(&mut writer)?;
        for i in &self.aO {
            i.write(&mut writer)?;
        }

        (self.s.len() as u64).write(&mut writer)?;
        for i in &self.s {
            i.write(&mut writer)?;
        }

        (self.w.len() as u64).write(&mut writer)?;
        for i in &self.w {
            i.write(&mut writer)?;
        }

        Ok(())
    }
}

impl<E: PairingEngine> FromBytes for Assignment<E> {
    #[inline]
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let l_len = u64::read(&mut reader)?;
        let mut aL = vec![];
        for _ in 0..l_len {
            let v = E::Fr::read(&mut reader)?;
            aL.push(v);
        }

        let r_len = u64::read(&mut reader)?;
        let mut aR = vec![];
        for _ in 0..r_len {
            let v = E::Fr::read(&mut reader)?;
            aR.push(v);
        }

        let o_len = u64::read(&mut reader)?;
        let mut aO = vec![];
        for _ in 0..o_len {
            let v = E::Fr::read(&mut reader)?;
            aO.push(v);
        }

        let s_len = u64::read(&mut reader)?;
        let mut s = vec![];
        for _ in 0..s_len {
            let v = E::Fr::read(&mut reader)?;
            s.push(v);
        }

        let w_len = u64::read(&mut reader)?;
        let mut w = vec![];
        for _ in 0..w_len {
            let v = E::Fr::read(&mut reader)?;
            w.push(v);
        }

        Ok(Self { aL, aR, aO, s, w })
    }
}

pub struct Proof<E: PairingEngine> {
    A_I: E::G1Affine,
    A_O: E::G1Affine,
    A_W: E::G1Affine,
    S: E::G1Affine,
    T_2: E::G1Affine,
    T_3: E::G1Affine,
    T_5: E::G1Affine,
    T_6: E::G1Affine,
    T_7: E::G1Affine,
    T_8: E::G1Affine,
    T_9: E::G1Affine,
    T_10: E::G1Affine,
    mu: E::Fr,
    tau_x: E::Fr,
    l_x: Vec<E::Fr>,
    r_x: Vec<E::Fr>,
    t_x: E::Fr,
    IPP: inner_product_proof::Proof<E>,
    IPP_P: E::G1Projective,
}

impl<E: PairingEngine> ToBytes for Proof<E> {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.A_I.write(&mut writer)?;
        self.A_O.write(&mut writer)?;
        self.A_W.write(&mut writer)?;
        self.S.write(&mut writer)?;
        self.T_2.write(&mut writer)?;
        self.T_3.write(&mut writer)?;
        self.T_5.write(&mut writer)?;
        self.T_6.write(&mut writer)?;
        self.T_7.write(&mut writer)?;
        self.T_8.write(&mut writer)?;
        self.T_9.write(&mut writer)?;
        self.T_10.write(&mut writer)?;
        self.mu.write(&mut writer)?;
        self.tau_x.write(&mut writer)?;

        (self.l_x.len() as u64).write(&mut writer)?;
        for i in &self.l_x {
            i.write(&mut writer)?;
        }
        (self.r_x.len() as u64).write(&mut writer)?;
        for i in &self.r_x {
            i.write(&mut writer)?;
        }

        self.t_x.write(&mut writer)?;
        self.IPP.write(&mut writer)?;
        self.IPP_P.write(&mut writer)?;

        Ok(())
    }
}

impl<E: PairingEngine> FromBytes for Proof<E> {
    #[inline]
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let A_I = E::G1Affine::read(&mut reader)?;
        let A_O = E::G1Affine::read(&mut reader)?;
        let A_W = E::G1Affine::read(&mut reader)?;
        let S = E::G1Affine::read(&mut reader)?;
        let T_2 = E::G1Affine::read(&mut reader)?;
        let T_3 = E::G1Affine::read(&mut reader)?;
        let T_5 = E::G1Affine::read(&mut reader)?;
        let T_6 = E::G1Affine::read(&mut reader)?;
        let T_7 = E::G1Affine::read(&mut reader)?;
        let T_8 = E::G1Affine::read(&mut reader)?;
        let T_9 = E::G1Affine::read(&mut reader)?;
        let T_10 = E::G1Affine::read(&mut reader)?;
        let mu = E::Fr::read(&mut reader)?;
        let tau_x = E::Fr::read(&mut reader)?;

        let l_len = u64::read(&mut reader)?;
        let mut l_x = vec![];
        for _ in 0..l_len {
            let v = E::Fr::read(&mut reader)?;
            l_x.push(v);
        }

        let r_len = u64::read(&mut reader)?;
        let mut r_x = vec![];
        for _ in 0..r_len {
            let v = E::Fr::read(&mut reader)?;
            r_x.push(v);
        }

        let t_x = E::Fr::read(&mut reader)?;
        let IPP = inner_product_proof::Proof::<E>::read(&mut reader)?;
        let IPP_P = E::G1Projective::read(&mut reader)?;

        Ok(Self {
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
            IPP,
            IPP_P,
        })
    }
}

// very basic support for R1CS ConstraintSystem
// TODO: refactor this then we do not need to return Generators, R1csCircuit, and Assignment.
pub fn create_proof<E, C, R>(
    circuit: C,
    rng: &mut R,
) -> Result<(Generators<E>, R1csCircuit<E>, Proof<E>, Assignment<E>), SynthesisError>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: Rng,
{
    let mut prover = ProvingAssignment::<E> {
        at: vec![],
        bt: vec![],
        ct: vec![],
        input_assignment: vec![],
        aux_assignment: vec![],
    };

    // Allocate the "one" input variable
    prover.alloc_input(|| "", || Ok(E::Fr::one()))?;

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

    let mut CL: Vec<Vec<E::Fr>> = vec![vec![E::Fr::zero(); num_assignments]; num_constraints];
    let mut CR: Vec<Vec<E::Fr>> = vec![vec![E::Fr::zero(); num_assignments]; num_constraints];
    let mut CO: Vec<Vec<E::Fr>> = vec![vec![E::Fr::zero(); num_assignments]; num_constraints];

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

    let r1cs_circuit = R1csCircuit::<E> {
        CL,
        CR,
        CO,
        CL_T: Default::default(),
        CR_T: Default::default(),
        CO_T: Default::default(),
    };

    let aL = vector_matrix_product_t::<E>(&f, &r1cs_circuit.CL);
    let aR = vector_matrix_product_t::<E>(&f, &r1cs_circuit.CR);
    let aO = vector_matrix_product_t::<E>(&f, &r1cs_circuit.CO);

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
    let g_vec_N = create_generators::<E, _>(rng, N);
    let h_vec_N = create_generators::<E, _>(rng, N);
    let gh = create_generators::<E, _>(rng, 2);
    let g = gh[0];
    let h = gh[1];
    let u = E::G1Projective::rand(rng).into_affine();

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

    Ok((generators, r1cs_circuit, proof, input))
}

// bulletproofs arithmetic circuit proof with R1CS format
pub fn prove<E: PairingEngine, R>(
    gens: &Generators<E>,
    r1cs_circuit: &R1csCircuit<E>,
    input: &Assignment<E>,
    rng: &mut R,
) -> Proof<E>
where
    R: Rng,
{
    let mut transcript = Transcript::new(b"protocol3");

    let n = input.aL.len();
    assert_eq!(n, input.aR.len());
    assert_eq!(n, input.aO.len());

    let k = input.s.len();
    let n_w = input.w.len();

    // generators
    let mut g_vec: Vec<E::G1Affine> = vec![E::G1Affine::default(); n];
    let mut h_vec: Vec<E::G1Affine> = vec![E::G1Affine::default(); n];
    g_vec.copy_from_slice(&gens.g_vec_N[0..n]);
    h_vec.copy_from_slice(&gens.h_vec_N[0..n]);
    let g: E::G1Affine = gens.g;
    let h: E::G1Affine = gens.h;
    let mut g_vec_w: Vec<E::G1Affine> = vec![E::G1Affine::default(); n_w];
    g_vec_w.copy_from_slice(&gens.g_vec_N[0..n_w]);

    // choose blinding vectors sL, sR
    let n_max = cmp::max(n, n_w);
    let N = n_max.next_power_of_two(); // N must be greater than or equal to n & n_w
    transcript.append_u64(b"n", n as u64);
    transcript.append_u64(b"N", N as u64);
    let mut sL: Vec<E::Fr> = (0..n_max).map(|_| E::Fr::rand(rng)).collect();
    let mut sR: Vec<E::Fr> = (0..n_max).map(|_| E::Fr::rand(rng)).collect();

    // alpha, beta, rou, gamma
    let aIBlinding: E::Fr = E::Fr::rand(rng);
    let aOBlinding: E::Fr = E::Fr::rand(rng);
    let sBlinding: E::Fr = E::Fr::rand(rng);
    let gamma: E::Fr = E::Fr::rand(rng); // w blinding

    // commit aL, aR, aO, sL, sR
    // A_I = h^alpha g_vec^aL h_vec^aR
    let A_I_projective: E::G1Projective = quick_multiexp::<E>(&vec![aIBlinding], &vec![h])
        + &quick_multiexp::<E>(&input.aL, &g_vec)
        + &quick_multiexp::<E>(&input.aR, &h_vec);
    let A_O_projective: E::G1Projective =
        quick_multiexp::<E>(&vec![aOBlinding], &vec![h]) + &quick_multiexp::<E>(&input.aO, &g_vec);
    let A_W_projective: E::G1Projective =
        quick_multiexp::<E>(&vec![gamma], &vec![h]) + &quick_multiexp::<E>(&input.w, &g_vec_w);
    let A_I: E::G1Affine = A_I_projective.into_affine();
    let A_O: E::G1Affine = A_O_projective.into_affine();
    let A_W: E::G1Affine = A_W_projective.into_affine();

    let mut g_vec_max: Vec<E::G1Affine> = vec![E::G1Affine::default(); n_max];
    let mut h_vec_max: Vec<E::G1Affine> = vec![E::G1Affine::default(); n_max];
    g_vec_max.copy_from_slice(&gens.g_vec_N[0..n_max]);
    h_vec_max.copy_from_slice(&gens.h_vec_N[0..n_max]);

    let S_projective: E::G1Projective = quick_multiexp::<E>(&vec![sBlinding], &vec![h])
        + &quick_multiexp::<E>(&sL, &g_vec_max)
        + &quick_multiexp::<E>(&sR, &h_vec_max);
    let S: E::G1Affine = S_projective.into_affine();

    transcript.append_message(b"A_I", &math::to_bytes!(A_I).unwrap());
    transcript.append_message(b"A_O", &math::to_bytes!(A_O).unwrap());
    transcript.append_message(b"A_W", &math::to_bytes!(A_W).unwrap());
    transcript.append_message(b"S", &math::to_bytes!(S).unwrap());

    // V challenge y, z
    let mut buf_y = [0u8; 31];
    let mut buf_z = [0u8; 31];
    transcript.challenge_bytes(b"y", &mut buf_y);
    transcript.challenge_bytes(b"z", &mut buf_z);
    let y = random_bytes_to_fr::<E>(&buf_y);
    let z = random_bytes_to_fr::<E>(&buf_z);

    // padding
    let mut aL = input.aL.clone();
    let mut aR = input.aR.clone();
    let mut aO = input.aO.clone();
    let mut witness = input.w.clone();
    aL.resize_with(N, Default::default); // padding with E::Fr::zero()
    aR.resize_with(N, Default::default);
    aO.resize_with(N, Default::default);
    witness.resize_with(N, Default::default);
    sL.resize_with(N, Default::default);
    sR.resize_with(N, Default::default);

    // compute y, z vectors
    let mut y_n: Vec<E::Fr> = vec![E::Fr::zero(); N]; // challenge per witness
    for i in 0..N {
        if i == 0 {
            y_n[i] = E::Fr::one();
        } else {
            y_n[i] = y_n[i - 1] * &y;
        }
    }

    let mut y_n_inv: Vec<E::Fr> = vec![E::Fr::zero(); N];
    for i in 0..N {
        y_n_inv[i] = y_n[i].inverse().unwrap();
    }

    let mut z_Q: Vec<E::Fr> = vec![E::Fr::zero(); n]; // challenge per constraint
    for i in 0..n {
        if i == 0 {
            z_Q[i] = z;
        } else {
            z_Q[i] = z_Q[i - 1] * &z;
        }
    }

    // WL, WR, WO with padding
    let mut WL: Vec<Vec<E::Fr>> = vec![vec![E::Fr::zero(); N]; n]; // Qxn, Q=n, n=N
    let mut WR: Vec<Vec<E::Fr>> = vec![vec![E::Fr::zero(); N]; n]; // Qxn, Q=n, n=N
    let mut WO: Vec<Vec<E::Fr>> = vec![vec![E::Fr::zero(); N]; n]; // Qxn, Q=n, n=N
    let zn = z_Q[n - 1];
    let zn_sq = zn * &zn;
    for i in 0..n {
        WL[i][i] = E::Fr::one();
        WR[i][i] = zn * &(E::Fr::one());
        WO[i][i] = zn_sq * &(E::Fr::one());
    }

    // c, WV
    let m = k + n_w;
    let mut C1: Vec<Vec<E::Fr>> = vec![vec![E::Fr::zero(); k]; n];
    let mut WV = vec![vec![E::Fr::zero(); N]; n]; // C2
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
    let zQ_WL: Vec<E::Fr> = vector_matrix_product::<E>(&z_Q, &WL);
    let zQ_WR: Vec<E::Fr> = vector_matrix_product::<E>(&z_Q, &WR);
    let zQ_WO: Vec<E::Fr> = vector_matrix_product::<E>(&z_Q, &WO);
    let zQ_WV: Vec<E::Fr> = vector_matrix_product::<E>(&z_Q, &WV);

    let ynInvZQWR: Vec<E::Fr> = hadamard_product::<E>(&y_n_inv, &zQ_WR);

    let yn_HP_aR: Vec<E::Fr> = hadamard_product::<E>(&y_n, &aR);
    let yn_HP_sR: Vec<E::Fr> = hadamard_product::<E>(&y_n, &sR);

    // P compute l(X), r(X)
    let mut l_poly = VecPoly5::<E>::zero(N);
    let mut r_poly = VecPoly5::<E>::zero(N);
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

    let t_poly = VecPoly5::<E>::special_inner_product(&l_poly, &r_poly);

    // generate blinding factors for ti
    let tau_2: E::Fr = E::Fr::rand(rng);
    let tau_3: E::Fr = E::Fr::rand(rng);
    let tau_5: E::Fr = E::Fr::rand(rng);
    let tau_6: E::Fr = E::Fr::rand(rng);
    let tau_7: E::Fr = E::Fr::rand(rng);
    let tau_8: E::Fr = E::Fr::rand(rng);
    let tau_9: E::Fr = E::Fr::rand(rng);
    let tau_10: E::Fr = E::Fr::rand(rng);

    // commit t_i
    let T_2 = quick_multiexp::<E>(&vec![t_poly.t2, tau_2], &vec![g, h]).into_affine();
    let T_3 = quick_multiexp::<E>(&vec![t_poly.t3, tau_3], &vec![g, h]).into_affine();
    let T_5 = quick_multiexp::<E>(&vec![t_poly.t5, tau_5], &vec![g, h]).into_affine();
    let T_6 = quick_multiexp::<E>(&vec![t_poly.t6, tau_6], &vec![g, h]).into_affine();
    let T_7 = quick_multiexp::<E>(&vec![t_poly.t7, tau_7], &vec![g, h]).into_affine();
    let T_8 = quick_multiexp::<E>(&vec![t_poly.t8, tau_8], &vec![g, h]).into_affine();
    let T_9 = quick_multiexp::<E>(&vec![t_poly.t9, tau_9], &vec![g, h]).into_affine();
    let T_10 = quick_multiexp::<E>(&vec![t_poly.t10, tau_10], &vec![g, h]).into_affine();

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
    let x = random_bytes_to_fr::<E>(&buf_x);

    // P computes:
    let l_x: Vec<E::Fr> = l_poly.eval(x);
    let r_x: Vec<E::Fr> = r_poly.eval(x);

    let t_x = inner_product::<E>(&l_x, &r_x);

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
    let x_1 = random_bytes_to_fr::<E>(&buf_x_1);
    let ux = (gens.u.mul(x_1)).into_affine();

    let IPP_P = quick_multiexp::<E>(&l_x, &gens.g_vec_N)
        + &quick_multiexp::<E>(&r_x, &gens.h_vec_N)
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

pub fn verify_proof<E: PairingEngine>(
    gens: &Generators<E>,
    proof: &Proof<E>,
    r1cs_circuit: &R1csCircuit<E>,
    public_inputs: &[E::Fr],
) -> bool {
    let mut transcript = Transcript::new(b"protocol3");
    let zero = E::Fr::zero();
    let one = E::Fr::one();

    // generators
    let g_vec: Vec<E::G1Affine> = gens.g_vec_N.clone();
    let h_vec: Vec<E::G1Affine> = gens.h_vec_N.clone();
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
    let y = random_bytes_to_fr::<E>(&buf_y);
    let z = random_bytes_to_fr::<E>(&buf_z);

    // compute y, z vectors, and delta(y, z)
    let mut y_n: Vec<E::Fr> = vec![zero; gens.N]; // challenge per witness
    for i in 0..gens.N {
        if i == 0 {
            y_n[i] = one;
        } else {
            y_n[i] = y_n[i - 1] * &y;
        }
    }

    let mut y_n_inv: Vec<E::Fr> = vec![zero; gens.N];
    for i in 0..gens.N {
        y_n_inv[i] = y_n[i].inverse().unwrap();
    }

    let mut z_Q: Vec<E::Fr> = vec![zero; gens.n]; // challenge per constraint
    for i in 0..gens.n {
        if i == 0 {
            z_Q[i] = z;
        } else {
            z_Q[i] = z_Q[i - 1] * &z;
        }
    }

    let z_Q_neg: Vec<E::Fr> = (0..gens.n).map(|i| -one * &z_Q[i]).collect();

    //println!("gens.N: {}, gens.n: {}", gens.N, gens.n);
    // WL, WR, WO with padding
    //let mut WL: Vec<Vec<E::Fr>> = vec![vec![E::Fr::zero(); gens.N]; gens.n]; // Qxn, Q=n, n=N
    //let mut WR: Vec<Vec<E::Fr>> = vec![vec![E::Fr::zero(); gens.N]; gens.n]; // Qxn, Q=n, n=N
    //let mut WO: Vec<Vec<E::Fr>> = vec![vec![E::Fr::zero(); gens.N]; gens.n]; // Qxn, Q=n, n=Nw
    let mut WL: Vec<E::Fr> = vec![zero; gens.n]; // Qxn, Q=n, n=N
    let mut WR: Vec<E::Fr> = vec![zero; gens.n]; // Qxn, Q=n, n=N
    let mut WO: Vec<E::Fr> = vec![zero; gens.n]; // Qxn, Q=n, n=N

    let zn = z_Q[gens.n - 1];
    let zn_sq = zn * &zn;
    for i in 0..gens.n {
        //WL[i][i] = E::Fr::one();
        //WR[i][i] = zn * &(E::Fr::one());
        //WO[i][i] = zn_sq * &(E::Fr::one());
        WL[i] = one;
        WR[i] = zn * &one;
        WO[i] = zn_sq * &one;
    }

    // c, WV
    let m = gens.k + gens.n_w;
    let mut C1: Vec<Vec<E::Fr>> = vec![vec![zero; gens.k]; gens.n];
    //let mut WV: Vec<Vec<E::Fr>> = vec![vec![zero; gens.N]; gens.n]; // C2
    let mut WV: BTreeMap<(u32, u32), E::Fr> = BTreeMap::new();

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
    let c = vector_matrix_product_t::<E>(&public_inputs.to_vec(), &C1);

    // zQ * WL, zQ * WR
    let zQ_WL: Vec<E::Fr> = vector_product::<E>(&z_Q, &WL, gens.N, gens.n);
    let zQ_WR: Vec<E::Fr> = vector_product::<E>(&z_Q, &WR, gens.N, gens.n);
    let zQ_WO: Vec<E::Fr> = vector_product::<E>(&z_Q, &WO, gens.N, gens.n);
    let zQ_neg_WV: Vec<E::Fr> = vector_map_product::<E>(&z_Q_neg, &WV, gens.N);

    let ynInvZQWR: Vec<E::Fr> = hadamard_product::<E>(&y_n_inv, &zQ_WR);
    let delta_yz: E::Fr = inner_product::<E>(&ynInvZQWR, &zQ_WL);

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
    let x = random_bytes_to_fr::<E>(&buf_x);

    // V computes and checks:
    let h_vec_inv: Vec<E::G1Affine> = (0..gens.N)
        .map(|i| h_vec[i].mul(y_n_inv[i]).into_affine())
        .collect();

    let wL: E::G1Projective = quick_multiexp::<E>(&zQ_WL, &h_vec_inv);
    let wR: E::G1Projective = quick_multiexp::<E>(&ynInvZQWR, &g_vec);
    let wO: E::G1Projective = quick_multiexp::<E>(&zQ_WO, &h_vec_inv);
    let wV: E::G1Projective = quick_multiexp::<E>(&zQ_neg_WV, &h_vec_inv);

    transcript.append_message(b"t_x", &math::to_bytes!(proof.t_x).unwrap());
    transcript.append_message(b"tau_x", &math::to_bytes!(proof.tau_x).unwrap());
    transcript.append_message(b"mu", &math::to_bytes!(proof.mu).unwrap());
    let mut buf_x_1 = [0u8; 31];
    transcript.challenge_bytes(b"x_1", &mut buf_x_1); // notice: challenge x in protocol1 to avoid cheating from prover
    let x_1 = random_bytes_to_fr::<E>(&buf_x_1);
    let ux = (gens.u.mul(x_1)).into_affine();

    // check tx ?= <lx, rx>
    // USE IPP here
    // assert_eq!(proof.t_x, inner_product::<E>(&proof.l_x, &proof.r_x));
    if !inner_product_proof::verify(
        gens.g_vec_N.clone(),
        gens.h_vec_N.clone(),
        ux,
        &proof.IPP_P,
        &proof.IPP,
    ) {
        return false;
    }

    // check ti
    let checkT_lhs: E::G1Projective =
        quick_multiexp::<E>(&vec![proof.t_x, proof.tau_x], &vec![g, h]);

    let zQ_c = inner_product::<E>(&z_Q, &c);

    let xx = x * &x;
    let xxxx = xx * &xx;
    let checkT_rhs: E::G1Projective =
        quick_multiexp::<E>(&vec![xxxx * &(delta_yz + &zQ_c)], &vec![g])
            + &proof.T_2.mul(xx)
            + &proof.T_3.mul(xx * &x)
            + &proof.T_5.mul(xxxx * &x)
            + &proof.T_6.mul(xxxx * &xx)
            + &proof.T_7.mul(xxxx * &(xx * &x))
            + &proof.T_8.mul(xxxx * &xxxx)
            + &proof.T_9.mul(xxxx * &(xxxx * &x))
            + &proof.T_10.mul(xxxx * &(xxxx * &xx));

    assert_eq!(checkT_lhs, checkT_rhs);

    let y_n_neg: Vec<E::Fr> = (0..gens.N).map(|i| -one * &y_n[i]).collect();
    let P = proof.A_I.mul(xx)
        + &proof.A_O.mul(xx * &x)
        + &proof.A_W.mul(xxxx)
        + &(quick_multiexp::<E>(&y_n_neg, &h_vec_inv).mul(x))
        + &wL.mul(xx)
        + &wR.mul(xx)
        + &wO.mul(x)
        + &wV
        + &proof.S.mul(xxxx * &x);
    let checkP = h.mul(proof.mu)
        + &quick_multiexp::<E>(&proof.l_x, &g_vec)
        + &quick_multiexp::<E>(&proof.r_x, &h_vec_inv);

    P == checkP
}

pub fn create_generators<E: PairingEngine, R: Rng>(rng: &mut R, len: usize) -> Vec<E::G1Affine> {
    let mut generators = Vec::new();
    for _ in 0..len {
        generators.push(E::G1Projective::rand(rng).into_affine());
    }
    generators
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve::{Bls12_381, Bn_256};

    fn run_protocol3_r1cs_helper<E: PairingEngine>(
        CL: Vec<Vec<E::Fr>>,
        CR: Vec<Vec<E::Fr>>,
        CO: Vec<Vec<E::Fr>>,
        statement: Vec<E::Fr>,
        witness: Vec<E::Fr>,
    ) {
        let rng = &mut math::test_rng();
        let r1cs_circuit = R1csCircuit::<E> {
            CL,
            CR,
            CO,
            CL_T: Default::default(),
            CR_T: Default::default(),
            CO_T: Default::default(),
        };

        let f = [&statement[..], &witness[..]].concat();
        let aL = vector_matrix_product_t::<E>(&f, &r1cs_circuit.CL);
        let aR = vector_matrix_product_t::<E>(&f, &r1cs_circuit.CR);
        let aO = vector_matrix_product_t::<E>(&f, &r1cs_circuit.CO);

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
        let g_vec_N = create_generators::<E, _>(rng, N);
        let h_vec_N = create_generators::<E, _>(rng, N);
        let gh = create_generators::<E, _>(rng, 2);
        let g = gh[0];
        let h = gh[1];
        let u = E::G1Projective::rand(rng).into_affine();

        let n = input.aL.len();
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

        verify_proof(&generators, &proof, &r1cs_circuit, &input.s);
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
    fn vitalik_problem_r1cs_succeed<E: PairingEngine>() {
        let zer = E::Fr::zero();
        let one = E::Fr::one();

        let CL: Vec<Vec<E::Fr>> = vec![
            vec![zer, zer, one, zer, zer, zer],
            vec![zer, zer, zer, one, zer, zer],
            vec![zer, zer, one, zer, one, zer],
            vec![E::Fr::from(5u8), zer, zer, zer, zer, one],
        ];
        let CR: Vec<Vec<E::Fr>> = vec![
            vec![zer, zer, one, zer, zer, zer],
            vec![zer, zer, one, zer, zer, zer],
            vec![one, zer, zer, zer, zer, zer],
            vec![one, zer, zer, zer, zer, zer],
        ];
        let CO: Vec<Vec<E::Fr>> = vec![
            vec![zer, zer, zer, one, zer, zer],
            vec![zer, zer, zer, zer, one, zer],
            vec![zer, zer, zer, zer, zer, one],
            vec![zer, one, zer, zer, zer, zer],
        ];
        let statement: Vec<E::Fr> = vec![one, E::Fr::from(35u8)];
        let witness: Vec<E::Fr> = vec![
            E::Fr::from(3u8),
            E::Fr::from(9u8),
            E::Fr::from(27u8),
            E::Fr::from(30u8),
        ];

        run_protocol3_r1cs_helper::<E>(CL, CR, CO, statement, witness);
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
    fn mul_circuit_1_r1cs_succeed<E: PairingEngine>() {
        let zer = E::Fr::zero();
        let one = E::Fr::one();

        let CL: Vec<Vec<E::Fr>> = vec![vec![zer, one, zer, zer]];
        let CR: Vec<Vec<E::Fr>> = vec![vec![zer, zer, one, zer]];
        let CO: Vec<Vec<E::Fr>> = vec![vec![zer, zer, zer, one]];
        let statement: Vec<E::Fr> = vec![one];
        let witness: Vec<E::Fr> = vec![E::Fr::from(2u8), E::Fr::from(3u8), E::Fr::from(6u8)];

        run_protocol3_r1cs_helper::<E>(CL, CR, CO, statement, witness);
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
    fn mul_circuit_3_r1cs_succeed<E: PairingEngine>() {
        let zer = E::Fr::zero();
        let one = E::Fr::one();

        let CL: Vec<Vec<E::Fr>> = vec![
            vec![zer, one, zer, zer, zer, zer, zer, zer, zer, zer],
            vec![zer, zer, zer, zer, one, zer, zer, zer, zer, zer],
            vec![zer, zer, zer, zer, zer, zer, zer, one, zer, zer],
        ];
        let CR: Vec<Vec<E::Fr>> = vec![
            vec![zer, zer, one, zer, zer, zer, zer, zer, zer, zer],
            vec![zer, zer, zer, zer, zer, one, zer, zer, zer, zer],
            vec![zer, zer, zer, zer, zer, zer, zer, zer, one, zer],
        ];
        let CO: Vec<Vec<E::Fr>> = vec![
            vec![zer, zer, zer, one, zer, zer, zer, zer, zer, zer],
            vec![zer, zer, zer, zer, zer, zer, one, zer, zer, zer],
            vec![zer, zer, zer, zer, zer, zer, zer, zer, zer, one],
        ];
        let statement: Vec<E::Fr> = vec![one];
        let witness: Vec<E::Fr> = vec![
            E::Fr::from(2u8),
            E::Fr::from(3u8),
            E::Fr::from(6u8),
            one,
            E::Fr::from(4u8),
            E::Fr::from(4u8),
            E::Fr::from(3u8),
            E::Fr::from(5u8),
            E::Fr::from(15u8),
        ];

        run_protocol3_r1cs_helper::<E>(CL, CR, CO, statement, witness);
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
    fn shuffle_circuit_r1cs_succeed<E: PairingEngine>() {
        let rng = &mut math::test_rng();

        let zer = E::Fr::zero();
        let one = E::Fr::one();
        let zx: E::Fr = E::Fr::rand(rng);
        // (a - x)(b - x) = (c - x)(d - x)
        let CL: Vec<Vec<E::Fr>> = vec![
            vec![-zx, one, zer, zer, zer, zer, zer],
            vec![-zx, zer, zer, one, zer, zer, zer],
            vec![zer, zer, zer, zer, zer, one, -one],
        ];
        let CR: Vec<Vec<E::Fr>> = vec![
            vec![-zx, zer, one, zer, zer, zer, zer],
            vec![-zx, zer, zer, zer, one, zer, zer],
            vec![one, zer, zer, zer, zer, zer, zer],
        ];
        let CO: Vec<Vec<E::Fr>> = vec![
            vec![zer, zer, zer, zer, zer, one, zer],
            vec![zer, zer, zer, zer, zer, zer, one],
            vec![zer, zer, zer, zer, zer, zer, zer],
        ];
        let statement: Vec<E::Fr> = vec![one];
        let three = E::Fr::from(3u8);
        let seven = E::Fr::from(7u8);
        let witness: Vec<E::Fr> = vec![
            three,
            seven,
            seven,
            three,
            (three - &zx) * &(seven - &zx),
            (seven - &zx) * &(three - &zx),
        ];

        run_protocol3_r1cs_helper::<E>(CL, CR, CO, statement, witness);
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
    fn add_circuit_succeed<E: PairingEngine>() {
        let zer = E::Fr::zero();
        let one = E::Fr::one();

        let CL: Vec<Vec<E::Fr>> = vec![vec![zer, one, one, zer]];
        let CR: Vec<Vec<E::Fr>> = vec![vec![one, zer, zer, zer]];
        let CO: Vec<Vec<E::Fr>> = vec![vec![zer, zer, zer, one]];
        let statement: Vec<E::Fr> = vec![one];
        let witness: Vec<E::Fr> = vec![E::Fr::from(4u8), E::Fr::from(5u8), E::Fr::from(9u8)];

        run_protocol3_r1cs_helper::<E>(CL, CR, CO, statement, witness);
    }
}
