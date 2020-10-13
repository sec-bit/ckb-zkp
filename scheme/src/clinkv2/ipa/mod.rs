use core::marker::PhantomData;
use digest::Digest;
use math::{
    io::{self, Result as IoResult},
    serialize::*,
    Curve, Field, FromBytes, ToBytes,
};
use rand::Rng;

pub mod ipa;
pub mod prover;
pub mod verifier;

pub use ipa::InnerProductArgPC;
pub use prover::create_random_proof;
pub use verifier::verify_proof;
pub type ProveKey<G> = ipa::CommitterKey<G>;
pub type VerifyKey<G> = ipa::VerifierKey<G>;

use crate::{String, Vec};

use super::r1cs::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};

type IPAPC<G, D> = InnerProductArgPC<G, D>;
type IPAProof<G> = ipa::Proof<G>;
type IPAComm<G> = ipa::Commitment<G>;

/// standard interface for create proof and to bytes.
pub fn prove_to_bytes<G: Curve, D: Digest, R: Rng>(
    assignment: &ProveAssignment<G, D>,
    pk: &ProveKey<G>,
    rng: &mut R,
    publics: &Vec<Vec<G::Fr>>,
) -> Result<(Vec<u8>, Vec<u8>), SynthesisError> {
    let proof = create_random_proof(assignment, pk, rng)?;
    let mut proof_bytes = vec![];
    proof.write(&mut proof_bytes)?;
    let mut publics_bytes = vec![];
    (publics.len() as u32).write(&mut publics_bytes)?;
    for i in publics {
        (i.len() as u32).write(&mut publics_bytes)?;
        for j in i {
            j.write(&mut publics_bytes)?;
        }
    }

    Ok((proof_bytes, publics_bytes))
}

/// standard interface for verify proof from bytes.
pub fn verify_from_bytes<G: Curve, D: Digest>(
    assignment: &VerifyAssignment<G, D>,
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    mut publics_bytes: &[u8],
) -> Result<bool, SynthesisError> {
    let vk = VerifyKey::read(vk_bytes)?;
    let proof = Proof::read(proof_bytes)?;
    let mut publics = vec![];
    let publics_len = u32::read(&mut publics_bytes)?;
    for _ in 0..publics_len {
        let i = u32::read(&mut publics_bytes)?;
        let mut tmp_publics = vec![];
        for _ in 0..i {
            tmp_publics.push(G::Fr::read(&mut publics_bytes)?);
        }
        publics.push(tmp_publics);
    }

    verify_proof::<G, D>(assignment, &vk, &proof, &publics)
}

/// The proof in Clinkv2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<G: Curve> {
    pub r_mid_comms: Vec<IPAComm<G>>,
    pub q_comm: IPAComm<G>,
    pub r_mid_q_values: Vec<G::Fr>,
    pub r_mid_q_proof: IPAProof<G>,
    pub opening_challenge: G::Fr,
}

impl<G: Curve> ToBytes for Proof<G> {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        (self.r_mid_comms.len() as u32).write(&mut writer)?;
        for i in &self.r_mid_comms {
            i.write(&mut writer)?;
        }
        self.q_comm.write(&mut writer)?;
        (self.r_mid_q_values.len() as u32).write(&mut writer)?;
        for i in &self.r_mid_q_values {
            i.write(&mut writer)?;
        }
        self.r_mid_q_proof.write(&mut writer)?;
        self.opening_challenge.write(&mut writer)
    }
}

impl<G: Curve> FromBytes for Proof<G> {
    #[inline]
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let mut r_mid_comms = vec![];
        let r_mid_comms_len = u32::read(&mut reader)?;
        for _ in 0..r_mid_comms_len {
            r_mid_comms.push(IPAComm::read(&mut reader)?);
        }
        let q_comm = IPAComm::read(&mut reader)?;
        let mut r_mid_q_values = vec![];
        let r_mid_q_values_len = u32::read(&mut reader)?;
        for _ in 0..r_mid_q_values_len {
            r_mid_q_values.push(G::Fr::read(&mut reader)?);
        }
        let r_mid_q_proof = IPAProof::read(&mut reader)?;
        let opening_challenge = G::Fr::read(&mut reader)?;

        let proof = Self {
            r_mid_comms,
            q_comm,
            r_mid_q_values,
            r_mid_q_proof,
            opening_challenge,
        };

        Ok(proof)
    }
}

fn push_constraints<F: Field>(
    l: LinearCombination<F>,
    constraints: &mut [Vec<(F, Index)>],
    this_constraint: usize,
) {
    for (var, coeff) in l.as_ref() {
        match var.get_unchecked() {
            Index::Input(i) => constraints[this_constraint].push((*coeff, Index::Input(i))),
            Index::Aux(i) => constraints[this_constraint].push((*coeff, Index::Aux(i))),
        }
    }
}

pub struct ProveAssignment<G: Curve, D: Digest> {
    // Constraints
    pub at: Vec<Vec<(G::Fr, Index)>>,
    pub bt: Vec<Vec<(G::Fr, Index)>>,
    pub ct: Vec<Vec<(G::Fr, Index)>>,

    // Assignments of variables
    // Two-demension vector
    pub input_assignment: Vec<Vec<G::Fr>>,
    pub aux_assignment: Vec<Vec<G::Fr>>,

    pub(crate) io_cur: usize,
    pub(crate) aux_cur: usize,
    _digest: PhantomData<D>,
}

impl<G: Curve, D: Digest> Default for ProveAssignment<G, D> {
    fn default() -> ProveAssignment<G, D> {
        ProveAssignment {
            at: vec![],
            bt: vec![],
            ct: vec![],
            input_assignment: vec![],
            aux_assignment: vec![],
            io_cur: 0usize,
            aux_cur: 0usize,
            _digest: PhantomData::<D>,
        }
    }
}

impl<G: Curve, D: Digest> ConstraintSystem<G::Fr> for ProveAssignment<G, D> {
    type Root = Self;

    #[inline]
    fn alloc<F, A, AR>(&mut self, _: A, f: F, i: usize) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<G::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        if i == 0 {
            if self.aux_assignment.len() == 0 {
                self.aux_cur = 0;
            }
            let mut aux_varj_vec = vec![];
            aux_varj_vec.push(f()?);
            self.aux_assignment.push(aux_varj_vec);
            let index = self.aux_cur;
            self.aux_cur += 1;
            Ok(Variable::new_unchecked(Index::Aux(index)))
        } else {
            if i == self.aux_assignment[0].len() {
                self.aux_cur = 0;
            }
            self.aux_assignment[self.aux_cur].push(f()?);
            let index = self.aux_cur;
            self.aux_cur += 1;
            Ok(Variable::new_unchecked(Index::Aux(index)))
        }
    }

    #[inline]
    fn alloc_input<F, A, AR>(&mut self, _: A, f: F, i: usize) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<G::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        if i == 0 {
            if self.input_assignment.len() == 0 {
                self.io_cur = 0;
            }
            let mut io_varj_vec = vec![];
            io_varj_vec.push(f()?);
            self.input_assignment.push(io_varj_vec);
            let index = self.io_cur;
            self.io_cur += 1;
            Ok(Variable::new_unchecked(Index::Input(index)))
        } else {
            if i == self.input_assignment[0].len() {
                self.io_cur = 0;
            }
            self.input_assignment[self.io_cur].push(f()?);
            let index = self.io_cur;
            self.io_cur += 1;
            Ok(Variable::new_unchecked(Index::Input(index)))
        }
    }

    #[inline]
    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<G::Fr>) -> LinearCombination<G::Fr>,
        LB: FnOnce(LinearCombination<G::Fr>) -> LinearCombination<G::Fr>,
        LC: FnOnce(LinearCombination<G::Fr>) -> LinearCombination<G::Fr>,
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

pub struct VerifyAssignment<G: Curve, D: Digest> {
    // Constraints
    pub at: Vec<Vec<(G::Fr, Index)>>,
    pub bt: Vec<Vec<(G::Fr, Index)>>,
    pub ct: Vec<Vec<(G::Fr, Index)>>,

    // Assignments of variables
    // Two-demension vector
    pub input_assignment: Vec<Vec<G::Fr>>,
    pub aux_assignment: Vec<Vec<G::Fr>>,

    pub(crate) io_cur: usize,
    pub(crate) aux_cur: usize,

    _digest: PhantomData<D>,
}

impl<G: Curve, D: Digest> Default for VerifyAssignment<G, D> {
    fn default() -> VerifyAssignment<G, D> {
        VerifyAssignment {
            at: vec![],
            bt: vec![],
            ct: vec![],
            input_assignment: vec![],
            aux_assignment: vec![],
            io_cur: 0usize,
            aux_cur: 0usize,
            _digest: PhantomData::<D>,
        }
    }
}

impl<G: Curve, D: Digest> ConstraintSystem<G::Fr> for VerifyAssignment<G, D> {
    type Root = Self;

    #[inline]
    fn alloc<F, A, AR>(&mut self, _: A, _f: F, _i: usize) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<G::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.aux_cur;
        self.aux_cur += 1;
        Ok(Variable::new_unchecked(Index::Aux(index)))
    }

    #[inline]
    fn alloc_input<F, A, AR>(&mut self, _: A, _f: F, _i: usize) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<G::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.io_cur;
        self.io_cur += 1;
        Ok(Variable::new_unchecked(Index::Input(index)))
    }

    #[inline]
    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<G::Fr>) -> LinearCombination<G::Fr>,
        LB: FnOnce(LinearCombination<G::Fr>) -> LinearCombination<G::Fr>,
        LC: FnOnce(LinearCombination<G::Fr>) -> LinearCombination<G::Fr>,
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
