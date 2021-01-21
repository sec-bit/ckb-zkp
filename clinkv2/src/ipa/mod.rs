use ark_ff::Field;
use core::marker::PhantomData;
use digest::Digest;
use zkp_curve::Curve;

pub mod ipa;
pub mod prover;
pub mod verifier;

pub use ipa::InnerProductArgPC;
pub use prover::create_random_proof;
pub use verifier::verify_proof;
pub type ProveKey<G> = ipa::CommitterKey<G>;
pub type VerifyKey<G> = ipa::VerifierKey<G>;

use crate::{String, Vec};

use crate::r1cs::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};

type IPAPC<G, D> = InnerProductArgPC<G, D>;
type IPAProof<G> = ipa::Proof<G>;
type IPAComm<G> = ipa::Commitment<G>;

/// The proof in Clinkv2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<G: Curve> {
    pub r_mid_comms: Vec<IPAComm<G>>,
    pub q_comm: IPAComm<G>,
    pub r_mid_q_values: Vec<G::Fr>,
    pub r_mid_q_proof: IPAProof<G>,
    pub opening_challenge: G::Fr,
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
