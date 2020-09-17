use math::{Field, PairingEngine};

pub mod kzg10;
pub mod prover;
pub mod r1cs;
pub mod verifier;

pub use prover::create_proof;
pub use verifier::verify_proof;
pub type VerifyKey<E> = kzg10::VerifierKey<E>;
pub type ProveKey<'a, E> = kzg10::Powers<'a, E>;

use crate::Vec;

use r1cs::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};

pub type Kzg10Proof<E> = kzg10::Proof<E>;
pub type Kzg10Comm<E> = kzg10::Commitment<E>;

/// The proof in Clinkv2.
#[derive(Clone, Debug)]
pub struct Proof<E: PairingEngine> {
    pub r_mid_comms: Vec<Kzg10Comm<E>>,
    pub q_comm: Kzg10Comm<E>,
    pub r_mid_q_values: Vec<E::Fr>,
    pub r_mid_q_proof: Kzg10Proof<E>,
    opening_challenge: E::Fr,
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

// #[derive(Default)]
pub struct ProvingAssignment<E: PairingEngine> {
    // Constraints
    pub at: Vec<Vec<(E::Fr, Index)>>,
    pub bt: Vec<Vec<(E::Fr, Index)>>,
    pub ct: Vec<Vec<(E::Fr, Index)>>,

    // Assignments of variables
    // Two-demension vector
    pub input_assignment: Vec<Vec<E::Fr>>,
    pub aux_assignment: Vec<Vec<E::Fr>>,

    pub(crate) io_cur: usize,
    pub(crate) aux_cur: usize,
}

impl<E: PairingEngine> Default for ProvingAssignment<E> {
    fn default() -> ProvingAssignment<E> {
        ProvingAssignment {
            at: vec![],
            bt: vec![],
            ct: vec![],
            input_assignment: vec![],
            aux_assignment: vec![],
            io_cur: 0usize,
            aux_cur: 0usize,
        }
    }
}

// TODO need del.
fn as_bytes<T>(x: &T) -> &[u8] {
    use core::mem;
    use core::slice;

    unsafe { slice::from_raw_parts(x as *const T as *const u8, mem::size_of_val(x)) }
}

impl<E: PairingEngine> ConstraintSystem<E::Fr> for ProvingAssignment<E> {
    type Root = Self;

    #[inline]
    fn alloc<F, A, AR>(&mut self, _: A, f: F, i: usize) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
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
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
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
