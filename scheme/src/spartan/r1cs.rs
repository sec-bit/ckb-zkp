use crate::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable,
};
use crate::{String, Vec};
use math::{log2, Field, One, PairingEngine, Zero};
use std::collections::HashMap;
// use std::time::{Duration, Instant};

pub struct R1CSInstance<E: PairingEngine> {
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_constraints: usize,
    pub a_matrix: Vec<Vec<(E::Fr, Index)>>,
    pub b_matrix: Vec<Vec<(E::Fr, Index)>>,
    pub c_matrix: Vec<Vec<(E::Fr, Index)>>,
}

impl<E: PairingEngine> ConstraintSystem<E::Fr> for R1CSInstance<E> {
    type Root = Self;

    #[inline]
    fn alloc<F, A, AR>(&mut self, _: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        // There is no assignment, so we don't invoke the
        // function for obtaining one.

        let index = self.num_aux;
        self.num_aux += 1;

        Ok(Variable::new_unchecked(Index::Aux(index)))
    }

    #[inline]
    fn alloc_input<F, A, AR>(&mut self, _: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        // There is no assignment, so we don't invoke the
        // function for obtaining one.

        let index = self.num_inputs;
        self.num_inputs += 1;

        Ok(Variable::new_unchecked(Index::Input(index)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
        LB: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
        LC: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
    {
        self.a_matrix.push(vec![]);
        self.b_matrix.push(vec![]);
        self.c_matrix.push(vec![]);

        push_constraints(
            a(LinearCombination::zero()),
            &mut self.a_matrix,
            self.num_constraints,
        );
        push_constraints(
            b(LinearCombination::zero()),
            &mut self.b_matrix,
            self.num_constraints,
        );
        push_constraints(
            c(LinearCombination::zero()),
            &mut self.c_matrix,
            self.num_constraints,
        );

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

pub fn generate_r1cs<E: PairingEngine, C: ConstraintSynthesizer<E::Fr>>(
    circuit: C,
) -> Result<R1CSInstance<E>, SynthesisError> {
    let mut r1cs = R1CSInstance {
        num_inputs: 0,
        num_aux: 0,
        num_constraints: 0,
        a_matrix: vec![],
        b_matrix: vec![],
        c_matrix: vec![],
    };

    // Allocate the "one" input variable
    r1cs.alloc_input(|| "", || Ok(E::Fr::one()))?;
    // Synthesize the circuit.
    circuit.generate_constraints(&mut r1cs)?;
    let num_constraints_t = (2usize).pow(log2(r1cs.num_constraints));

    for i in 0..num_constraints_t - r1cs.num_constraints {
        r1cs.enforce(
            || format!("append constraint {}", i),
            |lc| lc,
            |lc| lc,
            |lc| lc,
        );
    }

    assert_eq!(
        (2usize).pow(log2(r1cs.num_constraints)),
        r1cs.num_constraints
    );
    Ok(r1cs)
}

pub fn switch_matrix_to_list<E: PairingEngine>(
    m_matrix: &Vec<Vec<(E::Fr, Index)>>,
    witness_len: usize,
) -> Result<(Vec<E::Fr>, Vec<usize>, Vec<usize>), SynthesisError> {
    let mut vals = Vec::new();
    let mut rows = Vec::new();
    let mut cols = Vec::new();

    for (row, m_vec) in m_matrix.iter().enumerate() {
        let mut ms = HashMap::new();
        for (val, col) in m_vec.iter() {
            match col {
                Index::Aux(i) => {
                    if let Some(x) = ms.get_mut(i) {
                        *x = *val + *x;
                    } else {
                        ms.insert(*i, *val);
                    }
                }
                Index::Input(i) => {
                    if let Some(x) = ms.get_mut(&(*i + witness_len)) {
                        *x = *val + *x;
                    } else {
                        ms.insert(*i + witness_len, *val);
                    }
                }
            }
        }
        for (col, val) in ms.iter() {
            if !val.is_zero() {
                rows.push(row);
                cols.push(*col);
                vals.push(*val);
            }
        }
    }

    Ok((vals, rows, cols))
}
