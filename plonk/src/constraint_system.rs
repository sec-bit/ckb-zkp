use ark_ff::Field;

use crate::{BTreeMap, Vec};

mod arithmetic;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct Variable(usize);

#[derive(Debug)]
pub enum Error {
    ComposerError,
}

#[derive(Debug)]
pub enum Wire {
    W0(usize),
    W1(usize),
    W2(usize),
    W3(usize),
}

#[derive(Debug)]
pub struct Permutation {
    variables: BTreeMap<Variable, Vec<Wire>>,
}

impl Permutation {
    pub fn new() -> Self {
        Permutation {
            variables: BTreeMap::new(),
        }
    }

    pub fn alloc(&mut self) -> Variable {
        let var = Variable(self.variables.len());
        self.variables.insert(var, Vec::new());

        var
    }

    pub fn add_variable(&mut self, var: Variable, wire: Wire) {
        let wires = self.variables.get_mut(&var).unwrap();
        wires.push(wire);
    }
}

#[derive(Debug)]
pub struct Composer<F: Field> {
    n: usize,

    q_0: Vec<F>,
    q_1: Vec<F>,
    q_2: Vec<F>,
    q_3: Vec<F>,
    q_m: Vec<F>,
    q_c: Vec<F>,
    pi: Vec<F>,

    q_arith: Vec<F>,

    null_var: Variable,
    permutation: Permutation,
    assignments: BTreeMap<Variable, F>,
}

impl<F: Field> Composer<F> {
    pub fn new() -> Self {
        let mut cs = Composer {
            n: 0,

            q_0: Vec::new(),
            q_1: Vec::new(),
            q_2: Vec::new(),
            q_3: Vec::new(),
            q_m: Vec::new(),
            q_c: Vec::new(),
            pi: Vec::new(),

            q_arith: Vec::new(),

            null_var: Variable(0),
            permutation: Permutation::new(),
            assignments: BTreeMap::new(),
        };
        cs.null_var = cs.add_variable(F::zero());

        cs
    }

    pub fn add_variable(&mut self, value: F) -> Variable {
        let var = self.permutation.alloc();
        self.assignments.insert(var, value);

        var
    }
}
