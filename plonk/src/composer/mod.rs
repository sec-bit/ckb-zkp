use ark_ff::FftField as Field;

use crate::{Map, Vec};

mod permutation;
use permutation::Permutation;

mod selectors;

mod arithmetic;

#[derive(Debug)]
pub enum Error {
    PolynomialDegreeTooLarge,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
pub struct Variable(usize);

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
    assignments: Map<Variable, F>,
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
            assignments: Map::new(),
        };
        cs.null_var = cs.alloc_and_assign(F::zero());

        cs
    }

    pub fn alloc_and_assign(&mut self, value: F) -> Variable {
        let var = self.permutation.alloc();
        self.assignments.insert(var, value);

        var
    }
}
