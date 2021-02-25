use ark_ff::FftField as Field;
use ark_std::vec::Vec;

use crate::Map;

mod permutation;
use permutation::Permutation;

mod arithmetic;

mod synthesize;
pub use synthesize::Selectors;

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

    w_0: Vec<Variable>,
    w_1: Vec<Variable>,
    w_2: Vec<Variable>,
    w_3: Vec<Variable>,

    null_var: Variable,
    permutation: Permutation<F>,
    assignment: Map<Variable, F>,
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

            w_0: Vec::new(),
            w_1: Vec::new(),
            w_2: Vec::new(),
            w_3: Vec::new(),

            null_var: Variable(0),
            permutation: Permutation::new(),
            assignment: Map::new(),
        };
        cs.null_var = cs.alloc_and_assign(F::zero());

        cs
    }

    pub fn size(&self) -> usize {
        self.n
    }

    pub fn alloc_and_assign(&mut self, value: F) -> Variable {
        let var = self.permutation.alloc();
        self.assignment.insert(var, value);

        var
    }
}

#[cfg(test)]
mod test {
    use ark_bls12_381::Fr;
    use ark_ff::{One, Zero};

    use super::*;

    #[test]
    fn preprocess() {
        let ks = [
            Fr::one(),
            Fr::from(7_u64),
            Fr::from(13_u64),
            Fr::from(17_u64),
        ];
        let mut cs = Composer::new();
        let one = Fr::one();
        let two = one + one;
        let three = two + one;
        let four = two + two;
        let var_one = cs.alloc_and_assign(one);
        let var_two = cs.alloc_and_assign(two);
        let var_three = cs.alloc_and_assign(three);
        let var_four = cs.alloc_and_assign(four);
        cs.create_add_gate(
            (var_one, one),
            (var_two, one),
            var_three,
            None,
            Fr::zero(),
            Fr::zero(),
        );
        cs.create_add_gate(
            (var_two, one),
            (var_two, one),
            var_four,
            None,
            Fr::zero(),
            Fr::zero(),
        );
        cs.create_mul_gate(
            var_one,
            var_two,
            var_two,
            None,
            Fr::one(),
            Fr::zero(),
            Fr::zero(),
        );
        cs.preprocess(&ks).unwrap();
    }
}
