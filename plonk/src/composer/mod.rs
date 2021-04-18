use ark_ff::FftField as Field;
use ark_std::vec::Vec;

use crate::Map;

mod permutation;
use permutation::Permutation;

mod arithmetic;

mod synthesize;
pub use synthesize::{Error, Selectors, Witnesses};

#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash, Ord, PartialOrd)]
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

    q_arith: Vec<F>,

    pi: Vec<F>,

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
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::{One, UniformRand, Zero};
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    use ark_std::test_rng;

    use crate::utils::pad_to_size;

    use super::*;

    #[test]
    fn compose() {
        let cs = crate::tests::circuit();
        let ks = [
            Fr::one(),
            Fr::from(7_u64),
            Fr::from(13_u64),
            Fr::from(17_u64),
        ];

        let s = cs.compose(&ks).unwrap();
        let pi = pad_to_size(cs.public_inputs(), s.size());

        let witnesses = cs.synthesize().unwrap();
        let Witnesses { w_0, w_1, w_2, w_3 } = witnesses;
        assert_eq!(w_0.len(), s.q_0.len());

        // arithmetic
        (0..s.size()).into_iter().for_each(|i| {
            assert_eq!(
                Fr::zero(),
                w_0[i] * s.q_0[i]
                    + w_1[i] * s.q_1[i]
                    + w_2[i] * s.q_2[i]
                    + w_3[i] * s.q_3[i]
                    + w_1[i] * w_2[i] * s.q_m[i]
                    + s.q_c[i]
                    + pi[i]
            )
        });

        // permutation
        let ks = [
            Fr::one(),
            Fr::from(7_u64),
            Fr::from(13_u64),
            Fr::from(17_u64),
        ];
        let domain_n = GeneralEvaluationDomain::<Fr>::new(cs.size()).unwrap();
        let roots: Vec<_> = domain_n.elements().collect();
        let rng = &mut test_rng();
        let beta = Fr::rand(rng);
        let gamma = Fr::rand(rng);

        let numerator: Fr = (0..s.size())
            .into_iter()
            .map(|i| {
                (w_0[i] + beta * roots[i] * ks[0] + gamma)
                    * (w_1[i] + beta * roots[i] * ks[1] + gamma)
                    * (w_2[i] + beta * roots[i] * ks[2] + gamma)
                    * (w_3[i] + beta * roots[i] * ks[3] + gamma)
            })
            .product();

        let denumerator: Fr = (0..s.size())
            .into_iter()
            .map(|i| {
                (w_0[i] + beta * s.sigma_0[i] + gamma)
                    * (w_1[i] + beta * s.sigma_1[i] + gamma)
                    * (w_2[i] + beta * s.sigma_2[i] + gamma)
                    * (w_3[i] + beta * s.sigma_3[i] + gamma)
            })
            .product();
        assert_eq!(numerator, denumerator);
    }
}
