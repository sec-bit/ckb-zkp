use ark_poly::EvaluationDomain;
use ark_std::{cfg_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use core::marker::PhantomData;

use crate::composer::{Field, Variable};
use crate::Map;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum Wire {
    W0(usize),
    W1(usize),
    W2(usize),
    W3(usize),
}

#[derive(Debug)]
pub(crate) struct Permutation<F: Field> {
    variable_map: Map<Variable, Vec<Wire>>,
    _field: PhantomData<F>,
}

impl<F: Field> Permutation<F> {
    pub fn new() -> Self {
        Permutation {
            variable_map: Map::new(),
            _field: PhantomData,
        }
    }

    pub fn alloc(&mut self) -> Variable {
        let var = Variable(self.variable_map.len());
        self.variable_map.insert(var, Vec::new());

        var
    }

    pub fn insert_gate(
        &mut self,
        w_0: Variable,
        w_1: Variable,
        w_2: Variable,
        w_3: Variable,
        index: usize,
    ) {
        self.add_to_map(w_0, Wire::W0(index));
        self.add_to_map(w_1, Wire::W1(index));
        self.add_to_map(w_2, Wire::W2(index));
        self.add_to_map(w_3, Wire::W3(index));
    }

    fn add_to_map(&mut self, var: Variable, wire: Wire) {
        let wires = self.variable_map.get_mut(&var).unwrap();
        wires.push(wire);
    }
}

impl<F: Field> Permutation<F> {
    pub fn compute_sigmas(
        &self,
        domain_n: impl EvaluationDomain<F>,
        ks: &[F; 4],
    ) -> (Vec<F>, Vec<F>, Vec<F>, Vec<F>) {
        let perms = self.compute_wire_permutation(domain_n.size());

        let roots: Vec<_> = domain_n.elements().collect();
        let to = |&x| match x {
            Wire::W0(i) => roots[i] * ks[0],
            Wire::W1(i) => roots[i] * ks[1],
            Wire::W2(i) => roots[i] * ks[2],
            Wire::W3(i) => roots[i] * ks[3],
        };

        (
            cfg_iter!(perms[0]).map(to).collect(),
            cfg_iter!(perms[1]).map(to).collect(),
            cfg_iter!(perms[2]).map(to).collect(),
            cfg_iter!(perms[3]).map(to).collect(),
        )
    }

    fn compute_wire_permutation(&self, n: usize) -> [Vec<Wire>; 4] {
        let mut perm_0: Vec<_> = (0..n).map(|i| Wire::W0(i)).collect();
        let mut perm_1: Vec<_> = (0..n).map(|i| Wire::W1(i)).collect();
        let mut perm_2: Vec<_> = (0..n).map(|i| Wire::W2(i)).collect();
        let mut perm_3: Vec<_> = (0..n).map(|i| Wire::W3(i)).collect();

        for (_, wires) in self.variable_map.iter() {
            if wires.len() <= 1 {
                continue;
            }

            for (curr, curr_wire) in wires.iter().enumerate() {
                let next = match curr {
                    0 => wires.len() - 1,
                    _ => curr - 1,
                };
                let next_wire = &wires[next];

                match curr_wire {
                    Wire::W0(i) => perm_0[*i] = *next_wire,
                    Wire::W1(i) => perm_1[*i] = *next_wire,
                    Wire::W2(i) => perm_2[*i] = *next_wire,
                    Wire::W3(i) => perm_3[*i] = *next_wire,
                }
            }
        }

        [perm_0, perm_1, perm_2, perm_3]
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::One;
    use ark_poly::GeneralEvaluationDomain;

    use super::*;

    #[test]
    fn permutation() {
        let cs = crate::tests::circuit();
        let ks = [
            Fr::one(),
            Fr::from(7_u64),
            Fr::from(13_u64),
            Fr::from(17_u64),
        ];
        let domain_n = GeneralEvaluationDomain::<Fr>::new(cs.size()).unwrap();
        let roots: Vec<_> = domain_n.elements().collect();

        let (sigma_0, sigma_1, sigma_2, sigma_3) =
            cs.permutation.compute_sigmas(domain_n, &ks);

        let (id_0, id_1, id_2, id_3) = {
            let id_0: Vec<_> = cfg_iter!(roots).map(|r| ks[0] * r).collect();
            let id_1: Vec<_> = cfg_iter!(roots).map(|r| ks[1] * r).collect();
            let id_2: Vec<_> = cfg_iter!(roots).map(|r| ks[2] * r).collect();
            let id_3: Vec<_> = cfg_iter!(roots).map(|r| ks[3] * r).collect();
            (id_0, id_1, id_2, id_3)
        };

        let sigma: Vec<_> = [sigma_0, sigma_1, sigma_2, sigma_3]
            .iter()
            .map(|sigma| sigma.iter().product())
            .collect();
        let sigma_prod: Fr = sigma.iter().product();
        let id: Vec<_> = [id_0, id_1, id_2, id_3]
            .iter()
            .map(|id| id.iter().product())
            .collect();
        let id_prod: Fr = id.iter().product();
        assert_eq!(sigma_prod, id_prod);
    }
}
