use crate::composer::{Error, Field, Variable};
use crate::{Map, Vec};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use core::marker::PhantomData;

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

    pub fn add_gate(
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
        n: usize,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, Vec<F>), Error> {
        let domain = GeneralEvaluationDomain::<F>::new(4 * n)
            .ok_or(Error::PolynomialDegreeTooLarge)?;

        let perms = self.compute_wire_permutation(n);
        let to = |&x| match x {
            Wire::W0(i) => domain.element(i),
            Wire::W1(i) => domain.element(i + n),
            Wire::W2(i) => domain.element(i + 2 * n),
            Wire::W3(i) => domain.element(i + 3 * n),
        };
        Ok((
            perms[0].iter().map(to).collect(),
            perms[1].iter().map(to).collect(),
            perms[2].iter().map(to).collect(),
            perms[3].iter().map(to).collect(),
        ))
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
