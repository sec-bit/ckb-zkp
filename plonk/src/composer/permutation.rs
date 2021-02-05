use crate::composer::Variable;
use crate::HashMap;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum Wire {
    W0(usize),
    W1(usize),
    W2(usize),
    W3(usize),
}

#[derive(Debug)]
pub(crate) struct Permutation {
    variable_map: HashMap<Variable, Vec<Wire>>,
}

impl Permutation {
    pub fn new() -> Self {
        Permutation {
            variable_map: HashMap::new(),
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

impl Permutation {
    fn compute_sigmas(&self, n: usize) -> [Vec<Wire>; 4] {
        let mut sigma_0: Vec<_> = (0..n).map(|i| Wire::W0(i)).collect();
        let mut sigma_1: Vec<_> = (0..n).map(|i| Wire::W1(i)).collect();
        let mut sigma_2: Vec<_> = (0..n).map(|i| Wire::W2(i)).collect();
        let mut sigma_3: Vec<_> = (0..n).map(|i| Wire::W3(i)).collect();

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
                    Wire::W0(i) => sigma_0[*i] = *next_wire,
                    Wire::W1(i) => sigma_1[*i] = *next_wire,
                    Wire::W2(i) => sigma_2[*i] = *next_wire,
                    Wire::W3(i) => sigma_3[*i] = *next_wire,
                }
            }
        }

        [sigma_0, sigma_1, sigma_2, sigma_3]
    }
}
