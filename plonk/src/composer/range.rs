use ark_ff::BitIteratorBE;
use ark_ff::PrimeField;

use super::permutation::Wire;
use crate::composer::{Composer, Variable};

impl<F: PrimeField> Composer<F> {
    /// a in [0, 2.pow(num_bits))
    pub fn range_gate(&mut self, a: Variable, num_bits: usize, pi: F) {
        let add_wire = |composer: &mut Composer<F>, i: usize, variable: Variable| {
            // Since four quads can fit into one gate, the gate index does
            // not change for every four wires
            let gate_index = composer.size() + (i / 4);

            let wire_data = match i % 4 {
                0 => {
                    composer.w_3.push(variable);
                    Wire::W3(gate_index)
                }
                1 => {
                    composer.w_2.push(variable);
                    Wire::W2(gate_index)
                }
                2 => {
                    composer.w_1.push(variable);
                    Wire::W1(gate_index)
                }
                3 => {
                    composer.w_0.push(variable);
                    Wire::W0(gate_index)
                }
                _ => unreachable!(),
            };

            composer.permutation.add_to_map(variable, wire_data);
        };

        assert!(num_bits % 2 == 0);

        let value = self.assignment[&a];
        let mut bits: Vec<_> = BitIteratorBE::new(value.into_repr()).collect();
        bits.reverse();

        let mut num_gates = num_bits >> 3;

        if num_bits % 8 != 0 {
            num_gates += 1;
        }

        let num_quads = num_gates * 4;

        let pad = 1 + (((num_quads << 1) - num_bits) >> 1);

        let used_gates = num_gates + 1;

        let mut accumulators: Vec<Variable> = Vec::new();
        let mut accumulator = F::zero();
        let four = F::from(4u64);

        for i in 0..pad {
            add_wire(self, i, Variable(0));
        }

        for i in pad..=num_quads {
            // Convert each pair of bits to quads
            let bit_index = (num_quads - i) << 1;
            let q_0 = bits[bit_index] as u64;
            let q_1 = bits[bit_index + 1] as u64;
            let quad = q_0 + (2 * q_1);

            // Compute the next accumulator term
            accumulator = four * accumulator;
            accumulator += F::from(quad);

            let accumulator_var = self.alloc_and_assign(accumulator);
            accumulators.push(accumulator_var);

            add_wire(self, i, accumulator_var);
        }

        let zeros = vec![F::zero(); used_gates];

        self.q_0.extend(zeros.iter());
        self.q_1.extend(zeros.iter());
        self.q_2.extend(zeros.iter());
        self.q_3.extend(zeros.iter());
        self.q_m.extend(zeros.iter());
        self.q_c.extend(zeros.iter());
        self.q_arith.extend(zeros.iter());

        self.pi.push(pi);

        self.n += used_gates;

        self.w_0.push(Variable(0));
        self.w_1.push(Variable(0));
        self.w_2.push(Variable(0));

        let last_accumulator = accumulators.len() - 1;
        self.assert_equal(accumulators[last_accumulator], a);
        accumulators[last_accumulator] = a;
    }

    /// a > b
    pub fn greater_gate(&mut self, _a: Variable, _b: Variable, _num_bits: usize, _pi: F) {
        todo!()
        // x = (a-1) - b

        // x in 0 ~ 2.pow(num_bits)
    }
}
