use core::cmp;
use math::{log2, Curve, Zero};

use crate::Vec;

///operation
/// 0. add
/// 1. multiple
/// 2. dummy
/// 3. input
pub struct Gate {
    pub g: usize,
    pub op: u8,
    pub left_node: usize,
    pub right_node: usize,
}

impl Gate {
    pub fn new(g: usize, op: u8, left_node: usize, right_node: usize) -> Self {
        Self {
            g,
            op,
            left_node,
            right_node,
        }
    }
}

pub struct Layer {
    pub gates_count: usize,
    pub bit_size: usize,
    pub gates: Vec<Gate>,
}

impl Layer {
    pub fn input_new(num_inputs: usize, num_aux: usize) -> Self {
        let gates_num = cmp::max(num_aux, num_inputs).next_power_of_two() * 2;
        let bit_size = log2(gates_num) as usize;

        let mut gates = Vec::new();
        let mut gates_count = 0;
        for g in 0..2usize.pow(bit_size as u32) {
            let gate = Gate::new(g, 3, 0, 0);
            gates.push(gate);
            gates_count += 1;
        }
        Self {
            gates_count,
            bit_size,
            gates,
        }
    }

    pub fn mid_layer_new(
        gates_raw: &Vec<(u8, usize, usize)>,
        next_layer_gates_count: usize,
    ) -> Result<Self, Error> {
        let mut gates = Vec::new();
        let mut gates_count: usize = 0;
        for (g, &(op, left, right)) in gates_raw.iter().enumerate() {
            if op != 0 && op != 1 {
                return Err(Error::IllegalOperator);
            }
            if left >= next_layer_gates_count || right >= next_layer_gates_count {
                return Err(Error::IllegalNode);
            }
            let gate = Gate::new(g, op, left, right);
            gates.push(gate);
            gates_count += 1;
        }
        let bit_size = log2(gates_count.next_power_of_two()) as usize;
        let layer = Self {
            gates_count,
            bit_size,
            gates,
        };

        Ok(layer)
    }
}

pub struct Circuit {
    pub depth: usize,
    pub layers: Vec<Layer>,
}

impl Circuit {
    pub fn new(
        num_inputs: usize,
        num_aux: usize,
        layers_raw: &Vec<Vec<(u8, usize, usize)>>,
    ) -> Self {
        let mut layers = Vec::new();
        let mut depth = 0;

        let layer_input = Layer::input_new(num_inputs, num_aux);
        let mut next_layer_gates_count = layer_input.gates_count;
        layers.push(layer_input);
        depth += 1;

        for i in 0..layers_raw.len() {
            let gate_layer = Layer::mid_layer_new(&layers_raw[i], next_layer_gates_count).unwrap();
            next_layer_gates_count = gate_layer.gates_count;
            layers.push(gate_layer);
            depth += 1;
        }

        Self { depth, layers }
    }

    pub fn evaluate<G: Curve>(
        &self,
        inputs: &Vec<G::Fr>,
        aux: &Vec<G::Fr>,
    ) -> Result<Vec<Vec<G::Fr>>, Error> {
        let n = self.layers.len();
        let mut evals = vec![vec![]; n];
        let mut next_layer_values = Vec::new();

        // let bit_size = cmp::max(num_aux, num_inputs).next_power_of_two() * 2;
        for (d, layer) in self.layers.iter().enumerate() {
            let mut values = Vec::new();
            if d == 0 {
                let input_size = 2usize.pow(layer.bit_size as u32 - 1);
                assert!(input_size >= inputs.len());
                assert!(input_size >= aux.len());
                values = aux.clone();
                values.extend(&vec![G::Fr::zero(); input_size - inputs.len()]);
                values.extend(inputs.clone());
                values.extend(&vec![G::Fr::zero(); input_size - aux.len()]);
            } else {
                let next_layer_size = next_layer_values.len();
                for gate in layer.gates.iter() {
                    if gate.left_node >= next_layer_size || gate.right_node >= next_layer_size {
                        // illegal left, right
                        return Err(Error::IllegalNode);
                    }
                    if gate.op == 0 {
                        // add
                        values.push(
                            next_layer_values[gate.left_node] + &next_layer_values[gate.right_node],
                        );
                    } else if gate.op == 1 {
                        // mul
                        values.push(
                            next_layer_values[gate.left_node] * &next_layer_values[gate.right_node],
                        );
                    } else {
                        // illegal op
                        return Err(Error::IllegalNode);
                    }
                }
            }
            next_layer_values = values.clone();
            evals[n - d - 1] = values;
        }
        assert_eq!(evals.len(), self.depth);
        Ok(evals)
    }
}

#[derive(Debug)]
pub enum Error {
    IllegalOperator,

    IllegalNode,
}
