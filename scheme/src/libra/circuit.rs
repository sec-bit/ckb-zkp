use math::{log2, PairingEngine, Zero};

///operation
/// 0. add
/// 1. multiple
/// 2. dummy
/// 3. input
/// 4. direct relay
pub struct Gate<E: PairingEngine> {
    pub g: usize,
    pub op: u8,
    pub left_node: usize,
    pub right_node: usize,
    pub value: E::Fr,
}

impl<E: PairingEngine> Gate<E> {
    pub fn new(
        g: usize,
        op: u8,
        left_node: usize,
        right_node: usize,
        value: E::Fr,
        // gates_count: usize,
        // next_layer_gates_count: usize,
    ) -> Self {
        // if gates_count >= g {
        //     // illegal g
        // }
        // if op > 4 {
        //     // illegal operation
        // } else if op > 2
        //     && next_layer_gates_count >= left_node
        //     && next_layer_gates_count >= right_node
        // {
        //     // illegal left, right
        // }

        Self {
            g,
            op,
            left_node,
            right_node,
            value,
        }
    }
}

pub struct Layer<E: PairingEngine> {
    pub gates_count: usize,
    pub bit_size: usize,
    pub gates: Vec<Gate<E>>,
}

impl<E: PairingEngine> Layer<E> {
    pub fn input_new(inputs: &Vec<E::Fr>) -> Self {
        let mut gates = Vec::new();
        let mut gates_count: usize = 0;
        for (g, &value) in inputs.iter().enumerate() {
            let gate = Gate::new(g, 3, 0, 0, value);
            gates.push(gate);
            gates_count += 1;
        }
        let bit_size = log2(gates_count.next_power_of_two()) as usize;
        Self {
            gates_count,
            bit_size,
            gates,
        }
    }

    pub fn mid_layer_new(
        gates_raw: &Vec<(u8, usize, usize)>,
        next_layer_gates_count: usize,
    ) -> Self {
        let mut gates = Vec::new();
        let mut gates_count: usize = 0;
        for (g, &(op, left, right)) in gates_raw.iter().enumerate() {
            if op != 0 && op != 1 {
                // illegal op
            }
            if left >= next_layer_gates_count || right >= next_layer_gates_count {
                // illegal left, right
            }
            let gate = Gate::new(g, op, left, right, E::Fr::zero());
            gates.push(gate);
            gates_count += 1;
        }
        let bit_size = log2(gates_count.next_power_of_two()) as usize;
        Self {
            gates_count,
            bit_size,
            gates,
        }
    }
}

pub struct Circuit<E: PairingEngine> {
    pub depth: usize,
    pub layers: Vec<Layer<E>>,
}

impl<E: PairingEngine> Circuit<E> {
    pub fn new(inputs: &Vec<E::Fr>, layers_raw: &Vec<Vec<(u8, usize, usize)>>) -> Circuit<E> {
        let mut layers = Vec::new();
        let mut depth = 0;

        let layer_input = Layer::input_new(inputs);
        let mut next_layer_gates_count = layer_input.gates_count;
        layers.push(layer_input);
        depth += 1;

        for i in 0..layers_raw.len() {
            let gate_layer = Layer::mid_layer_new(&layers_raw[i], next_layer_gates_count);
            depth += 1;
            next_layer_gates_count = gate_layer.gates_count;
            layers.push(gate_layer);
        }

        // layers.reverse();
        Circuit { depth, layers }
    }

    pub fn evaluate(&self) -> Vec<Vec<E::Fr>> {
        let mut evals = Vec::new();
        let mut next_layer_values = Vec::new();
        for (d, layer) in self.layers.iter().enumerate() {
            let mut values = Vec::new();
            if d == 0 {
                for gate in layer.gates.iter() {
                    values.push(gate.value);
                }
            } else {
                let next_layer_size = next_layer_values.len();
                for gate in layer.gates.iter() {
                    if gate.left_node >= next_layer_size || gate.right_node >= next_layer_size {
                        // illegal left, right
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
                    }
                }
            }
            next_layer_values = values.clone();
            evals.push(values);
        }
        assert_eq!(evals.len(), self.depth);
        evals
    }
}
