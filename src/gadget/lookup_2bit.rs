use bellman::gadgets::boolean::{Boolean, AllocatedBit};
use bellman::gadgets::Assignment;
use ff::{Field, PrimeField, ScalarEngine};
use pairing::bls12_381::Bls12;
use pairing::Engine;
use rand::thread_rng;

// We'll use these interfaces to construct our circuit.
use bellman::gadgets::boolean;
use bellman::gadgets::test::TestConstraintSystem;
use bellman::{Circuit, ConstraintSystem, LinearCombination, SynthesisError, Variable};

// We're going to use the Groth16 proving system.
use bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};

// use bellman::gadgets::Assignment;

struct lookup2bitDemo<E: Engine> {
    in_bits: Vec<Option<Boolean>>,
    in_constants: Vec<Option<E::Fr>>,
}

impl<E: Engine> Circuit<E> for lookup2bitDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert!(self.in_constants.len() == 4);
        assert!(self.in_bits.len() == 2);
        // Calculate the index into `coords`
        let i = match (
            self.in_bits[0].unwrap().get_value(),
            self.in_bits[1].unwrap().get_value(),
        ) {
            (Some(a_value), Some(b_value)) => {
                let mut tmp: usize = 0;
                if a_value {
                    tmp += 1;
                }
                if b_value {
                    tmp += 2;
                }
                Some(tmp)
            }
            _ => None,
        };

        let mut res = self.in_constants[i.unwrap()];

        // let mut in_bits_value: Vec<Option<E::Fr>> = Vec::with_capacity(self.in_bits.len());
        let mut in_bits_var: Vec<Variable> = Vec::with_capacity(self.in_bits.len());
        let mut in_constants_var: Vec<Variable> = Vec::with_capacity(self.in_constants.len());
        let mut res_var = cs.alloc(
            || "lookup2bit",
            || res.ok_or(SynthesisError::AssignmentMissing),
        );

        for i in 0..self.in_bits.len() {
            let mut bit_value = if Some(true) == self.in_bits[i].unwrap().get_value() {Some(E::Fr::one())} else {Some(E::Fr::zero())};
            // in_bits_value.push(bit_value);
            let mut tmp = cs.alloc(
                || format!("lookup2bit_in_bits_var[{}]", i),
                || bit_value.ok_or(SynthesisError::AssignmentMissing),
            )?;
            in_bits_var.push(tmp);
        }

        for i in 0..self.in_constants.len() {
            let mut tmp = cs.alloc(
                || format!("lookup2bit_in_constants_var[{}]", i),
                || self.in_constants[i].ok_or(SynthesisError::AssignmentMissing),
            )?;
            in_constants_var.push(tmp);
        }

        let mut lhs = {
            let mut tmp = self.in_constants[];
        };

        // 开始构造约束
        cs.enforce(
            || format!("lhs = c[1] - c[0] + (b[1] * (c[3] - c[2] - c[1] + c[0]))"),
            |lc| lc,
            |lc| lc,
            |lc| lc,
        );




        Ok(())
    }
}

#[test]
fn test_lookup2bitDemo() {
    let rng = &mut thread_rng();
    println!("Creating parameters...");
    let params = {
        let c = lookup2bitDemo::<Bls12> {
            in_bits: vec![None, 2],
            in_constants: vec![None; 4],
        };

        generate_random_parameters(c, rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");
    let mut in_constants_v: Vec<Option<<Bls12 as ScalarEngine>::Fr>> = Vec::with_capacity(2);
    in_constants_v.push(<Bls12 as ScalarEngine>::Fr::from_str("9"));
    in_constants_v.push(<Bls12 as ScalarEngine>::Fr::from_str("10"));

    let mut cs = TestConstraintSystem::<Bls12>::new();
    let mut c1 = lookup2bitDemo::<Bls12> {
        in_bits: Some(Boolean::from(AllocatedBit::alloc(cs.namespace(|| "c"), Some(false)).unwrap())),
        in_constants: in_constants_v.clone(),
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();
    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
}