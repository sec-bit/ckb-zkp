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

struct lookup1bitDemo<E: Engine> {
    in_bit: Option<Boolean>,
    in_constants: Vec<Option<E::Fr>>,
}

impl<E: Engine> Circuit<E> for lookup1bitDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert!(self.in_constants.len() == 2);

        let mut in_bit_value =  if self.in_bit.unwrap().get_value() == Some(true) { Some(E::Fr::one()) } else { Some(E::Fr::zero()) };
        let mut res: Option<E::Fr>;
        if in_bit_value == Some(E::Fr::zero()) {
            res = Some(self.in_constants[0].unwrap());
        }else {
            res = Some(self.in_constants[1].unwrap());
        }

        let mut res_var = cs.alloc(
            || format!("res_var"),
            || res.ok_or(SynthesisError::AssignmentMissing),
        ).unwrap();

        // in_constants_var
        let mut in_constants_var: Vec<Variable> = Vec::with_capacity(self.in_constants.len());
        for i in 0..self.in_constants.len() {
            let mut tmp = cs.alloc(
                || format!("self.in_constants[{}]", i),
                || self.in_constants[i].ok_or(SynthesisError::AssignmentMissing),
            ).unwrap();
            in_constants_var.push(tmp);
        }

        let mut in_bit_var = cs.alloc(
            || format!("in_bit_var"),
            || in_bit_value.ok_or(SynthesisError::AssignmentMissing),
        ).unwrap();

        // 构建约束(c[0] + b*c[1] - b*c[0])*1 = r
        let mut in_constants_one_value = E::Fr::one();
        in_constants_one_value.negate();
        in_constants_one_value.mul_assign(&self.in_constants[0].unwrap());
        cs.enforce(
            || format!("lookup_1bit_gadget"),
            |lc| lc + in_constants_var[0] + (self.in_constants[1].unwrap(), in_bit_var) + (in_constants_one_value, in_bit_var),
            |lc| lc + CS::one(),
            |lc| lc + res_var,
        );

        Ok(())
    }
}

#[test]
fn test_lookup1bitDemo() {
    let rng = &mut thread_rng();
    println!("Creating parameters...");
    let params = {
        let c = lookup1bitDemo::<Bls12> {
            in_bit: None,
            in_constants: vec![None; 2],
        };

        generate_random_parameters(c, rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");
    let mut in_constants_v: Vec<Option<<Bls12 as ScalarEngine>::Fr>> = Vec::with_capacity(2);
    in_constants_v.push(<Bls12 as ScalarEngine>::Fr::from_str("9"));
    in_constants_v.push(<Bls12 as ScalarEngine>::Fr::from_str("10"));

    let mut cs = TestConstraintSystem::<Bls12>::new();
    let mut c1 = lookup1bitDemo::<Bls12> {
        in_bit: Some(Boolean::from(AllocatedBit::alloc(cs.namespace(|| "c"), Some(false)).unwrap())),
        in_constants: in_constants_v.clone(),
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();
    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
}