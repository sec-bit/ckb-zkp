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
    in_bit: Vec<Option<E::Fr>>,
    in_constants: Vec<Option<E::Fr>>,
}

impl<E: Engine> Circuit<E> for lookup2bitDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert!(self.in_constants.len() == 4);
        assert!(self.in_bit.len() == 2);
        // assert!(self.in_bit == Some(E::Fr::zero()) || self.in_bit == Some(E::Fr::one()));
        let mut index = match (self.in_bit[0], self.in_bit[1]) {
            (Some(a_value), Some(b_value)) => {
                let mut tmp: usize = 0;
                if a_value == E::Fr::one(){
                    tmp += 1;
                }

                if b_value == E::Fr::one(){
                    tmp += 2;
                }
                Some(tmp)
            }
            _ => None, 
        };

        let mut res: Option<E::Fr>;
        if index.is_some() {
            res = self.in_constants[index.unwrap()];
        } else {
            res = None;
        }

        // 构建约束 lhs = c[1] - c[0] + (b[1] * (c[3] - c[2] - c[1] + c[0]))
        // lhs*b[0]
        let mut lhs_tmp1_var = cs.alloc(
            || "lhs_tmp1_var = b[1] * (c[3] - c[2] - c[1] + c[0])",
            || {
                if self.in_bit[0].is_some() && self.in_bit[1].is_some() {
                    let mut res = self.in_constants[3].unwrap();
                    let mut tmp = self.in_constants[2].unwrap();
                    tmp.negate();
                    res.add_assign(&tmp);
                    tmp = self.in_constants[1].unwrap();
                    tmp.negate();
                    res.add_assign(&tmp);
                    tmp = self.in_constants[0].unwrap();
                    res.add_assign(&tmp);
                    res.mul_assign(&self.in_bit[1].unwrap());

                    res.add_assign(&self.in_constants[1].unwrap());
                    tmp = self.in_constants[0].unwrap();
                    tmp.negate();
                    res.add_assign(&tmp);
                    
                    res.mul_assign(&self.in_bit[0].unwrap());
                    Ok(res)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;


        // rhs = -c[0] + r + (b[1] * (-c[2] + c[0]))
        // -c[0]
        let mut rhs_tmp1_var = cs.alloc(
            || "rhs_tmp1_var = -c[0]",
            || {
                if self.in_constants[0].is_some() {
                    let mut tmp = self.in_constants[0].unwrap();
                    tmp.negate();

                    Ok(tmp)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;

        // r
        let mut rhs_tmp2_var = cs.alloc(
            || "rhs_tmp2_var = res",
            || res.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // b[1] * (-c[2] + c[0])
        let mut rhs_tmp3_var = cs.alloc(
            || "rhs_tmp3_var = b[1] * (-c[2] + c[0])",
            || {
                if self.in_bit[0].is_some() && self.in_bit[1].is_some() {
                    let mut res = self.in_constants[0].unwrap();
                    let mut tmp = self.in_constants[2].unwrap();
                    tmp.negate();
                    res.add_assign(&tmp);
                    res.mul_assign(&self.in_bit[1].unwrap());

                    Ok(res)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;

        cs.enforce(
            || format!("lookup_1bit_gadget"),
            |lc| lc + lhs_tmp1_var,
            |lc| lc + CS::one(),
            |lc| lc + rhs_tmp1_var + rhs_tmp2_var + rhs_tmp3_var,
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
            in_bit: vec![None; 2],
            in_constants: vec![None; 4],
        };
        generate_random_parameters(c, rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");
    let mut in_constants_value: Vec<Option<<Bls12 as ScalarEngine>::Fr>> = Vec::with_capacity(4);
    in_constants_value.push(<Bls12 as ScalarEngine>::Fr::from_str("9"));
    in_constants_value.push(<Bls12 as ScalarEngine>::Fr::from_str("10"));
    in_constants_value.push(<Bls12 as ScalarEngine>::Fr::from_str("11"));
    in_constants_value.push(<Bls12 as ScalarEngine>::Fr::from_str("12"));

    let mut in_bits_value: Vec<Option<<Bls12 as ScalarEngine>::Fr>> = Vec::with_capacity(2);
    in_bits_value.push(<Bls12 as ScalarEngine>::Fr::from_str("1"));
    in_bits_value.push(<Bls12 as ScalarEngine>::Fr::from_str("1"));

    let mut c1 = lookup2bitDemo::<Bls12> {
        in_bit: in_bits_value.clone(),
        in_constants: in_constants_value.clone(),
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();
    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
}