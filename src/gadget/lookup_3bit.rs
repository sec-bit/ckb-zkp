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

struct lookup3bitDemo<E: Engine> {
    in_bit: Vec<Option<E::Fr>>,
    in_constants: Vec<Option<E::Fr>>,
}

impl<E: Engine> Circuit<E> for lookup3bitDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert!(self.in_constants.len() == 8);
        assert!(self.in_bit.len() == 3);
        // assert!(self.in_bit == Some(E::Fr::zero()) || self.in_bit == Some(E::Fr::one()));
        let mut index = match (self.in_bit[0], self.in_bit[1], self.in_bit[2]) {
            (Some(a_value), Some(b_value), Some(c_value)) => {
                let mut tmp: usize = 0;
                if a_value == E::Fr::one(){
                    tmp += 1;
                }

                if b_value == E::Fr::one(){
                    tmp += 2;
                }

                if c_value == E::Fr::one(){
                    tmp += 4;
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

        let mut res_var = cs.alloc(
            || "res_var",
            || res.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let mut in_bit_var : Vec<Variable> = Vec::with_capacity(self.in_bit.len()); 
        for i in 0..self.in_bit.len() {
            let mut tmp = cs.alloc(
                || format!("self.in_bit[{}]", i),
                || self.in_bit[i].ok_or(SynthesisError::AssignmentMissing),
            )?;

            in_bit_var.push(tmp);
        }
        // b[0] * b[1] = precomp01
        let mut precomp01_var = cs.alloc(
            || "precomp01_var",
            || {
                if self.in_bit[0].is_some() && self.in_bit[1].is_some() {
                    let mut precomp01 = self.in_bit[0].unwrap();
                    precomp01.mul_assign(&self.in_bit[1].unwrap());

                    Ok(precomp01)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;

        cs.enforce(
            || "b[0] * b[1] = precomp01",
            |lc| lc + in_bit_var[0],
            |lc| lc + in_bit_var[1],
            |lc| lc + precomp01_var,
        );
        
        // b[0] * b[2] = precomp02
        let mut precomp02_var = cs.alloc(
            || "precomp02_var",
            || {
                if self.in_bit[0].is_some() && self.in_bit[1].is_some() {
                    let mut precomp02 = self.in_bit[0].unwrap();
                    precomp02.mul_assign(&self.in_bit[2].unwrap());
                    
                    Ok(precomp02)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;

        cs.enforce(
            || "b[0] * b[2] = precomp02",
            |lc| lc + in_bit_var[0],
            |lc| lc + in_bit_var[2],
            |lc| lc + precomp02_var 
        );

        // b[1] * b[2] = precomp12
        let mut precomp12_var = cs.alloc(
            || "precomp12_var",
            || {
                if self.in_bit[1].is_some() && self.in_bit[2].is_some() {
                    let mut precomp12 = self.in_bit[1].unwrap();
                    precomp12.mul_assign(&self.in_bit[2].unwrap());

                    Ok(precomp12)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;

        cs.enforce(
            || "b[1] * b[2] = precomp12",
            |lc| lc + in_bit_var[1],
            |lc| lc + in_bit_var[2],
            |lc| lc + precomp12_var
        );

        // precomp01 * b[2] = precomp012
        let mut precomp012_var = cs.alloc(
            || "precomp012_var",
            || {
                if self.in_bit[0].is_some() && self.in_bit[1].is_some() && self.in_bit[2].is_some() {
                    let mut precomp012 = self.in_bit[0].unwrap();
                    precomp012.mul_assign(&self.in_bit[1].unwrap());
                    precomp012.mul_assign(&self.in_bit[2].unwrap());

                    Ok(precomp012)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;

        cs.enforce(
            || "precomp01 * b[2] = precomp012",
            |lc| lc + precomp01_var,
            |lc| lc + in_bit_var[2],
            |lc| lc + precomp012_var,
        );

        let mut lhs_var = cs.alloc(
            || "lhs_var_alloc",
            || {
                if self.in_bit[0].is_some() && self.in_bit[1].is_some() && self.in_bit[2].is_some() {
                    let mut res = self.in_constants[0].unwrap();

                    // b[0]*-c[0]
                    let mut tmp = self.in_constants[0].unwrap();
                    tmp.negate();
                    tmp.mul_assign(&self.in_bit[0].unwrap());
                    res.add_assign(&tmp);

                    // b[0]*c[1]
                    tmp = self.in_constants[1].unwrap();
                    tmp.mul_assign(&self.in_bit[0].unwrap());
                    res.add_assign(&tmp);

                    // b[1]*-c[0]
                    tmp = self.in_constants[0].unwrap();
                    tmp.negate();
                    tmp.mul_assign(&self.in_bit[1].unwrap());
                    res.add_assign(&tmp);

                    // b[1]*c[2]
                    tmp = self.in_constants[2].unwrap();
                    tmp.mul_assign(&self.in_bit[1].unwrap());
                    res.add_assign(&tmp);

                    // (precomp01 * (-c[1] + -c[2] + c[0] + c[3]))
                    tmp = self.in_constants[1].unwrap();
                    tmp.negate();
                    let mut tmp1 = self.in_constants[2].unwrap();
                    tmp1.negate();
                    tmp.add_assign(&tmp1);
                    tmp.add_assign(&self.in_constants[0].unwrap());
                    tmp.add_assign(&self.in_constants[3].unwrap());
                    tmp.mul_assign(&self.in_bit[0].unwrap());
                    tmp.mul_assign(&self.in_bit[1].unwrap());
                    res.add_assign(&tmp);

                    // (b[2] * (-c[0] + c[4]))
                    tmp = self.in_constants[0].unwrap();
                    tmp.negate();
                    tmp.add_assign(&self.in_constants[4].unwrap());
                    tmp.mul_assign(&self.in_bit[2].unwrap());
                    res.add_assign(&tmp);

                    // (precomp02 * (c[0] - c[1] -c[4] + c[5]))
                    tmp = self.in_constants[1].unwrap();
                    tmp.negate();
                    tmp1 = self.in_constants[4].unwrap();
                    tmp1.negate();
                    tmp.add_assign(&tmp1);
                    tmp.add_assign(&self.in_constants[0].unwrap());
                    tmp.add_assign(&self.in_constants[5].unwrap());
                    tmp.mul_assign(&self.in_bit[0].unwrap());
                    tmp.mul_assign(&self.in_bit[2].unwrap());
                    res.add_assign(&tmp);

                    // (precomp12 * (c[0] - c[2] - c[4] + c[6]))
                    tmp = self.in_constants[2].unwrap();
                    tmp.negate();
                    tmp1 = self.in_constants[4].unwrap();
                    tmp1.negate();
                    tmp.add_assign(&tmp1);
                    tmp.add_assign(&self.in_constants[0].unwrap());
                    tmp.add_assign(&self.in_constants[6].unwrap());
                    tmp.mul_assign(&self.in_bit[1].unwrap());
                    tmp.mul_assign(&self.in_bit[2].unwrap());
                    res.add_assign(&tmp);

                    // precomp012 * (-c[0] + c[1] + c[2] - c[3] + c[4] - c[5] -c[6] + c[7])
                    tmp = self.in_constants[0].unwrap();
                    tmp.negate();
                    tmp.add_assign(&self.in_constants[1].unwrap());
                    tmp.add_assign(&self.in_constants[2].unwrap());
                    tmp1 = self.in_constants[3].unwrap();
                    tmp1.negate();
                    tmp.add_assign(&tmp1);
                    tmp.add_assign(&self.in_constants[4].unwrap());
                    tmp1 = self.in_constants[5].unwrap();
                    tmp1.negate();
                    tmp.add_assign(&tmp1);
                    tmp1 = self.in_constants[6].unwrap();
                    tmp1.negate();
                    tmp.add_assign(&tmp1);
                    tmp.add_assign(&self.in_constants[7].unwrap());
                    tmp.mul_assign(&self.in_bit[0].unwrap());
                    tmp.mul_assign(&self.in_bit[1].unwrap());
                    tmp.mul_assign(&self.in_bit[2].unwrap());
                    res.add_assign(&tmp);

                    Ok(res)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;
        // ... * 1 = r
        cs.enforce(
            || "lhs * 1 = r",
            |lc| lc + lhs_var,
            |lc| lc + CS::one(),
            |lc| lc + res_var 
        );
        Ok(())
    }
}

#[test]
fn test_lookup3bitDemo() {
    let rng = &mut thread_rng();
    println!("Creating parameters...");
    let params = {
        let c = lookup3bitDemo::<Bls12> {
            in_bit: vec![None; 3],
            in_constants: vec![None; 8],
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
    in_constants_value.push(<Bls12 as ScalarEngine>::Fr::from_str("13"));
    in_constants_value.push(<Bls12 as ScalarEngine>::Fr::from_str("14"));
    in_constants_value.push(<Bls12 as ScalarEngine>::Fr::from_str("15"));
    in_constants_value.push(<Bls12 as ScalarEngine>::Fr::from_str("16"));

    let mut in_bits_value: Vec<Option<<Bls12 as ScalarEngine>::Fr>> = Vec::with_capacity(2);
    in_bits_value.push(<Bls12 as ScalarEngine>::Fr::from_str("1"));
    in_bits_value.push(<Bls12 as ScalarEngine>::Fr::from_str("1"));
    in_bits_value.push(<Bls12 as ScalarEngine>::Fr::from_str("1"));

    let mut c1 = lookup3bitDemo::<Bls12> {
        in_bit: in_bits_value.clone(),
        in_constants: in_constants_value.clone(),
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();
    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
}