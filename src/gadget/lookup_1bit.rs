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
    in_bit: Option<E::Fr>,
    in_constants: Vec<Option<E::Fr>>,
}

impl<E: Engine> Circuit<E> for lookup1bitDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert!(self.in_constants.len() == 2);
        // assert!(self.in_bit == Some(E::Fr::zero()) || self.in_bit == Some(E::Fr::one()));
        let mut index = match self.in_bit {
            Some(a_value) => {
                let mut tmp: usize = 0;
                if a_value == E::Fr::one(){
                    tmp += 1;
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
        ).unwrap();

        let mut in_constants_var0 = cs.alloc(
            || "in_constants_var_0",
            || self.in_constants[0].ok_or(SynthesisError::AssignmentMissing),
        ).unwrap();

        // 构建约束(c[0] + b*c[1] - b*c[0])*1 = r
        /* 这里有问题。
        1. self.in_constants和self.in_bit中的成员变量位None的时候，如何避免对None.unwrap()。
        解决方法：使用is_some()函数对值进行校验
        2. 注意所有alloc的变量都必须在约束系统中进行出现。
        */
        let tmp_var = cs.alloc(
            || "tmp_var=b*c[1]",
            || {
                if self.in_bit.is_some() && self.in_constants[1].is_some() {
                    let mut tmp = self.in_bit.unwrap();
                    tmp.mul_assign(&self.in_constants[1].unwrap());
                    Ok(tmp)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;

        let tmp1_var = cs.alloc(
            || "tmp1_var=b*c[1]",
            || {
                if self.in_bit.is_some() && self.in_constants[0].is_some() {
                    let mut in_constants_one_value = E::Fr::one();
                    in_constants_one_value.negate();
                    let mut tmp = self.in_bit.unwrap();
                    tmp.mul_assign(&self.in_constants[0].unwrap());
                    tmp.mul_assign(&in_constants_one_value);
                    Ok(tmp)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;
        cs.enforce(
            || format!("lookup_1bit_gadget"),
            |lc| lc + in_constants_var0 + tmp_var + tmp1_var,
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
    let mut in_constants_value: Vec<Option<<Bls12 as ScalarEngine>::Fr>> = Vec::with_capacity(2);
    // <Bls12 as ScalarEngine>::Fr::from_str("9") 返回的是Option变量
    in_constants_value.push(<Bls12 as ScalarEngine>::Fr::from_str("9"));
    in_constants_value.push(<Bls12 as ScalarEngine>::Fr::from_str("10"));

    let mut c1 = lookup1bitDemo::<Bls12> {
        in_bit: <Bls12 as ScalarEngine>::Fr::from_str("1"),
        in_constants: in_constants_value.clone(),
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();
    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
}