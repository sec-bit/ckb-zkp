
use math::PrimeField;
use scheme::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, LinearCombination, SynthesisError, Variable,
};
use math::fields::Field;

use super::test_constraint_system::TestConstraintSystem;

// use bellman::gadgets::Assignment;

struct lookup1bitDemo<E: PrimeField> {
    in_bit: Option<E>,
    in_constants: Vec<Option<E>>,
}

impl<E: PrimeField> ConstraintSynthesizer<E> for lookup1bitDemo<E> {
    fn generate_constraints<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert!(self.in_constants.len() == 2);
        // assert!(self.in_bit == Some(E::zero()) || self.in_bit == Some(E::one()));
        let mut index = match self.in_bit {
            Some(a_value) => {
                let mut tmp: usize = 0;
                if a_value == E::one(){
                    tmp += 1;
                }
                Some(tmp)
            }
            _ => None, 
        };

        let mut res: Option<E>;
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
                    let mut in_constants_one_value = E::one();
                    in_constants_one_value = -in_constants_one_value;
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
    use curve::bn_256::{Bn_256, Fr};
    use math::test_rng;
    use math::fields::Field;
    use scheme::groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };
    let mut rng = &mut test_rng();
    println!("Creating parameters...");
    let params = {
        let c = lookup1bitDemo::<Fr> {
            in_bit: None,
            in_constants: vec![None; 2],
        };
        generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");
    let mut in_constants_value: Vec<Option<Fr>> = Vec::with_capacity(2);
    // Fr::from_str("9") 返回的是Option变量
    in_constants_value.push(Some(Fr::from(9u32)));
    in_constants_value.push(Some(Fr::from(10u32)));

    let mut c1 = lookup1bitDemo::<Fr> {
        in_bit: Some(Fr::from(1u32)),
        in_constants: in_constants_value.clone(),
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();
    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
}