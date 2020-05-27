use math::PrimeField;
use scheme::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, SynthesisError,
};

struct Lookup2bitDemo<E: PrimeField> {
    in_bit: Vec<Option<E>>,
    in_constants: Vec<Option<E>>,
}

impl<E: PrimeField> ConstraintSynthesizer<E> for Lookup2bitDemo<E> {
    fn generate_constraints<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert!(self.in_constants.len() == 4);
        assert!(self.in_bit.len() == 2);
        // assert!(self.in_bit == Some(E::zero()) || self.in_bit == Some(E::one()));
        let index = match (self.in_bit[0], self.in_bit[1]) {
            (Some(a_value), Some(b_value)) => {
                let mut tmp: usize = 0;
                if a_value == E::one(){
                    tmp += 1;
                }

                if b_value == E::one(){
                    tmp += 2;
                }
                Some(tmp)
            }
            _ => None, 
        };

        let res: Option<E>;
        if index.is_some() {
            res = self.in_constants[index.unwrap()];
        } else {
            res = None;
        }

        // 构建约束 lhs = c[1] - c[0] + (b[1] * (c[3] - c[2] - c[1] + c[0]))
        // lhs*b[0]
        let lhs_tmp1_var = cs.alloc(
            || "lhs_tmp1_var = b[1] * (c[3] - c[2] - c[1] + c[0])",
            || {
                if self.in_bit[0].is_some() && self.in_bit[1].is_some() {
                    let mut res = self.in_constants[3].unwrap();
                    let mut tmp = self.in_constants[2].unwrap();
                    tmp = -tmp;
                    res.add_assign(&tmp);
                    tmp = self.in_constants[1].unwrap();
                    tmp = -tmp;
                    res.add_assign(&tmp);
                    tmp = self.in_constants[0].unwrap();
                    res.add_assign(&tmp);
                    res.mul_assign(&self.in_bit[1].unwrap());

                    res.add_assign(&self.in_constants[1].unwrap());
                    tmp = self.in_constants[0].unwrap();
                    tmp = -tmp;
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
        let rhs_tmp1_var = cs.alloc(
            || "rhs_tmp1_var = -c[0]",
            || {
                if self.in_constants[0].is_some() {
                    let mut tmp = self.in_constants[0].unwrap();
                    tmp = -tmp;

                    Ok(tmp)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;

        // r
        let rhs_tmp2_var = cs.alloc(
            || "rhs_tmp2_var = res",
            || res.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // b[1] * (-c[2] + c[0])
        let rhs_tmp3_var = cs.alloc(
            || "rhs_tmp3_var = b[1] * (-c[2] + c[0])",
            || {
                if self.in_bit[0].is_some() && self.in_bit[1].is_some() {
                    let mut res = self.in_constants[0].unwrap();
                    let mut tmp = self.in_constants[2].unwrap();
                    tmp = -tmp;
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
fn test_lookup2bit_demo() {
    use curve::bn_256::{Bn_256, Fr};
    use math::test_rng;
    use scheme::groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };

    let mut rng = &mut test_rng();
    println!("Creating parameters...");
    let params = {
        let c = Lookup2bitDemo::<Fr> {
            in_bit: vec![None; 2],
            in_constants: vec![None; 4],
        };
        generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");
    let mut in_constants_value: Vec<Option<Fr>> = Vec::with_capacity(4);
    in_constants_value.push(Some(Fr::from(9u32)));
    in_constants_value.push(Some(Fr::from(10u32)));
    in_constants_value.push(Some(Fr::from(11u32)));
    in_constants_value.push(Some(Fr::from(12u32)));

    let mut in_bits_value: Vec<Option<Fr>> = Vec::with_capacity(2);
    in_bits_value.push(Some(Fr::from(1u32)));
    in_bits_value.push(Some(Fr::from(1u32)));

    let c1 = Lookup2bitDemo::<Fr> {
        in_bit: in_bits_value.clone(),
        in_constants: in_constants_value.clone(),
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();
    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
}