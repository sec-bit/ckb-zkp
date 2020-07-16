use math::PrimeField;
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

use crate::Vec;

struct Lookup1bit<E: PrimeField> {
    in_bit: Option<E>,
    in_constants: Vec<Option<E>>,
}

impl<E: PrimeField> ConstraintSynthesizer<E> for Lookup1bit<E> {
    fn generate_constraints<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        assert!(self.in_constants.len() == 2);

        let index = match self.in_bit {
            Some(v) => Some(if v == E::one() { 1 } else { 0 }),
            _ => None,
        };

        let res = index.map(|i| self.in_constants[i]).flatten();

        let res_var = cs.alloc(
            || "res_var",
            || res.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let in_constants_var0 = cs.alloc(
            || "in_constants_var_0",
            || self.in_constants[0].ok_or(SynthesisError::AssignmentMissing),
        )?;

        // (c[0] + b*c[1] - b*c[0])*1 = r
        let tmp_var = cs.alloc(
            || "tmp_var=b*c[1]",
            || match (self.in_bit, self.in_constants[1]) {
                (Some(b), Some(c)) => Ok(b * c),
                _ => Err(SynthesisError::AssignmentMissing),
            },
        )?;

        let tmp1_var = cs.alloc(
            || "tmp1_var=b*c[0]",
            || match (self.in_bit, self.in_constants[0]) {
                (Some(b), Some(c)) => Ok(b * c * (-E::one())),
                _ => Err(SynthesisError::AssignmentMissing),
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
fn test_lookup1bit() {
    use curve::bn_256::{Bn_256, Fr};
    use math::test_rng;
    use scheme::groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };

    let mut rng = &mut test_rng();

    println!("Creating parameters...");
    let params = {
        let c = Lookup1bit::<Fr> {
            in_bit: None,
            in_constants: vec![None; 2],
        };
        generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap()
    };
    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");
    let c1 = Lookup1bit::<Fr> {
        in_bit: Some(Fr::from(1u32)),
        in_constants: vec![Some(Fr::from(9u32)), Some(Fr::from(10u32))],
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();

    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
}
