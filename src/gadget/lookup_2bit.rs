use math::PrimeField;
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

use crate::Vec;

struct Lookup2bit<E: PrimeField> {
    in_bit: Vec<Option<E>>,
    in_constants: Vec<Option<E>>,
}

impl<E: PrimeField> ConstraintSynthesizer<E> for Lookup2bit<E> {
    fn generate_constraints<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        assert!(self.in_constants.len() == 4);
        assert!(self.in_bit.len() == 2);

        let index = match (self.in_bit[0], self.in_bit[1]) {
            (Some(b0), Some(b1)) => {
                let mut tmp: usize = 0;
                if b0 == E::one() {
                    tmp += 1;
                }

                if b1 == E::one() {
                    tmp += 2;
                }
                Some(tmp)
            }
            _ => None,
        };

        let res = index.map(|i| self.in_constants[i]).flatten();

        // (c[1] - c[0] + b[1] * (c[3] - c[2] - c[1] + c[0])) * b[0]
        let lhs_tmp1_var = cs.alloc(
            || "lhs_tmp1_var = b[1] * (c[3] - c[2] - c[1] + c[0])",
            || {
                let b0 = self.in_bit[0].ok_or(SynthesisError::AssignmentMissing)?;
                let b1 = self.in_bit[1].ok_or(SynthesisError::AssignmentMissing)?;
                let c0 = self.in_constants[0].ok_or(SynthesisError::AssignmentMissing)?;
                let c1 = self.in_constants[1].ok_or(SynthesisError::AssignmentMissing)?;
                let c2 = self.in_constants[2].ok_or(SynthesisError::AssignmentMissing)?;
                let c3 = self.in_constants[3].ok_or(SynthesisError::AssignmentMissing)?;

                Ok((c1 - c0 + b1 * (c3 - c2 - c1 + c0)) * b0)
            },
        )?;

        // rhs = -c[0] + r + (b[1] * (-c[2] + c[0]))
        // -c[0]
        let rhs_tmp1_var = cs.alloc(
            || "rhs_tmp1_var = -c[0]",
            || {
                let c0 = self.in_constants[0].ok_or(SynthesisError::AssignmentMissing)?;
                Ok(-c0)
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
                let b1 = self.in_bit[1].ok_or(SynthesisError::AssignmentMissing)?;
                let c0 = self.in_constants[0].ok_or(SynthesisError::AssignmentMissing)?;
                let c2 = self.in_constants[2].ok_or(SynthesisError::AssignmentMissing)?;

                Ok(b1 * (-c2 + c0))
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
fn test_lookup2bit() {
    use curve::bn_256::{Bn_256, Fr};
    use math::test_rng;
    use scheme::groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };

    let mut rng = &mut test_rng();

    println!("Creating parameters...");
    let params = {
        let c = Lookup2bit::<Fr> {
            in_bit: vec![None; 2],
            in_constants: vec![None; 4],
        };
        generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");
    let c1 = Lookup2bit::<Fr> {
        in_bit: vec![Some(Fr::from(1u32)), Some(Fr::from(1u32))],
        in_constants: vec![
            Some(Fr::from(9u32)),
            Some(Fr::from(10u32)),
            Some(Fr::from(11u32)),
            Some(Fr::from(12u32)),
        ],
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();

    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
}
