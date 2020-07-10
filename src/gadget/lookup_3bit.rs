use math::PrimeField;
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError, Variable};

use crate::Vec;

struct Lookup3bit<E: PrimeField> {
    in_bit: Vec<Option<E>>,
    in_constants: Vec<Option<E>>,
}

impl<E: PrimeField> ConstraintSynthesizer<E> for Lookup3bit<E> {
    fn generate_constraints<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        assert!(self.in_constants.len() == 8);
        assert!(self.in_bit.len() == 3);

        let index = match (self.in_bit[0], self.in_bit[1], self.in_bit[2]) {
            (Some(b0), Some(b1), Some(b2)) => {
                let mut tmp: usize = 0;
                if b0 == E::one() {
                    tmp += 1;
                }

                if b1 == E::one() {
                    tmp += 2;
                }

                if b2 == E::one() {
                    tmp += 4;
                }
                Some(tmp)
            }
            _ => None,
        };

        let res = index.map(|i| self.in_constants[i]).flatten();

        let res_var = cs.alloc(
            || "res_var",
            || res.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let mut in_bit_var: Vec<Variable> = Vec::with_capacity(self.in_bit.len());
        for i in 0..self.in_bit.len() {
            let tmp = cs.alloc(
                || "self.in_bit",
                || self.in_bit[i].ok_or(SynthesisError::AssignmentMissing),
            )?;

            in_bit_var.push(tmp);
        }

        // b[0] * b[1] = precomp01
        let precomp01_var = cs.alloc(
            || "precomp01_var",
            || {
                let b0 = self.in_bit[0].ok_or(SynthesisError::AssignmentMissing)?;
                let b1 = self.in_bit[1].ok_or(SynthesisError::AssignmentMissing)?;

                Ok(b0 * b1)
            },
        )?;

        cs.enforce(
            || "b[0] * b[1] = precomp01",
            |lc| lc + in_bit_var[0],
            |lc| lc + in_bit_var[1],
            |lc| lc + precomp01_var,
        );

        // b[0] * b[2] = precomp02
        let precomp02_var = cs.alloc(
            || "precomp02_var",
            || {
                let b0 = self.in_bit[0].ok_or(SynthesisError::AssignmentMissing)?;
                let b2 = self.in_bit[2].ok_or(SynthesisError::AssignmentMissing)?;

                Ok(b0 * b2)
            },
        )?;

        cs.enforce(
            || "b[0] * b[2] = precomp02",
            |lc| lc + in_bit_var[0],
            |lc| lc + in_bit_var[2],
            |lc| lc + precomp02_var,
        );

        // b[1] * b[2] = precomp12
        let precomp12_var = cs.alloc(
            || "precomp12_var",
            || {
                let b1 = self.in_bit[1].ok_or(SynthesisError::AssignmentMissing)?;
                let b2 = self.in_bit[2].ok_or(SynthesisError::AssignmentMissing)?;

                Ok(b1 * b2)
            },
        )?;

        cs.enforce(
            || "b[1] * b[2] = precomp12",
            |lc| lc + in_bit_var[1],
            |lc| lc + in_bit_var[2],
            |lc| lc + precomp12_var,
        );

        // b[0] * b[1] * b[2] = precomp012
        let precomp012_var = cs.alloc(
            || "precomp012_var",
            || {
                let b0 = self.in_bit[0].ok_or(SynthesisError::AssignmentMissing)?;
                let b1 = self.in_bit[1].ok_or(SynthesisError::AssignmentMissing)?;
                let b2 = self.in_bit[2].ok_or(SynthesisError::AssignmentMissing)?;

                Ok(b0 * b1 * b2)
            },
        )?;

        cs.enforce(
            || "precomp01 * b[2] = precomp012",
            |lc| lc + precomp01_var,
            |lc| lc + in_bit_var[2],
            |lc| lc + precomp012_var,
        );

        let lhs_var = cs.alloc(
            || "lhs_var_alloc",
            || {
                let b0 = self.in_bit[0].ok_or(SynthesisError::AssignmentMissing)?;
                let b1 = self.in_bit[1].ok_or(SynthesisError::AssignmentMissing)?;
                let b2 = self.in_bit[2].ok_or(SynthesisError::AssignmentMissing)?;
                let c0 = self.in_constants[0].ok_or(SynthesisError::AssignmentMissing)?;
                let c1 = self.in_constants[1].ok_or(SynthesisError::AssignmentMissing)?;
                let c2 = self.in_constants[2].ok_or(SynthesisError::AssignmentMissing)?;
                let c3 = self.in_constants[3].ok_or(SynthesisError::AssignmentMissing)?;
                let c4 = self.in_constants[4].ok_or(SynthesisError::AssignmentMissing)?;
                let c5 = self.in_constants[5].ok_or(SynthesisError::AssignmentMissing)?;
                let c6 = self.in_constants[6].ok_or(SynthesisError::AssignmentMissing)?;
                let c7 = self.in_constants[7].ok_or(SynthesisError::AssignmentMissing)?;

                #[rustfmt::skip]
                let r = c0 +
                        b0 * (-c0) +
                        b0 * c1 +
                        b1 * (-c0) +
                        b1 * c2 +
                        b0 * b1 * (-c1 + (-c2) + c0 + c3) +
                        b2 * (-c0 + c4) +
                        b0 * b2 * (c0 + (-c1) + (-c4) + c5) +
                        b1 * b2 * (c0 + (-c2) + (-c4) + c6) +
                        b0 * b1 * b2 * (-c0 + c1 + c2 + (-c3) + c4 + (-c5) + (-c6) + c7);

                Ok(r)
            },
        )?;

        // ... * 1 = r
        cs.enforce(
            || "lhs * 1 = r",
            |lc| lc + lhs_var,
            |lc| lc + CS::one(),
            |lc| lc + res_var,
        );

        Ok(())
    }
}

#[test]
fn test_lookup3bit() {
    use curve::bn_256::{Bn_256, Fr};
    use math::test_rng;
    use scheme::groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };

    let mut rng = &mut test_rng();

    println!("Creating parameters...");
    let params = {
        let c = Lookup3bit::<Fr> {
            in_bit: vec![None; 3],
            in_constants: vec![None; 8],
        };
        generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");
    let c1 = Lookup3bit::<Fr> {
        in_bit: vec![
            Some(Fr::from(1u32)),
            Some(Fr::from(1u32)),
            Some(Fr::from(1u32)),
        ],
        in_constants: vec![
            Some(Fr::from(9u32)),
            Some(Fr::from(10u32)),
            Some(Fr::from(11u32)),
            Some(Fr::from(12u32)),
            Some(Fr::from(13u32)),
            Some(Fr::from(14u32)),
            Some(Fr::from(15u32)),
            Some(Fr::from(16u32)),
        ],
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();

    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
}
