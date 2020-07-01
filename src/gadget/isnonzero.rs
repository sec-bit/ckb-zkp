use math::PrimeField;
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

struct IsnonzeroDemo<F: PrimeField> {
    check_num: Option<F>,
}

impl<E: PrimeField> ConstraintSynthesizer<E> for IsnonzeroDemo<E> {
    fn generate_constraints<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let inv_var = cs.alloc(
            || "elhemeral inverse",
            || {
                let tmp = self.check_num.clone();
                if tmp.unwrap() == E::zero() {
                    Err(SynthesisError::DivisionByZero)
                } else {
                    Ok(tmp.unwrap().inverse().unwrap())
                }
            },
        )?;

        let check_num_var = cs.alloc(
            || "check_num_var",
            || self.check_num.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Constrain a * inv = 1, which is only valid
        // iff a has a multiplicative inverse, untrue
        // for zero.
        cs.enforce(
            || "nonzero assertion constraint",
            |lc| lc + check_num_var,
            |lc| lc + inv_var,
            |lc| lc + CS::one(),
        );

        Ok(())
    }
}

#[test]
fn test_isnonzero_demo() {
    use curve::bn_256::{Bn_256, Fr};
    use math::test_rng;
    use scheme::groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };

    let mut rng = &mut test_rng();
    println!("Creating parameters...");
    let params = {
        let c = IsnonzeroDemo::<Fr> { check_num: None };

        generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    let c1 = IsnonzeroDemo::<Fr> {
        check_num: Some(Fr::from(1u32)),
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();
    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
}

#[test]
fn test_isnonzero_bp_demo() {
    use curve::bn_256::{Bn_256, Fr};
    use scheme::bulletproofs::arithmetic_circuit::{create_proof, verify_proof};

    let mut rng = &mut math::test_rng();

    println!("Creating proofs...");

    let c = IsnonzeroDemo::<Fr> {
        check_num: Some(Fr::from(1u32)),
    };
    let (generators, r1cs_circuit, proof, assignment) =
        create_proof::<Bn_256, _, _>(c, &mut rng).unwrap();

    verify_proof(&generators, &proof, &r1cs_circuit, &assignment.s);
}
