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

struct isnonzeroDemo<E: Engine> {
    check_num: Option<E::Fr>,
}

impl<E: Engine> Circuit<E> for isnonzeroDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let inv_var = cs.alloc(
            || "elhemeral inverse",
            || {
                let tmp = *self.check_num.get()?;
                if tmp.is_zero() {
                    Err(SynthesisError::DivisionByZero)
                } else {
                    Ok(tmp.inverse().unwrap())
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
fn test_isnonzeroDemo() {
    let rng = &mut thread_rng();
    println!("Creating parameters...");
    let params = {
        let c = isnonzeroDemo::<Bls12> {
            check_num: None,
        };

        generate_random_parameters(c, rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    let c1 = isnonzeroDemo::<Bls12> {
        check_num: Some(<Bls12 as ScalarEngine>::Fr::from_str("1").unwrap()),
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();
    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
}