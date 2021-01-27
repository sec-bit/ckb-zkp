use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::{One, PrimeField};
use rand::prelude::*;
use std::time::Instant;
use zkp_r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use zkp_spartan::{
    prover::create_nizk_proof, r1cs::generate_r1cs, setup::*, verify::verify_nizk_proof,
};

struct TestDemo<F: PrimeField> {
    lhs: Option<F>,
    rhs: Option<F>,
    ohs: Option<F>,
    phs: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for TestDemo<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let lhs_value = self.lhs;
        let lhs = cs.alloc(
            || "L",
            || lhs_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let rhs_value = self.rhs;
        let rhs = cs.alloc(
            || "R",
            || rhs_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let ohs_value = self.ohs;
        let ohs = cs.alloc(
            || "O",
            || ohs_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let phs_value = self.phs;
        let phs = cs.alloc_input(
            || "P",
            || phs_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        //(1 - lhs) * lhs = 0
        cs.enforce(
            || "lhs boolean constraint",
            |lc| lc + CS::one() - lhs,
            |lc| lc + lhs,
            |lc| lc,
        );

        //(1 - rhs) * rhs = -2
        cs.enforce(
            || "rhs boolean constraint",
            |lc| lc + CS::one() - rhs,
            |lc| lc + rhs,
            |lc| lc - CS::one() - CS::one(),
        );

        // lhs * lhs = 1
        cs.enforce(
            || "lhs boolean constraint",
            |lc| lc + lhs,
            |lc| lc + lhs,
            |lc| lc + CS::one(),
        );

        // rhs * rhs = 4
        cs.enforce(
            || "rhs boolean constraint",
            |lc| lc + rhs,
            |lc| lc + rhs,
            |lc| lc + CS::one() + CS::one() + CS::one() + CS::one(),
        );

        //(1 - lhs) * lhs = 0
        cs.enforce(
            || "lhs boolean constraint",
            |lc| lc + CS::one() - lhs,
            |lc| lc + lhs,
            |lc| lc,
        );

        //(1 - rhs) * rhs = -2
        cs.enforce(
            || "rhs boolean constraint",
            |lc| lc + CS::one() - rhs,
            |lc| lc + rhs,
            |lc| lc - CS::one() - CS::one(),
        );
        // phs * ohs = 1
        cs.enforce(
            || "ohs boolean constraint",
            |lc| lc + phs,
            |lc| lc + ohs,
            |lc| lc + CS::one(),
        );

        // rhs * (rhs + 1) = 6
        cs.enforce(
            || "rhs boolean constraint",
            |lc| lc + rhs,
            |lc| lc + rhs + CS::one(),
            |lc| lc + CS::one() + CS::one() + CS::one() + CS::one() + CS::one() + CS::one(),
        );

        Ok(())
    }
}

pub fn spartan_nizk() {
    let rng = &mut thread_rng();
    let c = TestDemo::<Fr> {
        lhs: None,
        rhs: None,
        ohs: None,
        phs: None,
    };

    println!("Generate parameters...");
    let start = Instant::now();
    let r1cs = generate_r1cs::<E, _>(c).unwrap();
    let params =
        generate_setup_nizk_parameters::<E, _>(rng, r1cs.num_aux, r1cs.num_inputs).unwrap();
    let c1 = TestDemo::<Fr> {
        lhs: Some(Fr::one()),
        rhs: Some(Fr::one() + &Fr::one()),
        ohs: Some(Fr::one()),
        phs: Some(Fr::one()),
    };
    let total_setup = start.elapsed();
    println!("SPARTAN NIZK SETUP TIME: {:?}", total_setup);

    // let mut transcript = Transcript::new(b"spartan nizk");
    println!("Creating proof...");
    let start = Instant::now();
    let proof = create_nizk_proof(&params, &r1cs, c1, rng).unwrap();
    let total_setup = start.elapsed();
    println!("SPARTAN NIZK CREATE PROOF TIME: {:?}", total_setup);

    println!("Verify proof...");
    let start = Instant::now();
    // let mut transcript = Transcript::new(b"spartan nizk");
    let result = verify_nizk_proof::<E>(&params, &r1cs, &vec![Fr::one()], &proof).unwrap();

    assert!(result);
    let total_setup = start.elapsed();
    println!("SPARTAN NIZK VERIFY PROOF TIME: {:?}", total_setup);
}

fn main() {
    println!("begin spartan nizk bls12_381...");
    spartan_nizk();
    println!("end spartan nizk bls12_381...");
}