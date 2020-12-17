use math::PrimeField;
use math::{One, PairingEngine};
use rand::thread_rng;
use scheme::r1cs::ConstraintSynthesizer;
use scheme::r1cs::ConstraintSystem;
use scheme::r1cs::SynthesisError;
use scheme::spartan::prover::create_snark_proof;
use scheme::spartan::r1cs::generate_r1cs;
use scheme::spartan::setup::*;
use scheme::spartan::spark::encode;
use scheme::spartan::verify::verify_snark_proof;
use std::time::Instant;

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

pub fn spartan_snark_bls12_381() {
    use curve::bls12_381::{Bls12_381, Fr};
    println!("\n spartan snark...");
    let rng = &mut thread_rng();
    let c = TestDemo::<Fr> {
        lhs: None,
        rhs: None,
        ohs: None,
        phs: None,
    };

    let r1cs = generate_r1cs::<Bls12_381, _>(c).unwrap();
    let start = Instant::now();
    let params = generate_setup_snark_parameters::<Bls12_381, _>(
        rng,
        r1cs.num_aux,
        r1cs.num_inputs,
        r1cs.num_constraints,
    )
    .unwrap();

    let c1 = TestDemo::<Fr> {
        lhs: Some(<Bls12_381 as PairingEngine>::Fr::one()),
        rhs: Some(
            <Bls12_381 as PairingEngine>::Fr::one() + &<Bls12_381 as PairingEngine>::Fr::one(),
        ),
        ohs: Some(<Bls12_381 as PairingEngine>::Fr::one()),
        phs: Some(<Bls12_381 as PairingEngine>::Fr::one()),
    };
    let total_setup = start.elapsed();
    println!("SPARTAN SNARK SETUP TIME: {:?}", total_setup);
    let (encode, encode_commit) = encode::<Bls12_381, _>(&params, &r1cs, rng).unwrap();

    // let mut transcript = Transcript::new(b"spartan snark");
    let start = Instant::now();
    let proof = create_snark_proof(&params, &r1cs, c1, &encode, rng).unwrap();
    let total_setup = start.elapsed();
    println!("SPARTAN SNARK CREATE PROOF TIME: {:?}", total_setup);

    let start = Instant::now();
    // let mut transcript = Transcript::new(b"spartan snark");
    let result = verify_snark_proof::<Bls12_381>(
        &params,
        &r1cs,
        &vec![<Bls12_381 as PairingEngine>::Fr::one()],
        &proof,
        &encode_commit,
    )
    .is_ok();
    let total_setup = start.elapsed();
    println!("SPARTAN SNARK VERIFY PROOF TIME: {:?}", total_setup);

    assert!(result);
}

pub fn spartan_snark_bn_256() {
    use curve::bn_256::{Bn_256, Fr};
    println!("\n spartan snark...");
    let rng = &mut thread_rng();
    let c = TestDemo::<Fr> {
        lhs: None,
        rhs: None,
        ohs: None,
        phs: None,
    };

    let start = Instant::now();
    let r1cs = generate_r1cs::<Bn_256, _>(c).unwrap();

    let params = generate_setup_snark_parameters::<Bn_256, _>(
        rng,
        r1cs.num_aux,
        r1cs.num_inputs,
        r1cs.num_constraints,
    )
    .unwrap();

    let c1 = TestDemo::<Fr> {
        lhs: Some(<Bn_256 as PairingEngine>::Fr::one()),
        rhs: Some(<Bn_256 as PairingEngine>::Fr::one() + &<Bn_256 as PairingEngine>::Fr::one()),
        ohs: Some(<Bn_256 as PairingEngine>::Fr::one()),
        phs: Some(<Bn_256 as PairingEngine>::Fr::one()),
    };
    let total_setup = start.elapsed();
    println!("SPARTAN SNARK SETUP TIME: {:?}", total_setup);

    let (encode, encode_commit) = encode::<Bn_256, _>(&params, &r1cs, rng).unwrap();

    let start = Instant::now();
    let proof = create_snark_proof(&params, &r1cs, c1, &encode, rng).unwrap();
    let total_setup = start.elapsed();
    println!("SPARTAN SNARK CREATE PROOF TIME: {:?}", total_setup);

    let _start = Instant::now();
    let result = verify_snark_proof::<Bn_256>(
        &params,
        &r1cs,
        &vec![<Bn_256 as PairingEngine>::Fr::one()],
        &proof,
        &encode_commit,
    )
    .is_ok();
    println!("SPARTAN SNARK VERIFY PROOF TIME: {:?}", total_setup);

    assert!(result);
}

fn main() {
    println!("begin spartan snark bls12_381...");
    spartan_snark_bls12_381();
    println!("end spartan snark bls12_381...");
    println!("begin spartan snark bn_256...");
    spartan_snark_bn_256();
    println!("end spartan snark bn_256...");
}
