use math::PrimeField;
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

struct Mini<F: PrimeField> {
    pub x: Option<F>,
    pub y: Option<F>,
    pub z: Option<F>,
    pub num: u32,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Mini<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let var_x = cs.alloc(|| "x", || self.x.ok_or(SynthesisError::AssignmentMissing))?;

        let var_y = cs.alloc(|| "y", || self.y.ok_or(SynthesisError::AssignmentMissing))?;

        let var_z = cs.alloc_input(
            || "z(output)",
            || self.z.ok_or(SynthesisError::AssignmentMissing),
        )?;

        for _ in 0..self.num {
            cs.enforce(
                || "x * (y + 2) = z",
                |lc| lc + var_x,
                |lc| lc + var_y + (F::from(2u32), CS::one()),
                |lc| lc + var_z,
            );
        }

        Ok(())
    }
}

#[test]
fn test_mini_groth_16() {
    // We're going to use the Groth16 proving system.
    use curve::bn_256::{Bn_256, Fr};
    use math::test_rng;
    use scheme::groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };
    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    println!("Creating parameters...");

    // Create parameters for our circuit
    let params = {
        let c = Mini::<Fr> {
            x: None,
            y: None,
            z: None,
            num: 10,
        };

        generate_random_parameters::<Bn_256, _, _>(c, rng).unwrap()
    };

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    println!("{}", pvk.gamma_abc_g1.len());

    println!("Creating proofs...");
    let c = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: 10,
    };

    let proof = create_random_proof(c, &params, rng).unwrap();

    println!("verifing...");
    assert!(verify_proof(&pvk, &proof, &[Fr::from(10u32)]).unwrap());
}

#[test]
fn test_mini_marlin() {
    use curve::bls12_381::{Bls12_381, Fr};
    use math::test_rng;
    use scheme::marlin::{index, prove, universal_setup, verify};

    let rng = &mut test_rng();

    // TRUSTED SETUP
    println!("Marlin setup...");
    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: 10,
    };

    let srs = universal_setup::<Bls12_381, _>(2usize.pow(10), rng).unwrap();
    println!("marlin indexer...");
    let (ipk, ivk) = index(&srs, c).unwrap();

    let circuit = Mini {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: 10,
    };

    let proof = prove(&ipk, circuit, rng).unwrap();
    assert!(verify(&ivk, &proof, &[Fr::from(10u32)]).unwrap());
}

#[test]
fn test_mini_spartan() {
    use curve::bn_256::{Bn_256, Fr};
    use math::test_rng;
    use merlin::Transcript;
    use scheme::spartan::prover::snark_prover;
    use scheme::spartan::r1cs::generate_r1cs;
    use scheme::spartan::setup::*;
    use scheme::spartan::spark::encode;
    use scheme::spartan::verify::snark_verify;

    println!("\n spartan snark...");
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: 10,
    };

    println!("[snark_spartan]Generate parameters...");
    let r1cs = generate_r1cs::<Bn_256, _>(c).unwrap();

    let params = generate_setup_parameters_with_spark::<Bn_256, _>(
        rng,
        r1cs.num_aux,
        r1cs.num_inputs,
        r1cs.num_constraints,
    )
    .unwrap();
    println!("[snark_spartan]Generate parameters...ok");

    println!("[snark_spartan]Encode...");
    let (encode, encode_commit) = encode::<Bn_256, _>(&params, &r1cs, rng).unwrap();
    println!("[snark_spartan]Encode...ok");

    let mut transcript = Transcript::new(b"spartan snark");
    println!("[snark_spartan]Creating proof...");
    let c1 = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: 10,
    };
    let proof = snark_prover(&params, &r1cs, c1, &encode, rng, &mut transcript).unwrap();
    println!("[snark_spartan]Creating proof...ok");

    println!("[snark_spartan]Verify proof...");
    let mut transcript = Transcript::new(b"spartan snark");
    let result = snark_verify::<Bn_256>(
        &params,
        &r1cs,
        vec![Fr::from(10u32)].to_vec(),
        proof,
        encode_commit,
        &mut transcript,
    )
    .is_ok();
    println!("[snark_spartan]Verify proof...ok");

    assert!(result);
}
