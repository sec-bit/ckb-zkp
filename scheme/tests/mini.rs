use math::PrimeField;
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

struct Mini<F: PrimeField> {
    pub x: Option<F>,
    pub y: Option<F>,
    pub z: Option<F>,
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

        cs.enforce(
            || "x * (y + 2) = z",
            |lc| lc + var_x,
            |lc| lc + var_y + (F::from(2u32), CS::one()),
            |lc| lc + var_z,
        );

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
    };

    let srs = universal_setup::<Bls12_381, _>(2usize.pow(10), rng).unwrap();
    println!("marlin indexer...");
    let (ipk, ivk) = index(&srs, c).unwrap();

    let circuit = Mini {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
    };

    let proof = prove(&ipk, circuit, rng).unwrap();
    assert!(verify(&ivk, &proof, &[Fr::from(10u32)]).unwrap());
}
