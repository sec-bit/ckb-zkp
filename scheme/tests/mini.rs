use curve::bls12_381::{Bls12_381 as E, Fr};
use math::{test_rng, One, PrimeField};
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
fn mini_groth16() {
    use scheme::groth16::{
        create_random_proof, generate_random_parameters, verifier::prepare_verifying_key,
        verify_proof,
    };

    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();
    let num = 10;

    println!("Creating parameters...");

    // Create parameters for our circuit
    let params = {
        let c = Mini::<Fr> {
            x: None,
            y: None,
            z: None,
            num: num,
        };

        generate_random_parameters::<E, _, _>(c, rng).unwrap()
    };

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    println!("{}", pvk.gamma_abc_g1.len());

    println!("Creating proofs...");
    let c = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: num,
    };

    let proof = create_random_proof(&params, c, rng).unwrap();

    println!("verifing...");
    assert!(verify_proof(&pvk, &proof, &[Fr::from(10u32)]).unwrap());
}

#[test]
fn mini_marlin() {
    use scheme::marlin::{create_random_proof, index, universal_setup, verify_proof};

    let rng = &mut test_rng();
    let num = 10;

    // TRUSTED SETUP
    println!("Marlin setup...");
    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };

    let srs = universal_setup::<E, _>(2usize.pow(10), rng).unwrap();
    println!("marlin indexer...");
    let (ipk, ivk) = index(&srs, c).unwrap();

    let circuit = Mini {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: num,
    };

    let proof = create_random_proof(&ipk, circuit, rng).unwrap();
    assert!(verify_proof(&ivk, &proof, &[Fr::from(10u32)]).unwrap());
}

#[test]
fn mini_bulletproofs() {
    use scheme::bulletproofs::{create_random_proof, verify_proof};

    let rng = &mut test_rng();
    let num = 10;

    // TRUSTED SETUP
    println!("Bulletproofs prove...");
    let c = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: num,
    };

    let (gens, r1cs, proof, publics) = create_random_proof::<E, _, _>(c, rng).unwrap();

    println!("Bulletproof verify...");
    let _c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };
    assert!(verify_proof(&gens, &proof, &r1cs, &publics.s));
}

use scheme::clinkv2::r1cs as clinkv2_r1cs;

pub struct Clinkv2Mini<F: PrimeField> {
    pub x: Option<F>,
    pub y: Option<F>,
    pub z: Option<F>,
    pub num: u32,
}

impl<F: PrimeField> clinkv2_r1cs::ConstraintSynthesizer<F> for Clinkv2Mini<F> {
    fn generate_constraints<CS: clinkv2_r1cs::ConstraintSystem<F>>(
        self,
        cs: &mut CS,
        index: usize,
    ) -> Result<(), clinkv2_r1cs::SynthesisError> {
        cs.alloc_input(|| "", || Ok(F::one()), index)?;

        let var_x = cs.alloc(
            || "x",
            || {
                self.x
                    .ok_or(clinkv2_r1cs::SynthesisError::AssignmentMissing)
            },
            index,
        )?;

        let var_y = cs.alloc(
            || "y",
            || {
                self.y
                    .ok_or(clinkv2_r1cs::SynthesisError::AssignmentMissing)
            },
            index,
        )?;

        let var_z = cs.alloc_input(
            || "z(output)",
            || {
                self.z
                    .ok_or(clinkv2_r1cs::SynthesisError::AssignmentMissing)
            },
            index,
        )?;

        if index == 0 {
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
fn mini_clinkv2() {
    use scheme::clinkv2::{
        create_random_proof, kzg10::KZG10, r1cs::ConstraintSynthesizer, verify_proof,
        ProveAssignment, VerifyAssignment,
    };

    let n: usize = 100;

    let num = 10;
    let rng = &mut test_rng(); // Only in test code.

    println!("Clinkv2 setup...");
    let degree: usize = n.next_power_of_two();
    let kzg10_pp = KZG10::<E>::setup(degree, false, rng).unwrap();
    let (kzg10_ck, kzg10_vk) = KZG10::<E>::trim(&kzg10_pp, degree).unwrap();

    println!("Clinkv2 proving...");

    let mut prover_pa = ProveAssignment::<E>::default();

    let mut io: Vec<Vec<Fr>> = vec![];
    let mut output: Vec<Fr> = vec![];

    for i in 0..n {
        // Generate a random preimage and compute the image
        {
            // Create an instance of our circuit (with the witness)
            let c = Clinkv2Mini::<Fr> {
                x: Some(Fr::from(2u32)),
                y: Some(Fr::from(3u32)),
                z: Some(Fr::from(10u32)),
                num: num,
            };

            output.push(Fr::from(10u32));
            c.generate_constraints(&mut prover_pa, i).unwrap();
        }
    }
    let one = vec![Fr::one(); n];
    io.push(one);
    io.push(output);

    let proof = create_random_proof(&prover_pa, &kzg10_ck, rng).unwrap();

    println!("Clinkv2 verifying...");

    let c = Clinkv2Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };

    let mut verifier_pa = VerifyAssignment::<E>::default();
    c.generate_constraints(&mut verifier_pa, 0usize).unwrap();

    assert!(verify_proof::<E>(&verifier_pa, &kzg10_vk, &proof, &io).unwrap());
}

#[test]
fn test_mini_spartan() {
    use curve::bn_256::{Bn_256, Fr};
    use math::test_rng;
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

    println!("[snark_spartan]Creating proof...");
    let c1 = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: 10,
    };
    let proof = snark_prover(&params, &r1cs, c1, &encode, rng).unwrap();
    println!("[snark_spartan]Creating proof...ok");

    println!("[snark_spartan]Verify proof...");
    let result = snark_verify::<Bn_256>(
        &params,
        &r1cs,
        vec![Fr::from(10u32)].to_vec(),
        proof,
        encode_commit,
    )
    .is_ok();
    println!("[snark_spartan]Verify proof...ok");

    assert!(result);
}
