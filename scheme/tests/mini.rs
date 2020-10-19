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
    let proof_bytes = postcard::to_allocvec(&proof).unwrap();
    println!("Groth16 proof...ok, size: {}", proof_bytes.len());

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
    let proof_bytes = postcard::to_allocvec(&proof).unwrap();
    println!("Marlin proof...ok, size: {}", proof_bytes.len());

    assert!(verify_proof(&ivk, &proof, &[Fr::from(10u32)]).unwrap());
}

#[test]
fn mini_bulletproofs() {
    use curve::baby_jubjub::{BabyJubJub, Fr};
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

    let (gens, r1cs, proof, publics) = create_random_proof::<BabyJubJub, _, _>(c, rng).unwrap();

    let proof_bytes = postcard::to_allocvec(&proof).unwrap();
    println!("Bulletproof proof...ok, size: {}", proof_bytes.len());

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
    use scheme::clinkv2::kzg10::{
        create_random_proof, verify_proof, ProveAssignment, VerifyAssignment, KZG10,
    };
    use scheme::clinkv2::r1cs::ConstraintSynthesizer;

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
    let proof_bytes = postcard::to_allocvec(&proof).unwrap();
    println!("Clinkv2 kzg10 proof...ok, size: {}", proof_bytes.len());

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
fn test_mini_spartan_snark() {
    use curve::bn_256::{Bn_256, Fr};
    use math::test_rng;
    use scheme::spartan::snark::{create_random_proof, generate_random_parameters, verify_proof};

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
    let params = generate_random_parameters(c, rng).unwrap();
    let (pk, vk) = params.keypair();

    println!("[snark_spartan]Creating proof...");
    let c1 = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: 10,
    };
    let proof = create_random_proof(&pk, c1, rng).unwrap();
    let proof_bytes = postcard::to_allocvec(&proof).unwrap();
    println!(
        "[snark_spartan]Creating proof...ok, size: {}",
        proof_bytes.len()
    );

    println!("[snark_spartan]Verify proof...");
    assert!(verify_proof::<Bn_256>(&vk, &proof, &vec![Fr::from(10u32)].to_vec(),).unwrap());
    println!("[snark_spartan]Verify proof...ok");
}

#[test]
fn test_mini_spartan_nizk() {
    use curve::bn_256::{Bn_256, Fr};
    use math::test_rng;
    use scheme::spartan::nizk::{create_random_proof, generate_random_parameters, verify_proof};

    println!("\n spartan nizk...");
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: 10,
    };

    println!("[nizk_spartan]Generate parameters...");
    let params = generate_random_parameters(c, rng).unwrap();
    let (pk, vk) = params.keypair();

    println!("[nizk_spartan]Creating proof...");
    let c1 = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: 10,
    };
    let proof = create_random_proof(&pk, c1, rng).unwrap();
    let proof_bytes = postcard::to_allocvec(&proof).unwrap();
    println!(
        "[nizk_spartan]Creating proof...ok, size: {}",
        proof_bytes.len()
    );

    println!("[nizk_spartan]Verify proof...");
    assert!(verify_proof::<Bn_256>(&vk, &proof, &vec![Fr::from(10u32)].to_vec(),).unwrap());
    println!("[nizk_spartan]Verify proof...ok");
}
