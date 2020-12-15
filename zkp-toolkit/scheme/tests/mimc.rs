// For randomness (during paramgen and proof generation)
use rand::Rng;

// Bring in some tools for using pairing-friendly curves
use curve::bn_256::{Bn_256, Fr};
use math::{test_rng, Field};

// We're going to use the BN-256 pairing-friendly elliptic curve.

// We'll use these interfaces to construct our circuit.
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

const MIMC_ROUNDS: usize = 322;

/// This is an implementation of MiMC, specifically a
/// variant named `LongsightF322p3` for BN-256.
/// See http://eprint.iacr.org/2016/492 for more
/// information about this construction.
///
/// ```
/// function LongsightF322p3(xL ⦂ Fp, xR ⦂ Fp) {
///     for i from 0 up to 321 {
///         xL, xR := xR + (xL + Ci)^3, xL
///     }
///     return xL
/// }
/// ```
fn mimc<F: Field>(mut xl: F, mut xr: F, constants: &[F]) -> F {
    assert_eq!(constants.len(), MIMC_ROUNDS);

    for i in 0..MIMC_ROUNDS {
        let mut tmp1 = xl;
        tmp1.add_assign(&constants[i]);
        let mut tmp2 = tmp1;
        tmp2.square_in_place();
        tmp2.mul_assign(&tmp1);
        tmp2.add_assign(&xr);
        xr = xl;
        xl = tmp2;
    }

    xl
}

/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
struct MiMCDemo<'a, F: Field> {
    xl: Option<F>,
    xr: Option<F>,
    constants: &'a [F],
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, F: Field> ConstraintSynthesizer<F> for MiMCDemo<'a, F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        // Allocate the first component of the preimage.
        let mut xl_value = self.xl;
        let mut xl = cs.alloc(
            || "preimage xl",
            || xl_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Allocate the second component of the preimage.
        let mut xr_value = self.xr;
        let mut xr = cs.alloc(
            || "preimage xr",
            || xr_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        for i in 0..MIMC_ROUNDS {
            // xL, xR := xR + (xL + Ci)^3, xL
            let cs = &mut cs.ns(|| format!("round {}", i));

            // tmp = (xL + Ci)^2
            let tmp_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.square_in_place();
                e
            });
            let tmp = cs.alloc(
                || "tmp",
                || tmp_value.ok_or(SynthesisError::AssignmentMissing),
            )?;

            cs.enforce(
                || "tmp = (xL + Ci)^2",
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + tmp,
            );

            // new_xL = xR + (xL + Ci)^3
            // new_xL = xR + tmp * (xL + Ci)
            // new_xL - xR = tmp * (xL + Ci)
            let new_xl_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.mul_assign(&tmp_value.unwrap());
                e.add_assign(&xr_value.unwrap());
                e
            });

            let new_xl = if i == (MIMC_ROUNDS - 1) {
                // This is the last round, xL is our image and so
                // we allocate a public input.
                cs.alloc_input(
                    || "image",
                    || new_xl_value.ok_or(SynthesisError::AssignmentMissing),
                )?
            } else {
                cs.alloc(
                    || "new_xl",
                    || new_xl_value.ok_or(SynthesisError::AssignmentMissing),
                )?
            };

            cs.enforce(
                || "new_xL = xR + (xL + Ci)^3",
                |lc| lc + tmp,
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + new_xl - xr,
            );

            // xR = xL
            xr = xl;
            xr_value = xl_value;

            // xL = new_xL
            xl = new_xl;
            xl_value = new_xl_value;
        }

        Ok(())
    }
}

#[test]
fn test_mimc_groth16() {
    // We're going to use the Groth16 proving system.
    use scheme::groth16::{
        create_random_proof, generate_random_parameters, verifier::prepare_verifying_key,
        verify_proof,
    };
    use std::time::{Duration, Instant};

    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    // Generate the MiMC round constants
    let constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();

    println!("Creating parameters...");

    // Create parameters for our circuit
    let params = {
        let c = MiMCDemo::<Fr> {
            xl: None,
            xr: None,
            constants: &constants,
        };

        generate_random_parameters::<Bn_256, _, _>(c, rng).unwrap()
    };

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");
    const SAMPLES: u32 = 3;
    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    for _ in 0..SAMPLES {
        // Generate a random preimage and compute the image
        let xl = rng.gen();
        let xr = rng.gen();
        let image = mimc(xl, xr, &constants);

        let start = Instant::now();
        {
            // Create an instance of our circuit (with the
            // witness)
            let c = MiMCDemo {
                xl: Some(xl),
                xr: Some(xr),
                constants: &constants,
            };

            let proof = create_random_proof(&params, c, rng).unwrap();
            total_proving += start.elapsed();

            let start = Instant::now();
            assert!(verify_proof(&pvk, &proof, &[image]).unwrap());
            total_verifying += start.elapsed();
        }
    }
    let proving_avg = total_proving / SAMPLES;
    let proving_avg =
        proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

    let verifying_avg = total_verifying / SAMPLES;
    let verifying_avg =
        verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (verifying_avg.as_secs() as f64);

    println!("Average proving time: {:?} seconds", proving_avg);
    println!("Average verifying time: {:?} seconds", verifying_avg)
}

#[test]
fn test_mimc_spartan() {
    use scheme::spartan::prover::create_snark_proof;
    use scheme::spartan::r1cs::generate_r1cs;
    use scheme::spartan::setup::*;
    use scheme::spartan::spark::encode;
    use scheme::spartan::verify::verify_snark_proof;
    use std::time::{Duration, Instant};

    println!("\n spartan snark...");
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    // Generate the MiMC round constants
    let constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();
    let c = MiMCDemo::<Fr> {
        xl: None,
        xr: None,
        constants: &constants,
    };

    println!("[snark_spartan]Generate parameters...");
    let r1cs = generate_r1cs::<Bn_256, _>(c).unwrap();

    let params = generate_setup_snark_parameters::<Bn_256, _>(
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
    const SAMPLES: u32 = 3;
    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    for _ in 0..SAMPLES {
        // Generate a random preimage and compute the image
        let xl = rng.gen();
        let xr = rng.gen();
        let image = mimc(xl, xr, &constants);

        let start = Instant::now();
        {
            // Create an instance of our circuit (with the
            // witness)
            let c1 = MiMCDemo {
                xl: Some(xl),
                xr: Some(xr),
                constants: &constants,
            };
            let proof = create_snark_proof(&params, &r1cs, c1, &encode, rng).unwrap();
            println!("[snark_spartan]Creating proof...ok");
            total_proving += start.elapsed();

            let start = Instant::now();
            let result = verify_snark_proof::<Bn_256>(
                &params,
                &r1cs,
                &vec![image].to_vec(),
                &proof,
                &encode_commit,
            )
            .is_ok();
            println!("[snark_spartan]Verify proof...ok");

            assert!(result);
            total_verifying += start.elapsed();
        }
    }
    let proving_avg = total_proving / SAMPLES;
    let proving_avg =
        proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

    let verifying_avg = total_verifying / SAMPLES;
    let verifying_avg =
        verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (verifying_avg.as_secs() as f64);

    println!("Average proving time: {:?} seconds", proving_avg);
    println!("Average verifying time: {:?} seconds", verifying_avg)
}

#[test]
fn test_mimc_nizk_spartan() {
    use scheme::spartan::prover::create_nizk_proof;
    use scheme::spartan::r1cs::generate_r1cs;
    use scheme::spartan::setup::*;
    use scheme::spartan::verify::verify_nizk_proof;
    use std::time::{Duration, Instant};

    println!("\n spartan nizk...");
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    // Generate the MiMC round constants
    let constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();
    let c = MiMCDemo::<Fr> {
        xl: None,
        xr: None,
        constants: &constants,
    };

    println!("[nizk_spartan]Generate parameters...");
    let r1cs = generate_r1cs::<Bn_256, _>(c).unwrap();

    let params =
        generate_setup_nizk_parameters::<Bn_256, _>(rng, r1cs.num_aux, r1cs.num_inputs).unwrap();
    println!("[nizk_spartan]Generate parameters...ok");

    println!("[nizk_spartan]Creating proof...");
    const SAMPLES: u32 = 3;
    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    for _ in 0..SAMPLES {
        // Generate a random preimage and compute the image
        let xl = rng.gen();
        let xr = rng.gen();
        let image = mimc(xl, xr, &constants);

        let start = Instant::now();
        {
            // Create an instance of our circuit (with the
            // witness)
            let c = MiMCDemo {
                xl: Some(xl),
                xr: Some(xr),
                constants: &constants,
            };
            let proof = create_nizk_proof(&params, &r1cs, c, rng).unwrap();
            println!("[nizk_spartan]Creating proof...ok");
            total_proving += start.elapsed();

            let start = Instant::now();
            let result =
                verify_nizk_proof::<Bn_256>(&params, &r1cs, &vec![image].to_vec(), &proof).is_ok();
            println!("[nizk_spartan]Verify proof...ok");

            assert!(result);
            total_verifying += start.elapsed();
        }
    }
    let proving_avg = total_proving / SAMPLES;
    let proving_avg =
        proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

    let verifying_avg = total_verifying / SAMPLES;
    let verifying_avg =
        verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (verifying_avg.as_secs() as f64);

    println!("Average proving time: {:?} seconds", proving_avg);
    println!("Average verifying time: {:?} seconds", verifying_avg)
}
