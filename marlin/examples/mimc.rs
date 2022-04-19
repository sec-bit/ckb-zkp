use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::Field;
use rand::prelude::*;
use std::time::{Duration, Instant};
use zkp_marlin::{create_random_proof, index, universal_setup, verify_proof};
use zkp_r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

// We'll use these interfaces to construct our circuit.

const MIMC_ROUNDS: usize = 5;
const SAMPLES: usize = 100; //131070;//16777210;//131070;//1048570;//131070;//16380;//1048574;

/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
struct MimcDemo<'a, F: Field> {
    // xl: Option<F>,
    // xr: Option<F>,
    constants: &'a [F],
    n: usize,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, F: Field> ConstraintSynthesizer<F> for MimcDemo<'a, F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let mut rng = &mut thread_rng();

        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        // Allocate the first component of the preimage.

        for _ in 0..self.n {
            // Generate a random preimage and compute the image
            let xl_0: F = F::rand(&mut rng);
            let xr_0: F = F::rand(&mut rng);
            //let image = mimc(xl, xr, &constants);

            let mut xl_value = Some(xl_0);
            let mut xl = cs.alloc(
                || "preimage xl",
                || xl_value.ok_or(SynthesisError::AssignmentMissing),
            )?;

            // Allocate the second component of the preimage.
            let mut xr_value = Some(xr_0);
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
                    cs.alloc(
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
        }
        Ok(())
    }
}

fn main() {
    let rng = &mut thread_rng();
    let constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();

    let c = MimcDemo::<Fr> {
        constants: &constants,
        n: SAMPLES,
    };

    println!("Running mimc_marlin...");

    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);
    let mut crs_time = Duration::new(0, 0);

    let num = SAMPLES * 70; //.next_power_of_two();
    println!("num: {}", num);
    let start = Instant::now();
    let srs = universal_setup::<E, _>(num, rng).unwrap();
    let (pk, vk) = index(&srs, c).unwrap();
    crs_time += start.elapsed();

    let c = MimcDemo::<Fr> {
        constants: &constants,
        n: SAMPLES,
    };

    let start = Instant::now();
    let proof = create_random_proof(&pk, c, rng).unwrap();
    total_proving += start.elapsed();

    let start = Instant::now();
    assert!(verify_proof(&vk, &proof, &[]).unwrap());
    total_verifying += start.elapsed();

    let total_proving =
        total_proving.subsec_nanos() as f64 / 1_000_000_000f64 + (total_proving.as_secs() as f64);
    let total_verifying = total_verifying.subsec_nanos() as f64 / 1_000_000_000f64
        + (total_verifying.as_secs() as f64);
    let crs_time = crs_time.subsec_nanos() as f64 / 1_000_000_000f64 + (crs_time.as_secs() as f64);

    println!("{:?}", crs_time);
    println!("{:?}", total_proving);
    println!("{:?}", total_verifying);
}
