use ckb_zkp::gadgets::rescue::RescueConstant;
use math::{test_rng, BitIterator, PrimeField};
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

// Hash Rescue utilizes Sponge Construction
// r, bitrate; c, capacity; M, state value, equal to r + c;
const _R: usize = 2;
const _C: usize = 1;
const M: usize = _R + _C;

const N: usize = 22; // round number

// ALPH * INVALPH == 1 (mod p-1)
// p == 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
const ALPH: [u64; 1] = [5];
const INVALPH: [u64; 4] = [
    0xcfe7f7a98ccccccd,
    0x535cb9d394945a0d,
    0x93736af8679aad17,
    0x26b6a528b427b354,
]; // 0x26b6a528b427b35493736af8679aad17535cb9d394945a0dcfe7f7a98ccccccd

pub fn block_cipher<F>(state: &mut [F], rc: &RescueConstant<F>)
where
    F: PrimeField,
{
    for i in 0..M {
        state[i].add_assign(rc.constants[0][i]);
    }

    let mut af: &[u64];
    for i in 0..2 * N {
        af = &ALPH;
        if i % 2 == 1 {
            af = &INVALPH;
        }
        for j in 0..M {
            state[j] = state[j].pow(af);
        }
        // matrix multiplication
        let mut tmp2 = [F::zero(); M];
        for j in 0..M {
            for k in 0..M {
                let mut t2 = rc.mds[j][k];
                t2.mul_assign(state[k]);
                tmp2[j] += t2;
            }
        }
        for j in 0..M {
            state[j] = tmp2[j] + rc.constants[i + 1][j];
        }
    }
}

pub fn rescue_hash<F: PrimeField>(xl: F, xr: F, constants: &RescueConstant<F>) -> F {
    let mut state = [xl, xr, F::zero()];
    block_cipher(&mut state, &constants);

    // c == 1
    state[0]
}

/// This is our demo circuit for proving knowledge of the
/// preimage of a Rescue hash invocation.

pub struct RescueDemo<'a, F: PrimeField> {
    pub xl: Option<F>,
    pub xr: Option<F>,
    pub constants: &'a RescueConstant<F>,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, F: PrimeField> ConstraintSynthesizer<F> for RescueDemo<'a, F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let xl_value = self.xl;
        let xl = cs.alloc(
            || "preimage xl",
            || xl_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let xr_value = self.xr;
        let xr = cs.alloc(
            || "preimage xl",
            || xr_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let three_value: Option<F> = Some(F::zero());
        let three = cs.alloc(
            || "preimage tmpf",
            || three_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let mut state_value = [xl_value, xr_value, three_value];
        let mut state = [xl, xr, three];
        let cs = &mut cs.ns(|| format!("Preassign"));

        for i in 0..M {
            let tmp_value = state_value[i].map(|mut e| {
                e.add_assign(&self.constants.constants[0][i]);
                e
            });

            let tmp = cs.alloc(
                || "tmp",
                || tmp_value.ok_or(SynthesisError::AssignmentMissing),
            )?;

            cs.enforce(
                || "tmp = (state[i] + Ci) * 1",
                |lc| lc + state[i] + (self.constants.constants[0][i], CS::one()),
                |lc| lc + (F::one(), CS::one()),
                |lc| lc + tmp,
            );

            state_value[i] = tmp_value;
            state[i] = tmp;
        }

        let mut af: &[u64];
        for i in 0..2 * N {
            let cs = &mut cs.ns(|| format!("round {}", i));
            af = &ALPH;
            if i % 2 == 1 {
                af = &INVALPH;
            }

            for j in 0..M {
                let tuple = pow_with_constraint(&state_value[j], &state[j], af, cs)?;
                state_value[j] = tuple.0;
                state[j] = tuple.1;
            }

            let mut tmp2_value = [Some(F::zero()); M];
            let mut tmp2 = Vec::with_capacity(3);
            for j in 0..M {
                tmp2.push(cs.alloc(
                    || "tmp2[j]",
                    || tmp2_value[j].ok_or(SynthesisError::AssignmentMissing),
                )?);
            }

            for j in 0..M {
                for k in 0..M {
                    let tmp3_value: Option<F> = Some(self.constants.mds[j][k]);
                    let tmp3 = cs.alloc(
                        || "tmp3",
                        || tmp3_value.ok_or(SynthesisError::AssignmentMissing),
                    )?;

                    let new_tmp_value = tmp3_value.map(|mut e| {
                        e.mul_assign(&state_value[k].unwrap());
                        e.add_assign(&tmp2_value[j].unwrap());
                        e
                    });

                    let new_tmp = cs.alloc(
                        || "new tmp",
                        || new_tmp_value.ok_or(SynthesisError::AssignmentMissing),
                    )?;

                    cs.enforce(
                        || "new_tmp - tmp2[j] = tmp3_value * state_value[k]",
                        |lc| lc + tmp3,
                        |lc| lc + state[k],
                        |lc| lc + new_tmp - tmp2[j],
                    );

                    tmp2_value[j] = new_tmp_value;
                    tmp2[j] = new_tmp;
                }
            }
            for j in 0..M {
                let tmp_value = tmp2_value[j].map(|mut e| {
                    e.add_assign(&self.constants.constants[i + 1][j]);
                    e
                });

                let tmp = cs.alloc(
                    || "tmp",
                    || tmp_value.ok_or(SynthesisError::AssignmentMissing),
                )?;

                cs.enforce(
                    || "tmp = tmp2[j] + constants[i+1][j]",
                    |lc| lc + tmp2[j] + (self.constants.constants[i + 1][j], CS::one()),
                    |lc| lc + (F::one(), CS::one()),
                    |lc| lc + tmp,
                );

                state[j] = tmp;
                state_value[j] = tmp_value;
            }
        }

        let tmp = cs.alloc_input(
            || "input ",
            || state_value[0].ok_or(SynthesisError::AssignmentMissing),
        )?;

        cs.enforce(
            || "tmp = tmp2[j] + constants[i+1][j]",
            |lc| lc + (F::one(), CS::one()),
            |lc| lc + state[0],
            |lc| lc + tmp,
        );
        Ok(())
    }
}

fn pow_with_constraint<F: PrimeField, CS: ConstraintSystem<F>, S: AsRef<[u64]>>(
    state_value: &Option<F>,
    state: &scheme::r1cs::Variable,
    exp: S,
    cs: &mut CS,
) -> Result<(Option<F>, scheme::r1cs::Variable), SynthesisError> {
    let mut res_value: Option<F> = Some(F::one());
    let mut res = cs.alloc(
        || "res",
        || res_value.ok_or(SynthesisError::AssignmentMissing),
    )?;

    let mut found_one = false;
    for i in BitIterator::new(exp) {
        if !found_one {
            if i {
                found_one = true;
            } else {
                continue;
            }
        }

        let tmp_value = res_value.map(|mut e| {
            e.square_in_place();
            e
        });

        let tmp = cs.alloc(
            || "tmp",
            || tmp_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        cs.enforce(
            || "tmp = res * res",
            |lc| lc + res,
            |lc| lc + res,
            |lc| lc + tmp,
        );

        res_value = tmp_value;
        res = tmp;
        if i {
            let tmp_value = res_value.map(|mut e| {
                e.mul_assign(&(*state_value).unwrap());
                e
            });
            let tmp = cs.alloc(
                || "tmp",
                || tmp_value.ok_or(SynthesisError::AssignmentMissing),
            )?;

            cs.enforce(
                || "tmp = res * state",
                |lc| lc + res,
                |lc| lc + *state,
                |lc| lc + tmp,
            );
            res_value = tmp_value;
            res = tmp;
        }
    }

    Ok((res_value, res))
}

fn main() {
    use rand::Rng;
    use scheme::groth16::{
        create_random_proof, generate_random_parameters, verifier::prepare_verifying_key,
        verify_proof,
    };
    use std::time::{Duration, Instant};

    let rng = &mut test_rng();
    use curve::bn_256::{Bn_256, Fr};
    let constants = RescueConstant::<Fr>::new_fp255();

    println!("Creating parameters...");

    let params = {
        let xl: Fr = rng.gen();
        let xr: Fr = rng.gen();

        let c = RescueDemo::<Fr> {
            xl: Some(xl),
            xr: Some(xr),
            constants: &constants,
        };

        generate_random_parameters::<Bn_256, _, _>(c, rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);
    println!("Creating proofs...");

    // let's benchmark stuff!
    const SAMPLES: u32 = 3;
    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    for _ in 0..SAMPLES {
        let xl: Fr = rng.gen();
        let xr: Fr = rng.gen();
        let image = rescue_hash(xl, xr, &constants);
        println!("xl {} xr {} \n hash: {}", xl, xr, image);
        {
            let start = Instant::now();
            let c = RescueDemo {
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
