use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::{BitIteratorBE, PrimeField};
use rand::prelude::*;
use std::time::{Duration, Instant};
use zkp_gadgets::hashes::poseidon::PoseidonConstant;
use zkp_groth16::{
    create_random_proof, generate_random_parameters, verifier::prepare_verifying_key, verify_proof,
};
use zkp_r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError, Variable};

// Hash Poseidon utilizes Sponge Construction
// r, bitrate; c, capacity; M, state value, equal to r + c;
const _R: usize = 2;
const _C: usize = 1;
const RF: usize = 8;
const RP: usize = 83;

const M: usize = _R + _C;
const N: usize = RF + RP; // round number

const ALPH: [u64; 1] = [5];

pub struct PoseidonDemo<'a, F: PrimeField> {
    pub xl: Option<F>,
    pub xr: Option<F>,
    pub constants: &'a PoseidonConstant<F>,
}

pub fn hades_permutation<F>(state: &mut [F], rc: &PoseidonConstant<F>)
where
    F: PrimeField,
{
    for i in 0..N {
        for j in 0..M {
            state[j].add_assign(&rc.ark[i][j]);
        }

        if i < (RF / 2) || i > (RF / 2) {
            // full round
            for j in 0..M {
                state[j] = state[j].pow(ALPH);
            }
        } else {
            // partial round
            state[M - 1] = state[M - 1].pow(ALPH);
        }

        // MixLayer
        let mut tmp2 = [F::zero(); M];
        for j in 0..M {
            for k in 0..M {
                let mut t2 = rc.mds[j][k];
                t2.mul_assign(state[k]);
                tmp2[j] += t2;
            }
        }
        for j in 0..M {
            state[j] = tmp2[j];
        }
    }
}

pub fn poseidon_hash<F: PrimeField>(xl: F, xr: F, constants: &PoseidonConstant<F>) -> F {
    let mut state = [xl, xr, F::zero()];
    hades_permutation(&mut state, &constants);
    // c == 1
    state[0]
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, F: PrimeField> ConstraintSynthesizer<F> for PoseidonDemo<'a, F> {
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

        for i in 0..N {
            let cs = &mut cs.ns(|| format!("round {}", i));

            for j in 0..M {
                let tmp_value = state_value[j].map(|mut e| {
                    e.add_assign(&self.constants.ark[i][j]);
                    e
                });

                let tmp = cs.alloc(
                    || "tmp",
                    || tmp_value.ok_or(SynthesisError::AssignmentMissing),
                )?;

                cs.enforce(
                    || "tmp = (state[j] + Ci) * 1",
                    |lc| lc + state[j] + (self.constants.ark[i][j], CS::one()),
                    |lc| lc + (F::one(), CS::one()),
                    |lc| lc + tmp,
                );

                state_value[j] = tmp_value;
                state[j] = tmp;
            }

            if i < (RF / 2) || i > (RF / 2) {
                // full round
                for j in 0..M {
                    let tuple = pow_with_constraint(&state_value[j], &state[j], ALPH, cs)?;
                    state_value[j] = tuple.0;
                    state[j] = tuple.1;
                }
            } else {
                // partial round
                let tuple = pow_with_constraint(&state_value[M - 1], &state[M - 1], ALPH, cs)?;
                state_value[M - 1] = tuple.0;
                state[M - 1] = tuple.1;
            }

            // Mix Layer
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
                state[j] = tmp2[j];
                state_value[j] = tmp2_value[j];
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
    state: &Variable,
    exp: S,
    cs: &mut CS,
) -> Result<(Option<F>, Variable), SynthesisError> {
    let mut res_value: Option<F> = Some(F::one());
    let mut res = cs.alloc(
        || "res",
        || res_value.ok_or(SynthesisError::AssignmentMissing),
    )?;

    let mut found_one = false;
    for i in BitIteratorBE::new(exp) {
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

    // println!("cs.num_constraint(): {}", cs.num_constraints());
    Ok((res_value, res))
}

fn main() {
    let mut rng = thread_rng();
    let constants = PoseidonConstant::<Fr>::new_fp255();

    println!("Creating parameters...");

    let params = {
        let xl: Fr = rng.gen();
        let xr: Fr = rng.gen();

        let c = PoseidonDemo::<Fr> {
            xl: Some(xl),
            xr: Some(xr),
            constants: &constants,
        };

        generate_random_parameters::<E, _, _>(c, &mut rng).unwrap()
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

        let image = poseidon_hash(xl, xr, &constants);
        println!("xl {} xr {} \n hash: {}", xl, xr, image);
        let start = Instant::now();
        {
            let c = PoseidonDemo {
                xl: Some(xl),
                xr: Some(xr),
                constants: &constants,
            };

            let proof = create_random_proof(&params, c, &mut rng).unwrap();

            assert!(verify_proof(&pvk, &proof, &[image]).unwrap());
        }
        total_proving += start.elapsed();

        let start = Instant::now();
        total_verifying += start.elapsed();
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
