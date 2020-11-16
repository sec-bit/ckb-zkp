use ckb_zkp::gadgets::rescue::RescueConstant;
use math::One;
use math::{test_rng, BitIterator, PrimeField};

use curve::bn_256::{Bn_256, Fr};
use rand::Rng;
use scheme::clinkv2::kzg10::{
    create_random_proof, verify_proof, ProveAssignment, VerifyAssignment, KZG10,
};
use scheme::clinkv2::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use std::time::{Duration, Instant};

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
        let mut tmp2 = [F::one(); M];
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
    let mut state = [xl, xr, F::one()];
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
        index: usize,
    ) -> Result<(), SynthesisError> {

        cs.alloc_input(|| "", || Ok(F::one()), index)?;

        let xl_value = self.xl;
        let xl = cs.alloc(
            || "preimage xl",
            || xl_value.ok_or(SynthesisError::AssignmentMissing),
            index,
        )?;

        let xr_value = self.xr;
        let xr = cs.alloc(
            || "preimage xl",
            || xr_value.ok_or(SynthesisError::AssignmentMissing),
            index,
        )?;

        let three_value: Option<F> = Some(F::one());
        let three = cs.alloc(
            || "preimage tmpf",
            || three_value.ok_or(SynthesisError::AssignmentMissing),
            index,
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
                index,
            )?;

            if index == 0 {
                cs.enforce(
                    || "tmp = (state[i] + Ci) * 1",
                    |lc| lc + state[i] + (self.constants.constants[0][i], CS::one()),
                    |lc| lc + (F::one(), CS::one()),
                    |lc| lc + tmp,
                );
            }

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
                let tuple = pow_with_constraint(&state_value[j], &state[j], af, cs, index)?;
                state_value[j] = tuple.0;
                state[j] = tuple.1;
            }

            let mut tmp2_value = [Some(F::one()); M];
            let mut tmp2 = Vec::with_capacity(3);
            for j in 0..M {
                tmp2.push(cs.alloc(
                    || "tmp2[j]",
                    || tmp2_value[j].ok_or(SynthesisError::AssignmentMissing),
                    index,
                )?);
            }

            for j in 0..M {
                for k in 0..M {
                    let tmp3_value: Option<F> = Some(self.constants.mds[j][k]);
                    let tmp3 = cs.alloc(
                        || "tmp3",
                        || tmp3_value.ok_or(SynthesisError::AssignmentMissing),
                        index,
                    )?;

                    let new_tmp_value = tmp3_value.map(|mut e| {
                        e.mul_assign(&state_value[k].unwrap());
                        e.add_assign(&tmp2_value[j].unwrap());
                        e
                    });

                    let new_tmp = cs.alloc(
                        || "new tmp",
                        || new_tmp_value.ok_or(SynthesisError::AssignmentMissing),
                        index,
                    )?;

                    if index == 0 {
                        cs.enforce(
                            || "new_tmp - tmp2[j] = tmp3_value * state_value[k]",
                            |lc| lc + tmp3,
                            |lc| lc + state[k],
                            |lc| lc + new_tmp - tmp2[j],
                        );
                    }

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
                    index,
                )?;

                if index == 0 {
                    cs.enforce(
                        || "tmp = tmp2[j] + constants[i+1][j]",
                        |lc| lc + tmp2[j] + (self.constants.constants[i + 1][j], CS::one()),
                        |lc| lc + (F::one(), CS::one()),
                        |lc| lc + tmp,
                    );
                }

                state[j] = tmp;
                state_value[j] = tmp_value;
            }
        }

        let tmp = cs.alloc_input(
            || "input ",
            || state_value[0].ok_or(SynthesisError::AssignmentMissing),
            index,
        )?;

        if index == 0 {
            cs.enforce(
                || "tmp = tmp2[j] + constants[i+1][j]",
                |lc| lc + (F::one(), CS::one()),
                |lc| lc + state[0],
                |lc| lc + tmp,
            );
        }
        Ok(())
    }
}

fn pow_with_constraint<F: PrimeField, CS: ConstraintSystem<F>, S: AsRef<[u64]>>(
    state_value: &Option<F>,
    state: &scheme::clinkv2::r1cs::Variable,
    exp: S,
    cs: &mut CS,
    index: usize,
) -> Result<(Option<F>, scheme::clinkv2::r1cs::Variable), SynthesisError> {
    let mut res_value: Option<F> = Some(F::one());
    let mut res = cs.alloc(
        || "res",
        || res_value.ok_or(SynthesisError::AssignmentMissing),
        index,
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
            index,
        )?;

        if index == 0 {
            cs.enforce(
                || "tmp = res * res",
                |lc| lc + res,
                |lc| lc + res,
                |lc| lc + tmp,
            );
        }

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
                index,
            )?;

            if index == 0 {
                cs.enforce(
                    || "tmp = res * state",
                    |lc| lc + res,
                    |lc| lc + *state,
                    |lc| lc + tmp,
                );
            }
            res_value = tmp_value;
            res = tmp;
        }
    }

    Ok((res_value, res))
}

fn main() {
    println!("Creating parameters...");
    let mut rng = &mut test_rng();
    const SAMPLES: usize = 8;
    let constants = RescueConstant::<Fr>::new_fp255();

    // Create parameters for our circuit
    println!("rescue_clinkv2 setup:");
    let start = Instant::now();
    let degree: usize = SAMPLES.next_power_of_two();
    let kzg10_pp = KZG10::<Bn_256>::setup(degree, false, &mut rng).unwrap();
    let (kzg10_ck, kzg10_vk) = KZG10::<Bn_256>::trim(&kzg10_pp, degree).unwrap();
    let setup_time = start.elapsed();

    println!("rescue_clinkv2 prepare proof.");
    let mut prover_pa = ProveAssignment::<Bn_256>::default();
    let mut io: Vec<Vec<Fr>> = vec![];
    let mut output: Vec<Fr> = vec![];
    for i in 0..SAMPLES {
        let xl: Fr = rng.gen();
        let xr: Fr = rng.gen();
        let image = rescue_hash(xl, xr, &constants);
        output.push(image);
        println!("xl {} xr {} \n hash: {}", xl, xr, image);
        {
            // Create an instance of our circuit (with the witness)
            let c = RescueDemo {
                xl: Some(xl),
                xr: Some(xr),
                constants: &constants,
            };
            c.generate_constraints(&mut prover_pa, i).unwrap();
        }
    }

    let one = vec![Fr::one(); SAMPLES];
    io.push(one);
    io.push(output);

    // Create a clinkv2 proof with our parameters.
    println!("Create prove...");
    let start = Instant::now();
    let proof = create_random_proof(&prover_pa, &kzg10_ck, rng).unwrap();
    let prove_time = start.elapsed();
    let proof_bytes = postcard::to_allocvec(&proof).unwrap();
    println!("Clinkv2-ipa mimc proof...ok, size: {}", proof_bytes.len());

    // verify proof
    println!("Start verify prepare...");
    let start = Instant::now();
    let mut verifier_pa = VerifyAssignment::<Bn_256>::default();

    // Create an instance of our circuit (with the witness)
    let xl: Fr = rng.gen();
    let xr: Fr = rng.gen();
    let verify_c = RescueDemo {
        xl: Some(xl),
        xr: Some(xr),
        constants: &constants,
    };
    verify_c
        .generate_constraints(&mut verifier_pa, 0usize)
        .unwrap();

    // Check the proof
    assert!(verify_proof(&verifier_pa, &kzg10_vk, &proof, &io).unwrap());
    let verify_time = start.elapsed();
    println!("rescue_clinkv2 setup_time: {:?}", setup_time);
    println!("rescue_clinkv2 create proof: {:?}", prove_time);
    println!("rescue_clinkv2 verify proof: {:?}", verify_time);
}
