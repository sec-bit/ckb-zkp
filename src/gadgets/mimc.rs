//! Circuits for the [MiMC] hash function and its constants function.
//!
//! [MiMC]: http://eprint.iacr.org/2016/492

use math::{Field, FromBytes, PrimeField};
use scheme::r1cs::{ConstraintSystem, SynthesisError, Variable};

use crate::Vec;

use super::abstract_hash::{AbstractHash, AbstractHashOutput};

/// This is we used MiMC rounds constant.
pub const MIMC_ROUNDS: usize = 322;

/// This is we used MiMC constants's seed, it can derived constants with different pairing curve.
pub const SEED: [u8; 32] = [0; 32];

/// it will return MiMC's constants, when use pairing curve as generic type.
pub fn constants<F: Field>() -> [F; MIMC_ROUNDS] {
    constants_with_seed(SEED)
}

/// it will return MiMC's constants, when use pairing curve as generic type, and use custom seed.
fn constants_with_seed<F: Field>(seed: [u8; 32]) -> [F; MIMC_ROUNDS] {
    use rand::{Rng, SeedableRng};
    let rng = &mut rand::rngs::StdRng::from_seed(seed);

    let mut constants = [F::zero(); MIMC_ROUNDS];

    let mut i = 0;
    loop {
        let new_seed: [u8; 32] = rng.gen();
        if let Some(f) = F::from_random_bytes(&new_seed) {
            constants[i] = f;
            i += 1;
            if i == MIMC_ROUNDS {
                break;
            }
        }
    }

    constants
}

/// This is an implementation of MiMC, specifically a
/// variant named `LongsightF322p3` for BN-256.
/// See http://eprint.iacr.org/2016/492 for more
/// information about this construction.
fn mimc_block<F: Field>(mut xl: F, mut xr: F, constants: &[F]) -> F {
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

/// mimc hash function.
fn mimc_hash<F: PrimeField>(b: &[u8], constants: &[F]) -> (F, F, F) {
    let mut v: Vec<F> = Vec::new();
    let n = <F::BigInt as math::BigInteger>::NUM_LIMBS * 8;
    for i in 0..(b.len() / n) {
        let repr = F::BigInt::read(&b[i * n..(i + 1) * n]).unwrap_or(Default::default());
        v.push(F::from_repr(repr));
    }

    if b.len() % n != 0 {
        let repr = F::BigInt::read(&b[(b.len() / n) * n..]).unwrap_or(Default::default());
        v.push(F::from_repr(repr));
    }

    let mut h: F = F::zero();
    let xr = v[v.len() - 1].clone();
    let mut xl = F::zero();

    for i in 0..v.len() {
        if i == v.len() - 1 {
            xl = h.clone();
        }

        h = mimc_block(h, v[i], constants);
    }

    (xl, xr, h)
}

pub fn hash<F: PrimeField>(b: &[u8]) -> F {
    mimc_hash(b, &constants()).2
}

pub fn mimc<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    b: &[u8],
) -> Result<F, SynthesisError> {
    let constants = constants::<F>();
    let (mut xl, mut xr, image) = mimc_hash(b, &constants);

    let mut var_xl = cs.alloc(|| "preimage xl", || Ok(xl))?;
    let mut var_xr = cs.alloc(|| "preimage xr", || Ok(xr))?;

    for i in 0..MIMC_ROUNDS {
        let mut n_cs = cs.ns(|| format!("rounds_{}", i));

        let tmp = *((xl + constants[i]).square_in_place());
        let var_tmp = n_cs.alloc(|| "tmp", || Ok(tmp))?;

        n_cs.enforce(
            || "tmp = (xL + Ci)^2",
            |lc| lc + var_xl + (constants[i], CS::one()),
            |lc| lc + var_xl + (constants[i], CS::one()),
            |lc| lc + var_tmp,
        );

        let new_xl = (xl + constants[i]) * tmp + xr;
        let var_new_xl = if i == (MIMC_ROUNDS - 1) {
            n_cs.alloc(|| "image", || Ok(new_xl))
        } else {
            n_cs.alloc(|| "new_xl", || Ok(new_xl))
        }?;

        n_cs.enforce(
            || "new_xL = xR + (xL + Ci)^3",
            |lc| lc + var_tmp,
            |lc| lc + var_xl + (constants[i], CS::one()),
            |lc| lc + var_new_xl - var_xr,
        );

        xr = xl;
        var_xr = var_xl;

        xl = new_xl;
        var_xl = var_new_xl;
    }

    Ok(image)
}

/// implement AbstractHashOutput.
#[derive(Clone)]
pub struct AbstractHashMimcOutput<F: PrimeField> {
    value: Option<F>,
    variable: Variable,
}

impl<F: PrimeField> AbstractHashMimcOutput<F> {
    pub fn alloc<CS: ConstraintSystem<F>>(
        mut cs: CS,
        f: Option<F>, // mimc params
    ) -> Result<Self, SynthesisError> {
        let var = cs.alloc(
            || "mimc_hash",
            || f.ok_or(SynthesisError::AssignmentMissing),
        )?;

        Ok(Self {
            value: f,
            variable: var,
        })
    }

    pub fn alloc_input<CS: ConstraintSystem<F>>(
        mut cs: CS,
        f: Option<F>, // mimc params
    ) -> Result<Self, SynthesisError> {
        let var = cs.alloc_input(
            || "mimc_hash",
            || f.ok_or(SynthesisError::AssignmentMissing),
        )?;

        Ok(Self {
            value: f,
            variable: var,
        })
    }

    pub fn get_value(&self) -> Option<F> {
        self.value
    }
}

impl<F: PrimeField> AbstractHashOutput<F> for AbstractHashMimcOutput<F> {
    fn get_variables(&self) -> Vec<Variable> {
        vec![self.variable]
    }

    fn get_variable_values(&self) -> Vec<Option<F>> {
        vec![self.value]
    }
}

// implement AbstractHash.
pub struct AbstractHashMimc<F>(core::marker::PhantomData<F>);

impl<F: PrimeField> AbstractHash<F> for AbstractHashMimc<F> {
    type Output = AbstractHashMimcOutput<F>;

    fn hash_enforce<CS: ConstraintSystem<F>>(
        mut cs: CS,
        params: &[&Self::Output],
    ) -> Result<Self::Output, SynthesisError> {
        let mut bytes = vec![];
        for o in params.iter() {
            if let Some(l) = o.get_value() {
                l.write(&mut bytes)
                    .map_err(|e| SynthesisError::IoError(e))?;
            } else {
                return Err(SynthesisError::AssignmentMissing);
            }
        }

        let r = mimc(cs.ns(|| format!("mimc_hash")), &bytes)?;

        AbstractHashMimcOutput::alloc(cs.ns(|| "mimc_output"), Some(r))
    }
}

#[cfg(test)]
mod test {
    use curve::bn_256::Fr;
    use math::test_rng;
    use rand::prelude::*;
    use scheme::r1cs::ConstraintSystem;

    use super::super::test_constraint_system::TestConstraintSystem;
    use super::*;

    #[test]
    fn test_mimc_hash() {
        let rng = &mut test_rng();

        for _ in 0..10 {
            let bytes: Vec<u8> = (0..100).map(|_| rng.next_u32() as u8).collect();
            let hash1 = hash::<Fr>(&bytes);
            let mut cs = TestConstraintSystem::<Fr>::new();
            let hash2 = mimc(cs.ns(|| "mimc hash"), &bytes).unwrap();
            assert_eq!(hash1, hash2);
            assert!(cs.is_satisfied());
            assert_eq!(644, cs.num_constraints());
        }
    }
}
