use math::Field;
use math::FromBytes;
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

use crate::Vec;

/// This is an implementation of MiMC, specifically a
/// variant named `LongsightF322p3` for BN-256.
/// See http://eprint.iacr.org/2016/492 for more
/// information about this construction.
///
/// ``` ignore
/// function LongsightF322p3(xL ⦂ Fp, xR ⦂ Fp) {
///     for i from 0 up to 321 {
///         xL, xR := xR + (xL + Ci)^3, xL
///     }
///     return xL
/// }
/// ```
pub fn mimc<F: Field>(mut xl: F, mut xr: F, constants: &[F]) -> F {
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
pub fn mimc_hash<F: math::fields::PrimeField + Field>(b: &[u8], constants: &[F]) -> (F, F, F) {
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

        h = mimc(h, v[i], constants);
    }

    (xl, xr, h)
}

/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
pub struct MiMC<'a, F: Field> {
    pub xl: Option<F>,
    pub xr: Option<F>,
    pub constants: &'a [F],
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, F: Field> ConstraintSynthesizer<F> for MiMC<'a, F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
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

/// This is we used MiMC rounds constant.
pub const MIMC_ROUNDS: usize = 322;

/// This is we used MiMC constants's seed, it can derived constants with different pairing curve.
pub const SEED: [u8; 32] = [0; 32];

/// This is we used groth16 seed, it can derived parameters with different pairing curve.
pub const GROTH16_SEED: [u8; 32] = [0; 32];

/// Not used now.
pub const GROTH16_VK: [u8; 32] = [0; 32];

/// it will return MiMC's constants, when use pairing curve as generic type.
pub fn constants<F: Field>() -> [F; MIMC_ROUNDS] {
    constants_with_seed(SEED)
}

/// it will return MiMC's constants, when use pairing curve as generic type, and use custom seed.
pub fn constants_with_seed<F: Field>(seed: [u8; 32]) -> [F; MIMC_ROUNDS] {
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

/// it will return groth16 parameters when use pairing curve as generic type.
#[cfg(feature = "groth16")]
pub fn groth16_params<E: math::PairingEngine>(
    constants: &[E::Fr],
) -> Result<scheme::groth16::Parameters<E>, SynthesisError> {
    groth16_params_with_seed(constants, GROTH16_SEED)
}

/// it will return groth16 parameters, when use pairing curve as generic type, and use custom seed.
#[cfg(feature = "groth16")]
pub fn groth16_params_with_seed<E: math::PairingEngine>(
    constants: &[E::Fr],
    seed: [u8; 32],
) -> Result<scheme::groth16::Parameters<E>, SynthesisError> {
    let c = MiMC::<E::Fr> {
        xl: None,
        xr: None,
        constants: constants,
    };
    use rand::SeedableRng;
    let rng = &mut rand::rngs::StdRng::from_seed(seed);

    scheme::groth16::generate_random_parameters::<E, _, _>(c, rng)
}
