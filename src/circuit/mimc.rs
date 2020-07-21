//! Circuits for the [MiMC] hash function and its constants function.
//!
//! [MiMC]: http://eprint.iacr.org/2016/492

use math::{Field, FromBytes, PrimeField};

use crate::Vec;

/// This is we used MiMC rounds constant.
pub const MIMC_ROUNDS: usize = 322;

/// This is we used MiMC constants's seed, it can derived constants with different pairing curve.
pub const SEED: [u8; 32] = [0; 32];

/// it will return MiMC's constants, when use pairing curve as generic type.
fn _constants<F: Field>() -> [F; MIMC_ROUNDS] {
    _constants_with_seed(SEED)
}

/// it will return MiMC's constants, when use pairing curve as generic type, and use custom seed.
fn _constants_with_seed<F: Field>(seed: [u8; 32]) -> [F; MIMC_ROUNDS] {
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
fn mimc<F: Field>(mut xl: F, mut xr: F, constants: &[F]) -> F {
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
pub fn mimc_hash<F: PrimeField>(b: &[u8], constants: &[F]) -> (F, F, F) {
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

//pub fn mimc<F: PrimeField, CS: ConstraintSystem<F>>(mut cs: CS, xl: F, xr: F) {}
