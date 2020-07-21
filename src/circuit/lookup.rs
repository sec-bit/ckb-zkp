//! Window table lookup gadgets.

use core::iter::IntoIterator;
use math::PrimeField;
use scheme::r1cs::{ConstraintSystem, SynthesisError};

use super::{boolean::Boolean, fr::AllocatedFr};

// Synthesize the constants for each base pattern.
fn synth<'a, F: PrimeField, I>(window_size: usize, constants: I, assignment: &mut [F])
where
    I: IntoIterator<Item = &'a F>,
{
    assert_eq!(assignment.len(), 1 << window_size);
    for (i, constant) in constants.into_iter().enumerate() {
        let mut cur = assignment[i];
        cur = -cur; // negate
        cur += constant;
        assignment[i] = cur;
        for (j, eval) in assignment.iter_mut().enumerate().skip(i + 1) {
            if j & i == i {
                *eval += cur;
            }
        }
    }
}

/// Performs a 1-bit window table lookup. `bits` is in
/// little-endian order. constants is 1D-coords.
pub fn lookup1_x<F, CS>(mut cs: CS, b: &Boolean, c: &[F]) -> Result<AllocatedFr<F>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    assert_eq!(c.len(), 2);

    if let Boolean::Constant(cond) = *b {
        if cond {
            AllocatedFr::alloc(cs.ns(|| "lookup_true"), || Ok(c[1]))
        } else {
            AllocatedFr::alloc(cs.ns(|| "lookup_false"), || Ok(c[0]))
        }
    } else {
        let true_value = AllocatedFr::alloc(cs.ns(|| "lookup_true"), || Ok(c[1]))?;
        let false_value = AllocatedFr::alloc(cs.ns(|| "lookup_false"), || Ok(c[0]))?;

        let result = AllocatedFr::alloc(cs.ns(|| ""), || {
            b.get_value()
                .and_then(|cond| {
                    if cond {
                        true_value.clone()
                    } else {
                        false_value.clone()
                    }
                    .get_value()
                })
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        // a = self; b = other; c = cond;
        //
        // r = c * a + (1  - c) * b
        // r = b + c * (a - b)
        // c * (a - b) = r - b
        let one = CS::one();
        cs.enforce(
            || "conditionally_select",
            |_| b.lc(one, F::one()),
            |lc| lc + true_value.get_variable() - false_value.get_variable(),
            |lc| lc + result.get_variable() - false_value.get_variable(),
        );

        Ok(result)
    }
}

/// Performs a 2-bit window table lookup. `bits` is in
/// little-endian order. constants is 1D-coords.
pub fn lookup2_x<F, CS>(
    mut cs: CS,
    b: &[Boolean],
    c: &[F],
) -> Result<AllocatedFr<F>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    assert_eq!(b.len(), 2);
    assert_eq!(c.len(), 4);

    let i = match (b[0].get_value(), b[1].get_value()) {
        (Some(a_value), Some(b_value)) => {
            let mut tmp = 0;
            if a_value {
                tmp += 1;
            }
            if b_value {
                tmp += 2;
            }
            Some(tmp)
        }
        _ => None,
    };
    let res_x = AllocatedFr::alloc(cs.ns(|| "x"), || {
        Ok(c[i.ok_or(SynthesisError::AssignmentMissing)?])
    })?;

    let one = CS::one();
    cs.enforce(
        || "x-coordinate lookup",
        |lc| lc + b[1].lc(one, c[3] - &c[2] - &c[1] + &c[0]) + (c[1] - &c[0], one),
        |lc| lc + b[0].lc(one, F::one()),
        |lc| lc + res_x.get_variable() + (-c[0], one) + b[1].lc(one, c[0] - &c[2]),
    );

    Ok(res_x)
}

/// Performs a 2-bit window table lookup. `bits` is in
/// little-endian order. constants is 2D-coords.
pub fn lookup2_xy<F, CS>(
    mut cs: CS,
    b: &[Boolean],
    c: &[(F, F)],
) -> Result<(AllocatedFr<F>, AllocatedFr<F>), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    assert_eq!(b.len(), 2);
    assert_eq!(c.len(), 4);

    let i = match (b[0].get_value(), b[1].get_value()) {
        (Some(a_value), Some(b_value)) => {
            let mut tmp = 0;
            if a_value {
                tmp += 1;
            }
            if b_value {
                tmp += 2;
            }
            Some(tmp)
        }
        _ => None,
    };
    let res_x = AllocatedFr::alloc(cs.ns(|| "x"), || {
        Ok(c[i.ok_or(SynthesisError::AssignmentMissing)?].0)
    })?;
    let res_y = AllocatedFr::alloc(cs.ns(|| "y"), || {
        Ok(c[i.ok_or(SynthesisError::AssignmentMissing)?].1)
    })?;

    let one = CS::one();
    cs.enforce(
        || "x-coordinate lookup",
        |lc| lc + b[1].lc(one, c[3].0 - &c[2].0 - &c[1].0 + &c[0].0) + (c[1].0 - &c[0].0, one),
        |lc| lc + b[0].lc(one, F::one()),
        |lc| lc + res_x.get_variable() + (-c[0].0, one) + b[1].lc(one, c[0].0 - &c[2].0),
    );

    cs.enforce(
        || "y-coordinate lookup",
        |lc| lc + b[1].lc(one, c[3].1 - &c[2].1 - &c[1].1 + &c[0].1) + (c[1].1 - &c[0].1, one),
        |lc| lc + b[0].lc(one, F::one()),
        |lc| lc + res_y.get_variable() + (-c[0].1, one) + b[1].lc(one, c[0].1 - &c[2].1),
    );

    Ok((res_x, res_y))
}

/// Performs a 3-bit window table lookup. `bits` is in
/// little-endian order. constants is 1D-coords.
pub fn lookup3_x<F, CS>(
    mut cs: CS,
    bits: &[Boolean],
    coords: &[F],
) -> Result<AllocatedFr<F>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    assert_eq!(bits.len(), 3);
    assert_eq!(coords.len(), 8);

    let i = match (
        bits[0].get_value(),
        bits[1].get_value(),
        bits[2].get_value(),
    ) {
        (Some(a_value), Some(b_value), Some(c_value)) => {
            let mut tmp = 0;
            if a_value {
                tmp += 1;
            }
            if b_value {
                tmp += 2;
            }
            if c_value {
                tmp += 4;
            }
            Some(tmp)
        }
        _ => None,
    };

    // Allocate the x-coordinate resulting from the lookup
    let res_x = AllocatedFr::alloc(cs.ns(|| "x"), || {
        Ok(coords[i.ok_or(SynthesisError::AssignmentMissing)?])
    })?;

    // Compute the coefficients for the lookup constraints
    let zero = F::zero();
    let mut x_coeffs = [zero; 8];
    synth::<F, _>(3, coords, &mut x_coeffs);

    let precomp = Boolean::and(cs.ns(|| "precomp"), &bits[1], &bits[2])?;

    let one = CS::one();
    cs.enforce(
        || "x-coordinate lookup",
        |lc| {
            lc + (x_coeffs[0b001], one)
                + &bits[1].lc::<F>(one, x_coeffs[0b011])
                + &bits[2].lc::<F>(one, x_coeffs[0b101])
                + &precomp.lc::<F>(one, x_coeffs[0b111])
        },
        |lc| lc + &bits[0].lc::<F>(one, F::one()),
        |lc| {
            lc + res_x.get_variable()
                - (x_coeffs[0b000], one)
                - &bits[1].lc::<F>(one, x_coeffs[0b010])
                - &bits[2].lc::<F>(one, x_coeffs[0b100])
                - &precomp.lc::<F>(one, x_coeffs[0b110])
        },
    );

    Ok(res_x)
}

/// Performs a 3-bit window table lookup. `bits` is in
/// little-endian order. constants is 2D-coords.
pub fn lookup3_xy<F, CS>(
    mut cs: CS,
    bits: &[Boolean],
    coords: &[(F, F)],
) -> Result<(AllocatedFr<F>, AllocatedFr<F>), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    assert_eq!(bits.len(), 3);
    assert_eq!(coords.len(), 8);

    let i = match (
        bits[0].get_value(),
        bits[1].get_value(),
        bits[2].get_value(),
    ) {
        (Some(a_value), Some(b_value), Some(c_value)) => {
            let mut tmp = 0;
            if a_value {
                tmp += 1;
            }
            if b_value {
                tmp += 2;
            }
            if c_value {
                tmp += 4;
            }
            Some(tmp)
        }
        _ => None,
    };

    // Allocate the x-coordinate resulting from the lookup
    let res_x = AllocatedFr::alloc(cs.ns(|| "x"), || {
        Ok(coords[i.ok_or(SynthesisError::AssignmentMissing)?].0)
    })?;

    // Allocate the y-coordinate resulting from the lookup
    let res_y = AllocatedFr::alloc(cs.ns(|| "y"), || {
        Ok(coords[i.ok_or(SynthesisError::AssignmentMissing)?].1)
    })?;

    // Compute the coefficients for the lookup constraints
    let zero = F::zero();
    let mut x_coeffs = [zero; 8];
    let mut y_coeffs = [zero; 8];
    synth::<F, _>(3, coords.iter().map(|c| &c.0), &mut x_coeffs);
    synth::<F, _>(3, coords.iter().map(|c| &c.1), &mut y_coeffs);

    let precomp = Boolean::and(cs.ns(|| "precomp"), &bits[1], &bits[2])?;

    let one = CS::one();
    cs.enforce(
        || "x-coordinate lookup",
        |lc| {
            lc + (x_coeffs[0b001], one)
                + &bits[1].lc::<F>(one, x_coeffs[0b011])
                + &bits[2].lc::<F>(one, x_coeffs[0b101])
                + &precomp.lc::<F>(one, x_coeffs[0b111])
        },
        |lc| lc + &bits[0].lc::<F>(one, F::one()),
        |lc| {
            lc + res_x.get_variable()
                - (x_coeffs[0b000], one)
                - &bits[1].lc::<F>(one, x_coeffs[0b010])
                - &bits[2].lc::<F>(one, x_coeffs[0b100])
                - &precomp.lc::<F>(one, x_coeffs[0b110])
        },
    );

    cs.enforce(
        || "y-coordinate lookup",
        |lc| {
            lc + (y_coeffs[0b001], one)
                + &bits[1].lc::<F>(one, y_coeffs[0b011])
                + &bits[2].lc::<F>(one, y_coeffs[0b101])
                + &precomp.lc::<F>(one, y_coeffs[0b111])
        },
        |lc| lc + &bits[0].lc::<F>(one, F::one()),
        |lc| {
            lc + res_y.get_variable()
                - (y_coeffs[0b000], one)
                - &bits[1].lc::<F>(one, y_coeffs[0b010])
                - &bits[2].lc::<F>(one, y_coeffs[0b100])
                - &precomp.lc::<F>(one, y_coeffs[0b110])
        },
    );

    Ok((res_x, res_y))
}

#[cfg(test)]
mod test {
    use curve::bn_256::Fr;
    use math::test_rng;
    use rand::prelude::*;
    use scheme::r1cs::ConstraintSystem;

    use super::super::boolean::{AllocatedBit, Boolean};
    use super::super::test_constraint_system::TestConstraintSystem;
    use super::*;

    fn get_booleans<CS: ConstraintSystem<Fr>>(cs: &mut CS, num: u32) -> (usize, Vec<Boolean>) {
        let rng = &mut test_rng();

        let mut bits = vec![];
        let mut index = 0;

        for i in 0..num {
            let a_val = rng.next_u32() % 2 != 0;
            let a = Boolean::from(
                AllocatedBit::alloc(cs.ns(|| format!("boolean_{}", i)), Some(a_val)).unwrap(),
            );
            bits.push(a);

            if a_val {
                index += 2_u32.pow(i);
            }
        }
        (index as usize, bits)
    }

    #[test]
    fn test_lookup1_x() {
        let rng = &mut test_rng();

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Fr>::new();
            let (index, bits) = get_booleans(&mut cs, 1);
            let points: Vec<Fr> = (0..2).map(|_| rng.gen()).collect();

            let res = lookup1_x(&mut cs, &bits[0], &points).unwrap();

            assert!(cs.is_satisfied());

            assert_eq!(res.get_value().unwrap(), points[index]);
        }
    }

    #[test]
    fn test_lookup2_x() {
        let rng = &mut test_rng();

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Fr>::new();
            let (index, bits) = get_booleans(&mut cs, 2);
            let points: Vec<Fr> = (0..4).map(|_| rng.gen()).collect();

            let res = lookup2_x(&mut cs, &bits, &points).unwrap();

            assert!(cs.is_satisfied());

            assert_eq!(res.get_value().unwrap(), points[index]);
        }
    }

    #[test]
    fn test_lookup2_xy() {
        let rng = &mut test_rng();

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Fr>::new();
            let (index, bits) = get_booleans(&mut cs, 2);
            let points: Vec<(Fr, Fr)> = (0..4).map(|_| (rng.gen(), rng.gen())).collect();

            let res = lookup2_xy(&mut cs, &bits, &points).unwrap();

            assert!(cs.is_satisfied());

            assert_eq!(res.0.get_value().unwrap(), points[index].0);
            assert_eq!(res.1.get_value().unwrap(), points[index].1);
        }
    }

    #[test]
    fn test_lookup3_x() {
        let rng = &mut test_rng();

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Fr>::new();
            let (index, bits) = get_booleans(&mut cs, 3);
            let points: Vec<Fr> = (0..8).map(|_| rng.gen()).collect();

            let res = lookup3_x(&mut cs, &bits, &points).unwrap();

            assert!(cs.is_satisfied());

            assert_eq!(res.get_value().unwrap(), points[index]);
        }
    }

    #[test]
    fn test_lookup3_xy() {
        let rng = &mut test_rng();

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Fr>::new();
            let (index, bits) = get_booleans(&mut cs, 3);
            let points: Vec<(Fr, Fr)> = (0..8).map(|_| (rng.gen(), rng.gen())).collect();

            let res = lookup3_xy(&mut cs, &bits, &points).unwrap();

            assert!(cs.is_satisfied());

            assert_eq!(res.0.get_value().unwrap(), points[index].0);
            assert_eq!(res.1.get_value().unwrap(), points[index].1);
        }
    }
}
