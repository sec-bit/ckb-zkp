use ff::{Field, PrimeField, ScalarEngine};
use pairing::bls12_381::Bls12;
use pairing::Engine;
use rand::thread_rng;

// We'll use these interfaces to construct our circuit.
use bellman::gadgets::boolean;
use bellman::gadgets::test::TestConstraintSystem;
use bellman::{Circuit, ConstraintSystem, LinearCombination, SynthesisError, Variable};

// We're going to use the Groth16 proving system.
use bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};

// use bellman::gadgets::Assignment;

struct RangeProofDemo<E: Engine> {
    lhs: Option<E::Fr>,
    rhs: Option<E::Fr>,
    // less: Option<bool>,
    // lessOrEqual: Option<E::Fr>,
    // n: Option<u32>,
    // alpha: Option<E::Fr>,
    // notAllZeroes: Option<bool>,
    // constants: &'a [E::Fr],
}

impl<E: Engine> Circuit<E> for RangeProofDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let mut i = 0;
        let mut n: u64 = 10;
        let mut coeff = E::Fr::one();
        let mut lhs_value = self.lhs;
        let mut lhs = cs.alloc(
            || "A",
            || lhs_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let mut rhs_value = self.rhs;
        let mut rhs = cs.alloc(
            || "B",
            || rhs_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let twon_value = Some(E::Fr::from_str("2").unwrap().pow(&[n]));
        let mut twon = cs.alloc_input(
            || "2^n",
            || twon_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        /* alpha_packed = 2^n + B - A */
        let mut alpha_packed_value = match (&self.rhs, &self.lhs) {
            (Some(r), Some(l)) => {
                let mut tmp = E::Fr::from_str("2").unwrap().pow(&[n as u64]);
                tmp.add_assign(&self.rhs.unwrap());
                tmp.sub_assign(&self.lhs.unwrap());
                Some(tmp)
            }
            _ => None,
        };
        let mut alpha_packed = cs.alloc(
            || "alpha_packed",
            || alpha_packed_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let mut alpha_bits: Vec<Option<E::Fr>> = Vec::new();
        let mut cs1 = TestConstraintSystem::<Bls12>::new();
        let bits = match alpha_packed_value {
            Some(i) => boolean::field_into_allocated_bits_le(cs1, alpha_packed_value)?,
            _ => boolean::field_into_allocated_bits_le(cs1, Some(E::Fr::zero()))?,
        };
        for i in 0..(n + 1) {
            if bits[i as usize].get_value() == Some(true) {
                alpha_bits.push(Some(E::Fr::one()));
            } else {
                alpha_bits.push(Some(E::Fr::zero()));
            }
        }
        assert_eq!(alpha_bits.len(), (n + 1) as usize);

        let mut lessOrEqual;
        let mut alpha: Vec<Variable> = Vec::new();

        let mut i: u64 = 0;
        let mut lessOrEqual_Value = E::Fr::zero();
        for i in 0..n {
            let alpha_i = cs.alloc(
                || format!("alpha[{}]", i),
                || alpha_bits[i as usize].ok_or(SynthesisError::AssignmentMissing),
            )?;
            alpha.push(alpha_i);
        }
        lessOrEqual_Value = alpha_bits[n as usize].unwrap();
        lessOrEqual = cs.alloc(
            || "lessOrEqual",
            || alpha_bits[n as usize].ok_or(SynthesisError::AssignmentMissing),
        )?;
        alpha.push(lessOrEqual);

        let mut sum_value = E::Fr::zero();
        for i in 0..n {
            if !alpha_bits[i as usize].unwrap().is_zero() {
                sum_value.add_assign(&E::Fr::one())
            };
        }
        let mut inv_value;
        let mut not_all_zeros;
        if sum_value.is_zero() {
            inv_value = Some(E::Fr::zero());
            not_all_zeros = Some(E::Fr::zero());
        } else {
            inv_value = Some(sum_value.inverse().unwrap());
            not_all_zeros = Some(E::Fr::one());
        }
        let mut inv = cs.alloc(
            || "inv",
            || inv_value.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let mut output = cs.alloc(
            || "output",
            || not_all_zeros.ok_or(SynthesisError::AssignmentMissing),
        )?;

        /* 1 * (2^n + B - A) = alpha_packed */
        cs.enforce(
            || " main_constraint",
            |lc| lc + CS::one(),
            |lc| lc + twon + rhs - lhs,
            |lc| lc + alpha_packed,
        );

        /* (1 - bits_i) * bits_i = 0 */
        for b in &alpha {
            cs.enforce(
                || "bit[i] boolean constraint",
                |lc| lc + CS::one() - (coeff, *b),
                |lc| lc + (coeff, *b),
                |lc| lc,
            )
        }

        /* inv * sum = output */
        let mut lc2 = LinearCombination::<E>::zero();
        for i in 0..n {
            lc2 = lc2 + (coeff, alpha[i as usize]);
        }
        cs.enforce(
            || "inv * sum = output",
            |lc| lc + inv,
            |_| lc2,
            |lc| lc + output,
        );

        let mut lc2 = LinearCombination::<E>::zero();
        for i in 0..n {
            lc2 = lc2 + (coeff, alpha[i as usize]);
        }
        cs.enforce(
            || "(1-output) * sum = 0",
            |lc| lc + CS::one() - output,
            |_| lc2,
            |lc| lc,
        );

        /* less = less_or_eq * not_all_zeros */
        let mut less_value = Some(E::Fr::one());
        if lessOrEqual_Value.is_zero() || not_all_zeros.unwrap().is_zero() {
            less_value = Some(E::Fr::zero());
        }
        let mut less = cs.alloc(
            || "less",
            || less_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        /* less_or_eq  * output = less*/
        cs.enforce(
            || "less_or_eq  * output = less",
            |lc| lc + lessOrEqual,
            |lc| lc + output,
            |lc| lc + less,
        );

        //(1 - output) * output = 0
        cs.enforce(
            || "output boolean constraint",
            |lc| lc + CS::one() - output,
            |lc| lc + output,
            |lc| lc,
        );

        /* 1 * sum(bits) = alpha_packed*/
        let mut lc2 = LinearCombination::<E>::zero();
        for b in &alpha {
            lc2 = lc2 + (coeff, *b);
            coeff.double();
        }
        cs.enforce(
            || " packing_constraint",
            |lc| lc + CS::one(),
            |_| lc2,
            |lc| lc + alpha_packed,
        );

        /* less * 1 = 1 A < B 额外加的*/
        cs.enforce(
            || "less  * 1 = 1",
            |lc| lc + less,
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );

        // /* less_or_eq * 1 = 1 A <= B 额外加的*/
        // cs.enforce(
        //     || "less_or_eq  * 1 = 1",
        //     |lc| lc + lessOrEqual,
        //     |lc| lc + CS::one(),
        //     |lc| lc + CS::one(),
        // );

        Ok(())
    }
}

#[test]
fn test_rangeproof() {
    let rng = &mut thread_rng();
    println!("Creating parameters...");
    let params = {
        let c = RangeProofDemo::<Bls12> {
            lhs: None,
            rhs: None,
        };

        generate_random_parameters(c, rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    let c1 = RangeProofDemo::<Bls12> {
        lhs: Some(<Bls12 as ScalarEngine>::Fr::from_str("24").unwrap()),
        rhs: Some(<Bls12 as ScalarEngine>::Fr::from_str("25").unwrap()),
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();
    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
}
