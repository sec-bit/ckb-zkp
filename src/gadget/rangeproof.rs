use math::{BitIterator,PrimeField};
use scheme::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, LinearCombination, SynthesisError, Variable,
};

use crate::Vec;

pub struct RangeProof<F: PrimeField> {
    pub lhs: Option<F>,
    pub rhs: Option<F>,
    pub n: u64,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for RangeProof<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let n: u64 = self.n;

        let mut coeff = F::one();
        let lhs_value = self.lhs;
        let lhs = cs.alloc(
            || "A",
            || lhs_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let rhs_value = self.rhs;
        let rhs = cs.alloc(
            || "B",
            || rhs_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let twon_value = Some(F::from(2u32).pow(&[n]));
        let twon = cs.alloc_input(
            || "2^n",
            || twon_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        /* alpha_packed = 2^n + B - A */
        let alpha_packed_value = match (&self.rhs, &self.lhs) {
            (Some(_r), Some(_l)) => {
                let mut tmp = F::from(2u32).pow(&[n]);
                tmp.add_assign(&self.rhs.unwrap());
                tmp.sub_assign(&self.lhs.unwrap());
                Some(tmp)
            }
            _ => None,
        };
        let alpha_packed = cs.alloc(
            || "alpha_packed",
            || alpha_packed_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let alpha_value = match alpha_packed_value {
            Some(i) => i,
            _ =>F::zero(),
        };
        
        let mut alpha_bits: Vec<Option<F>> = Vec::new();
        let mut bits: Vec<Option<F>> = Vec::new();
        
        for b in BitIterator::new(alpha_value.into_repr()) {
            if b {
                bits.push(Some(F::one()));
            } else {
                bits.push(Some(F::zero()));
            }
        }
        for i in 0..(n+1){
            alpha_bits.push(bits[bits.len()-1-i as usize]);
        }
        assert_eq!(alpha_bits.len(), (n + 1) as usize);

        let mut alpha: Vec<Variable> = Vec::new();
        for i in 0..n {
            let alpha_i = cs.alloc(
                || format!("alpha[{}]", i),
                || alpha_bits[i as usize].ok_or(SynthesisError::AssignmentMissing),
            )?;
            alpha.push(alpha_i);
        }
        let less_or_equal_value = alpha_bits[n as usize].unwrap();
        let less_or_equal = cs.alloc(
            || "less_or_equal",
            || alpha_bits[n as usize].ok_or(SynthesisError::AssignmentMissing),
        )?;
        alpha.push(less_or_equal);

        let mut sum_value = F::zero();
        for i in 0..n {
            if !alpha_bits[i as usize].unwrap().is_zero() {
                sum_value.add_assign(&F::one())
            };
        }

        let (inv_value, not_all_zeros) = if sum_value.is_zero() {
            (Some(F::zero()), Some(F::zero()))
        } else {
            (Some(sum_value.inverse().unwrap()), Some(F::one()))
        };

        let inv = cs.alloc(
            || "inv",
            || inv_value.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let output = cs.alloc(
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
        let mut lc2 = LinearCombination::<F>::zero();
        for i in 0..n {
            lc2 = lc2 + (coeff, alpha[i as usize]);
        }
        cs.enforce(
            || "inv * sum = output",
            |lc| lc + inv,
            |_| lc2,
            |lc| lc + output,
        );

        let mut lc2 = LinearCombination::<F>::zero();
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
        let mut less_value = Some(F::one());
        if less_or_equal_value.is_zero() || not_all_zeros.unwrap().is_zero() {
            less_value = Some(F::zero());
        }
        let less = cs.alloc(
            || "less",
            || less_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        /* less_or_eq  * output = less*/
        cs.enforce(
            || "less_or_eq  * output = less",
            |lc| lc + less_or_equal,
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
        let mut lc2 = LinearCombination::<F>::zero();
        for b in &alpha {
            lc2 = lc2 + (coeff, *b);
            coeff = coeff.double();
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
        //     |lc| lc + less_or_equal,
        //     |lc| lc + CS::one(),
        //     |lc| lc + CS::one(),
        // );

        Ok(())
    }
}

use crate::{Gadget, GadgetProof};
use math::{Field, FromBytes, PairingEngine, ToBytes};

#[cfg(feature = "groth16")]
pub fn groth16_prove<E: PairingEngine, R: rand::Rng>(
    g: &Gadget,
    pk: &[u8],
    mut rng: R,
) -> Result<GadgetProof, ()> {
    use scheme::groth16::{create_random_proof, Parameters};
    let params = Parameters::<E>::read(pk).map_err(|_| ())?;

    match g {
        Gadget::GreaterThan(s, lhs) => {
            let repr_s = <E::Fr as PrimeField>::BigInt::from(*s);
            let repr_lhs = <E::Fr as PrimeField>::BigInt::from(*lhs);

            let c1 = RangeProof::<E::Fr> {
                lhs: Some(<E::Fr as PrimeField>::from_repr(repr_lhs)),
                rhs: Some(<E::Fr as PrimeField>::from_repr(repr_s)),
                n: 64,
            };

            let proof = create_random_proof(c1, &params, &mut rng).map_err(|_| ())?;
            let mut p_bytes = Vec::new();
            proof.write(&mut p_bytes).map_err(|_| ())?;
            Ok(GadgetProof::GreaterThan(*lhs, p_bytes))
        }
        Gadget::LessThan(s, rhs) => {
            let repr_s = <E::Fr as PrimeField>::BigInt::from(*s);
            let repr_rhs = <E::Fr as PrimeField>::BigInt::from(*rhs);

            let c1 = RangeProof::<E::Fr> {
                lhs: Some(<E::Fr as PrimeField>::from_repr(repr_s)),
                rhs: Some(<E::Fr as PrimeField>::from_repr(repr_rhs)),
                n: 64,
            };

            let proof = create_random_proof(c1, &params, &mut rng).map_err(|_| ())?;
            let mut p_bytes = Vec::new();
            proof.write(&mut p_bytes).map_err(|_| ())?;
            Ok(GadgetProof::LessThan(*rhs, p_bytes))
        }
        Gadget::Between(s, lhs, rhs) => {
            let repr_s = <E::Fr as PrimeField>::BigInt::from(*s);
            let repr_lhs = <E::Fr as PrimeField>::BigInt::from(*lhs);
            let repr_rhs = <E::Fr as PrimeField>::BigInt::from(*rhs);

            let c_l = RangeProof::<E::Fr> {
                lhs: Some(<E::Fr as PrimeField>::from_repr(repr_lhs)),
                rhs: Some(<E::Fr as PrimeField>::from_repr(repr_s)),
                n: 64,
            };
            let proof_l = create_random_proof(c_l, &params, &mut rng).map_err(|_| ())?;

            let c_r = RangeProof::<E::Fr> {
                lhs: Some(<E::Fr as PrimeField>::from_repr(repr_s)),
                rhs: Some(<E::Fr as PrimeField>::from_repr(repr_rhs)),
                n: 64,
            };
            let proof_r = create_random_proof(c_r, &params, &mut rng).map_err(|_| ())?;

            let mut p_bytes = Vec::new();

            proof_l.write(&mut p_bytes).map_err(|_| ())?;
            proof_r.write(&mut p_bytes).map_err(|_| ())?;

            Ok(GadgetProof::Between(*lhs, *rhs, p_bytes))
        }
        _ => Err(()),
    }
}

#[cfg(feature = "groth16")]
pub fn groth16_verify<E: PairingEngine>(
    g: GadgetProof,
    vk: &[u8],
    is_pp: bool,
) -> Result<bool, ()> {
    use scheme::groth16::{
        prepare_verifying_key, verify_proof, PreparedVerifyingKey, Proof, VerifyingKey,
    };
    let pvk = if is_pp {
        PreparedVerifyingKey::<E>::read(vk).map_err(|_| ())?
    } else {
        let vk = VerifyingKey::<E>::read(vk).map_err(|_| ())?;
        prepare_verifying_key(&vk)
    };

    let repr_image = <E::Fr as PrimeField>::BigInt::from(2);
    let image = <E::Fr as PrimeField>::from_repr(repr_image).pow([64]);

    match g {
        GadgetProof::GreaterThan(_, p_bytes) | GadgetProof::LessThan(_, p_bytes) => {
            let proof = Proof::<E>::read(&p_bytes[..]).map_err(|_| ())?;

            verify_proof(&pvk, &proof, &[image]).map_err(|_| ())
        }
        GadgetProof::Between(_, _, p_bytes) => {
            let len = p_bytes.len() / 2;
            let l_proof = Proof::<E>::read(&p_bytes[0..len]).map_err(|_| ())?;
            let r_proof = Proof::<E>::read(&p_bytes[len..]).map_err(|_| ())?;

            Ok(verify_proof(&pvk, &l_proof, &[image]).map_err(|_| ())?
                && verify_proof(&pvk, &r_proof, &[image]).map_err(|_| ())?)
        }
        _ => Err(()),
    }
}

#[test]
fn test_rangeproof() {
    use curve::bn_256::{Bn_256, Fr};
    use math::fields::Field;
    use math::test_rng;
    use scheme::groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };

    let mut rng = &mut test_rng();
    let n = 10u64; // |lhs - rhs| < 2^10

    println!("Creating parameters...");
    let params = {
        let c = RangeProof::<Fr> {
            lhs: None,
            rhs: None,
            n: n,
        };

        generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    let c1 = RangeProof::<Fr> {
        lhs: Some(Fr::from(25u32)),
        rhs: Some(Fr::from(26u32)),
        n: n,
    };

    let proof = create_random_proof(c1, &params, &mut rng).unwrap();
    println!("Proofs ok, start verify...");

    assert!(verify_proof(&pvk, &proof, &[Fr::from(2u32).pow(&[n])]).unwrap());
}
