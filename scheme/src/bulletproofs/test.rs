use math::Field;

use crate::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

struct MySillyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
    fn generate_constraints<CS: ConstraintSystem<ConstraintF>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let a = cs.alloc(|| "a", || self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.alloc(|| "b", || self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.alloc_input(
            || "c",
            || {
                let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                a.mul_assign(&b);
                Ok(a)
            },
        )?;

        cs.enforce(|| "a*b=c", |lc| lc + a, |lc| lc + b, |lc| lc + c);
        cs.enforce(|| "a*b=c", |lc| lc + a, |lc| lc + b, |lc| lc + c);
        cs.enforce(|| "a*b=c", |lc| lc + a, |lc| lc + b, |lc| lc + c);
        cs.enforce(|| "a*b=c", |lc| lc + a, |lc| lc + b, |lc| lc + c);
        cs.enforce(|| "a*b=c", |lc| lc + a, |lc| lc + b, |lc| lc + c);
        cs.enforce(|| "a*b=c", |lc| lc + a, |lc| lc + b, |lc| lc + c);

        Ok(())
    }
}

mod bn_256 {
    use super::*;
    use crate::bulletproofs::arithmetic_circuit::{create_proof, verify_proof};

    use core::ops::MulAssign;
    use curve::bn_256::{Bn_256, Fr};
    use math::{test_rng, UniformRand};

    #[test]
    fn prove_and_verify() {
        let rng = &mut test_rng();

        for _ in 0..5 {
            let a = Fr::rand(rng);
            let b = Fr::rand(rng);
            let mut c = a;
            c.mul_assign(&b);

            let (generators, r1cs_circuit, proof, assignment) =
                create_proof::<Bn_256, _>(MySillyCircuit {
                    a: Some(a),
                    b: Some(b),
                })
                .unwrap();

            assert!(verify_proof(
                &generators,
                &proof,
                &r1cs_circuit,
                &assignment.s
            ));
        }
    }
}

mod bls12_381 {
    use super::*;
    use crate::bulletproofs::arithmetic_circuit::{create_proof, verify_proof};

    use core::ops::MulAssign;
    use curve::bls12_381::{Bls12_381, Fr};
    use math::{test_rng, UniformRand};

    #[test]
    fn prove_and_verify() {
        let rng = &mut test_rng();

        for _ in 0..5 {
            let a = Fr::rand(rng);
            let b = Fr::rand(rng);
            let mut c = a;
            c.mul_assign(&b);

            let (generators, r1cs_circuit, proof, assignment) =
                create_proof::<Bls12_381, _>(MySillyCircuit {
                    a: Some(a),
                    b: Some(b),
                })
                .unwrap();

            assert!(verify_proof(
                &generators,
                &proof,
                &r1cs_circuit,
                &assignment.s
            ));
        }
    }
}
