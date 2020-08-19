use math::Field;

use crate::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

#[derive(Clone)]
struct Circuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
    num_constraints: usize,
    num_variables: usize,
}

impl<F: Field> ConstraintSynthesizer<F> for Circuit<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
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

        for i in 3..self.num_variables {
            cs.alloc(
                || format!("variable_{}", i),
                || self.a.ok_or(SynthesisError::AssignmentMissing),
            )?;
        }

        for i in 0..self.num_constraints {
            cs.enforce(
                || format!("constraint_{}", i),
                |lc| lc + a,
                |lc| lc + b,
                |lc| lc + c,
            );
        }

        Ok(())
    }
}

mod marlin {
    use super::*;
    use crate::marlin::Marlin;

    use curve::bls12_381::{Bls12_381, Fr};
    use math::UniformRand;

    use blake2::Blake2s;
    use core::ops::MulAssign;

    type MarlinInst = Marlin<Bls12_381, Blake2s>;

    fn test_circuit(num_constraints: usize, num_variables: usize) {
        let rng = &mut curve::test_rng();
        let a = Fr::rand(rng);
        let b = Fr::rand(rng);
        let mut c = a;
        c.mul_assign(&b);

        let circuit = Circuit {
            a: Some(a),
            b: Some(b),
            num_constraints,
            num_variables,
        };
        println!("calling setup...");
        let srs = MarlinInst::universal_setup(num_constraints, num_variables, num_constraints, rng)
            .unwrap();
        println!("calling indexer...");
        let (ipk, ivk) = MarlinInst::index(&srs, circuit.clone()).unwrap();
        println!("calling prover...");
        let proof = MarlinInst::prove(&ipk, circuit, rng).unwrap();
        println!("calling verifier... should verify");
        assert!(MarlinInst::verify(&ivk, &[c], &proof).unwrap());
        println!("calling verifier... should not verify");
        assert!(!MarlinInst::verify(&ivk, &[a], &proof).unwrap());
    }

    #[test]
    fn small_squat() {
        let num_constraints = 6;
        let num_variables = 11;

        test_circuit(num_constraints, num_variables);
    }

    #[test]
    fn small_tall() {
        let num_constraints = 11;
        let num_variables = 6;

        test_circuit(num_constraints, num_variables);
    }
}
