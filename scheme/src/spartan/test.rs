use crate::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use math::PrimeField;

struct TestDemo<F: PrimeField> {
    lhs: Option<F>,
    rhs: Option<F>,
    ohs: Option<F>,
    phs: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for TestDemo<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let lhs_value = self.lhs;
        let lhs = cs.alloc(
            || "L",
            || lhs_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let rhs_value = self.rhs;
        let rhs = cs.alloc(
            || "R",
            || rhs_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let ohs_value = self.ohs;
        let ohs = cs.alloc(
            || "O",
            || ohs_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let phs_value = self.phs;
        let phs = cs.alloc_input(
            || "P",
            || phs_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        //(1 - lhs) * lhs = 0
        cs.enforce(
            || "lhs boolean constraint",
            |lc| lc + CS::one() - lhs,
            |lc| lc + lhs,
            |lc| lc,
        );

        //(1 - rhs) * rhs = -2
        cs.enforce(
            || "rhs boolean constraint",
            |lc| lc + CS::one() - rhs,
            |lc| lc + rhs,
            |lc| lc - CS::one() - CS::one(),
        );

        // lhs * lhs = 1
        cs.enforce(
            || "lhs boolean constraint",
            |lc| lc + lhs,
            |lc| lc + lhs,
            |lc| lc + CS::one(),
        );

        // rhs * rhs = 4
        cs.enforce(
            || "rhs boolean constraint",
            |lc| lc + rhs,
            |lc| lc + rhs,
            |lc| lc + CS::one() + CS::one() + CS::one() + CS::one(),
        );

        //(1 - lhs) * lhs = 0
        cs.enforce(
            || "lhs boolean constraint",
            |lc| lc + CS::one() - lhs,
            |lc| lc + lhs,
            |lc| lc,
        );

        //(1 - rhs) * rhs = -2
        cs.enforce(
            || "rhs boolean constraint",
            |lc| lc + CS::one() - rhs,
            |lc| lc + rhs,
            |lc| lc - CS::one() - CS::one(),
        );
        // phs * ohs = 1
        cs.enforce(
            || "ohs boolean constraint",
            |lc| lc + phs,
            |lc| lc + ohs,
            |lc| lc + CS::one(),
        );

        // rhs * (rhs + 1) = 6
        cs.enforce(
            || "rhs boolean constraint",
            |lc| lc + rhs,
            |lc| lc + rhs + CS::one(),
            |lc| lc + CS::one() + CS::one() + CS::one() + CS::one() + CS::one() + CS::one(),
        );

        Ok(())
    }
}

#[cfg(test)]
mod bls12_381 {
    use super::*;
    use crate::spartan::prover::{create_nizk_proof, create_snark_proof};
    use crate::spartan::r1cs::generate_r1cs;
    use crate::spartan::setup::*;
    use crate::spartan::spark::encode;
    use crate::spartan::verify::{verify_nizk_proof, verify_snark_proof};
    use curve::bls12_381::{Bls12_381, Fr};
    use math::{One, PairingEngine};
    use rand::thread_rng;

    #[test]
    fn test_nizk_spartan_bls12_381() {
        let rng = &mut thread_rng();
        let c = TestDemo::<Fr> {
            lhs: None,
            rhs: None,
            ohs: None,
            phs: None,
        };

        println!("Generate parameters...");
        let r1cs = generate_r1cs::<Bls12_381, _>(c).unwrap();
        let params =
            generate_setup_nizk_parameters::<Bls12_381, _>(rng, r1cs.num_aux, r1cs.num_inputs)
                .unwrap();
        let c1 = TestDemo::<Fr> {
            lhs: Some(<Bls12_381 as PairingEngine>::Fr::one()),
            rhs: Some(
                <Bls12_381 as PairingEngine>::Fr::one() + &<Bls12_381 as PairingEngine>::Fr::one(),
            ),
            ohs: Some(<Bls12_381 as PairingEngine>::Fr::one()),
            phs: Some(<Bls12_381 as PairingEngine>::Fr::one()),
        };

        // let mut transcript = Transcript::new(b"spartan nizk");
        println!("Creating proof...");
        let proof = create_nizk_proof(&params, &r1cs, c1, rng).unwrap();

        println!("Verify proof...");
        // let mut transcript = Transcript::new(b"spartan nizk");
        let result = verify_nizk_proof::<Bls12_381>(
            &params,
            &r1cs,
            &vec![<Bls12_381 as PairingEngine>::Fr::one()],
            &proof,
        )
        .unwrap();

        assert!(result);
    }

    #[test]
    fn test_snark_spartan_bls12_381() {
        println!("\n spartan snark...");
        let rng = &mut thread_rng();
        let c = TestDemo::<Fr> {
            lhs: None,
            rhs: None,
            ohs: None,
            phs: None,
        };

        println!("[snark_spartan]Generate parameters...");
        let r1cs = generate_r1cs::<Bls12_381, _>(c).unwrap();

        let params = generate_setup_snark_parameters::<Bls12_381, _>(
            rng,
            r1cs.num_aux,
            r1cs.num_inputs,
            r1cs.num_constraints,
        )
        .unwrap();

        let c1 = TestDemo::<Fr> {
            lhs: Some(<Bls12_381 as PairingEngine>::Fr::one()),
            rhs: Some(
                <Bls12_381 as PairingEngine>::Fr::one() + &<Bls12_381 as PairingEngine>::Fr::one(),
            ),
            ohs: Some(<Bls12_381 as PairingEngine>::Fr::one()),
            phs: Some(<Bls12_381 as PairingEngine>::Fr::one()),
        };
        println!("[snark_spartan]Generate parameters...ok");

        println!("[snark_spartan]Encode...");
        let (encode, encode_commit) = encode::<Bls12_381, _>(&params, &r1cs, rng).unwrap();
        println!("[snark_spartan]Encode...ok");

        // let mut transcript = Transcript::new(b"spartan snark");
        println!("[snark_spartan]Creating proof...");
        let proof = create_snark_proof(&params, &r1cs, c1, &encode, rng).unwrap();
        println!("[snark_spartan]Creating proof...ok");

        println!("[snark_spartan]Verify proof...");
        // let mut transcript = Transcript::new(b"spartan snark");
        let result = verify_snark_proof::<Bls12_381>(
            &params,
            &r1cs,
            &vec![<Bls12_381 as PairingEngine>::Fr::one()],
            &proof,
            &encode_commit,
        )
        .is_ok();
        println!("[snark_spartan]Verify proof...ok");

        assert!(result);
    }
}

#[cfg(test)]
mod bn_256 {
    use super::*;
    use crate::spartan::prover::{create_nizk_proof, create_snark_proof};
    use crate::spartan::r1cs::generate_r1cs;
    use crate::spartan::setup::*;
    use crate::spartan::spark::encode;
    use crate::spartan::verify::{verify_nizk_proof, verify_snark_proof};
    use curve::bn_256::{Bn_256, Fr};
    use math::{Curve, One};
    use rand::thread_rng;

    #[test]
    fn test_nizk_spartan_bn_256() {
        let rng = &mut thread_rng();
        let c = TestDemo::<Fr> {
            lhs: None,
            rhs: None,
            ohs: None,
            phs: None,
        };

        println!("Generate parameters...");
        let r1cs = generate_r1cs::<Bn_256, _>(c).unwrap();
        let params =
            generate_setup_nizk_parameters::<Bn_256, _>(rng, r1cs.num_aux, r1cs.num_inputs)
                .unwrap();
        let c1 = TestDemo::<Fr> {
            lhs: Some(<Bn_256 as Curve>::Fr::one()),
            rhs: Some(<Bn_256 as Curve>::Fr::one() + &<Bn_256 as Curve>::Fr::one()),
            ohs: Some(<Bn_256 as Curve>::Fr::one()),
            phs: Some(<Bn_256 as Curve>::Fr::one()),
        };

        println!("Creating proof...");
        let proof = create_nizk_proof(&params, &r1cs, c1, rng).unwrap();

        println!("Verify proof...");
        let result = verify_nizk_proof::<Bn_256>(
            &params,
            &r1cs,
            &vec![<Bn_256 as Curve>::Fr::one()],
            &proof,
        )
        .unwrap();

        assert!(result);
    }

    #[test]
    fn test_snark_spartan_bn_256() {
        println!("\n spartan snark...");
        let rng = &mut thread_rng();
        let c = TestDemo::<Fr> {
            lhs: None,
            rhs: None,
            ohs: None,
            phs: None,
        };

        println!("[snark_spartan]Generate parameters...");
        let r1cs = generate_r1cs::<Bn_256, _>(c).unwrap();

        let params = generate_setup_snark_parameters::<Bn_256, _>(
            rng,
            r1cs.num_aux,
            r1cs.num_inputs,
            r1cs.num_constraints,
        )
        .unwrap();

        let c1 = TestDemo::<Fr> {
            lhs: Some(<Bn_256 as Curve>::Fr::one()),
            rhs: Some(<Bn_256 as Curve>::Fr::one() + &<Bn_256 as Curve>::Fr::one()),
            ohs: Some(<Bn_256 as Curve>::Fr::one()),
            phs: Some(<Bn_256 as Curve>::Fr::one()),
        };
        println!("[snark_spartan]Generate parameters...ok");

        println!("[snark_spartan]Encode...");
        let (encode, encode_commit) = encode::<Bn_256, _>(&params, &r1cs, rng).unwrap();
        println!("[snark_spartan]Encode...ok");

        println!("[snark_spartan]Creating proof...");
        let proof = create_snark_proof(&params, &r1cs, c1, &encode, rng).unwrap();
        println!("[snark_spartan]Creating proof...ok");

        println!("[snark_spartan]Verify proof...");
        let result = verify_snark_proof::<Bn_256>(
            &params,
            &r1cs,
            &vec![<Bn_256 as Curve>::Fr::one()],
            &proof,
            &encode_commit,
        )
        .is_ok();
        println!("[snark_spartan]Verify proof...ok");

        assert!(result);
    }
}
