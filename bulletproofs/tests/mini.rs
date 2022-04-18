use ark_ff::PrimeField;
use ark_std::test_rng;
use zkp_bulletproofs::{create_random_proof, verify_proof, Proof};
use zkp_r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
// size: 71%, time: 13%, 14%
//use zkp_curve25519::{Curve25519 as E, Fr};
use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_serialize::*;
use std::time::Instant;

struct Mini<F: PrimeField> {
    pub x: Option<F>,
    pub y: Option<F>,
    pub z: Option<F>,
    pub num: u32,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Mini<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let var_x = cs.alloc(|| "x", || self.x.ok_or(SynthesisError::AssignmentMissing))?;

        let var_y = cs.alloc(|| "y", || self.y.ok_or(SynthesisError::AssignmentMissing))?;

        let var_z = cs.alloc_input(
            || "z(output)",
            || self.z.ok_or(SynthesisError::AssignmentMissing),
        )?;

        for _ in 0..self.num {
            cs.enforce(
                || "x * (y + 2) = z",
                |lc| lc + var_x,
                |lc| lc + var_y + (F::from(2u32), CS::one()),
                |lc| lc + var_z,
            );
        }

        Ok(())
    }
}

#[test]
fn mini_bulletproofs() {
    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();
    let num = 10;

    let c = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: num,
    };

    let p_start = Instant::now();
    let (gens, r1cs, proof) = create_random_proof::<E, _, _>(c, rng).unwrap();
    let p_time = p_start.elapsed();
    println!("[Bulletproofs] Prove time   : {:?}", p_time);

    let mut proof_bytes = vec![];
    proof.serialize(&mut proof_bytes).unwrap();
    println!("[Bulletproofs] Proof length : {}", proof_bytes.len());

    let _c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };

    let v_start = Instant::now();
    assert!(verify_proof(&gens, &proof, &r1cs, &[Fr::from(10u32)]).unwrap());
    let v_time = v_start.elapsed();
    println!("[Bulletproofs] Verify time  : {:?}", v_time);

    let proof2 = Proof::<E>::deserialize(&proof_bytes[..]).unwrap();
    assert!(verify_proof(&gens, &proof2, &r1cs, &[Fr::from(10u32)]).unwrap());
}
