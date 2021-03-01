use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::PrimeField;
use ark_serialize::*;
use ark_std::test_rng;
use std::time::Instant;
use zkp_marlin::{create_random_proof, index, universal_setup, verify_proof, Proof, VerifyKey};
use zkp_r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

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
fn mini_marlin() {
    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    let num = 10;

    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };

    let srs = universal_setup::<E, _>(2usize.pow(10), rng).unwrap();
    let (ipk, ivk) = index(&srs, c).unwrap();

    let mut vk_bytes = Vec::new();
    ivk.serialize(&mut vk_bytes).unwrap();
    println!("[Marlin] VerifyKey length : {}", vk_bytes.len());

    let circuit = Mini {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: num,
    };

    let p_start = Instant::now();
    let proof = create_random_proof(&ipk, circuit, rng).unwrap();
    let p_time = p_start.elapsed();
    println!("[Marlin] Prove time       : {:?}", p_time);

    let mut proof_bytes = vec![];
    proof.serialize(&mut proof_bytes).unwrap();
    println!("[Marlin] Proof length     : {}", proof_bytes.len());

    let v_start = Instant::now();
    assert!(verify_proof(&ivk, &proof, &[Fr::from(10u32)]).unwrap());
    let v_time = v_start.elapsed();
    println!("[Marlin] Verify time      : {:?}", v_time);

    let vk2 = VerifyKey::<E>::deserialize(&vk_bytes[..]).unwrap();
    let proof2 = Proof::<E>::deserialize(&proof_bytes[..]).unwrap();
    assert!(verify_proof(&vk2, &proof2, &[Fr::from(10u32)]).unwrap());
}
