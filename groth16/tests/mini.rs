use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::PrimeField;
use ark_serialize::*;
use ark_std::test_rng;
use std::time::Instant;
use zkp_groth16::{
    create_random_proof, generate_random_parameters, verifier::prepare_verifying_key, verify_proof,
    Proof, VerifyKey,
};
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
fn mini_groth16() {
    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    let s_start = Instant::now();
    let params = {
        let c = Mini::<Fr> {
            x: None,
            y: None,
            z: None,
            num: 10,
        };

        generate_random_parameters::<E, _, _>(c, rng).unwrap()
    };
    let s_time = s_start.elapsed();
    println!("[Groth16] Setup time       : {:?}", s_time);

    let mut vk_bytes = Vec::new();
    params.vk.serialize(&mut vk_bytes).unwrap();
    println!("[Groth16] VerifyKey length : {}", vk_bytes.len());

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    let c = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: 10,
    };

    let p_start = Instant::now();
    let proof = create_random_proof(&params, c, rng).unwrap();
    let p_time = p_start.elapsed();
    println!("[Groth16] Prove time       : {:?}", p_time);

    let mut proof_bytes = vec![];
    proof.serialize(&mut proof_bytes).unwrap();
    println!("[Groth16] Proof length     : {}", proof_bytes.len());

    let v_start = Instant::now();
    assert!(verify_proof(&pvk, &proof, &[Fr::from(10u32)]).unwrap());
    let v_time = v_start.elapsed();
    println!("[Groth16] Verify time      : {:?}", v_time);

    let vk2 = VerifyKey::<E>::deserialize(&vk_bytes[..]).unwrap();
    let proof2 = Proof::<E>::deserialize(&proof_bytes[..]).unwrap();
    let pvk2 = prepare_verifying_key(&vk2);
    assert!(verify_proof(&pvk2, &proof2, &[Fr::from(10u32)]).unwrap());
}
