use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::PrimeField;
use ark_serialize::*;
use ark_std::test_rng;
use std::time::Instant;
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
fn mini_spartan_snark() {
    use zkp_spartan::snark::{
        create_random_proof, generate_random_parameters, verify_proof, Proof, VerifyKey,
    };

    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: 10, // 10-times constraints
    };
    let params = generate_random_parameters::<E, _, _>(c, rng).unwrap();
    let r1cs_hash = params.r1cs.r1cs_to_hash();
    let params_hash = params.params.param_to_hash();
    let encode_hash = params.encode_comm.encode_to_hash();

    let (pk, vk) = params.keypair();

    let mut vk_bytes = Vec::new();
    vk.serialize(&mut vk_bytes).unwrap();

    println!("[Spartan Snark] VerifyKey length : {}", vk_bytes.len());

    let c1 = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: 10,
    };

    let p_start = Instant::now();
    let proof = create_random_proof(&pk, c1,r1cs_hash, params_hash,encode_hash, rng).unwrap();
    let p_time = p_start.elapsed();
    println!("[Spartan Snark] Prove time       : {:?}", p_time);

    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes).unwrap();
    println!("[Spartan Snark] Proof length     : {}", proof_bytes.len());

    let v_start = Instant::now();
    assert!(verify_proof(&vk, &proof, &[Fr::from(10u32)],r1cs_hash, params_hash, encode_hash).unwrap());
    let v_time = v_start.elapsed();
    println!("[Spartan Snark] Verify time      : {:?}", v_time);

    let vk2 = VerifyKey::<E>::deserialize(&vk_bytes[..]).unwrap();
    let proof2 = Proof::<E>::deserialize(&proof_bytes[..]).unwrap();
    assert!(verify_proof(&vk2, &proof2, &[Fr::from(10u32)],r1cs_hash, params_hash, encode_hash).unwrap());
}

#[test]
fn mini_spartan_nizk() {
    use zkp_spartan::nizk::{
        create_random_proof, generate_random_parameters, verify_proof, Proof, VerifyKey,
    };

    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: 10, // 10-times constraints
    };
    let params = generate_random_parameters::<E, _, _>(c, rng).unwrap();
    let r1cs_hash = params.r1cs.r1cs_to_hash();
    let params_hash = params.params.param_to_hash();

    let (pk, vk) = params.keypair();

    let mut vk_bytes = Vec::new();
    vk.serialize(&mut vk_bytes).unwrap();

    println!("[Spartan Nizk] VerifyKey length  : {}", vk_bytes.len());

    let c1 = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: 10,
    };

    let p_start = Instant::now();
    let proof = create_random_proof(&pk, c1, r1cs_hash, params_hash, rng).unwrap();
    let p_time = p_start.elapsed();
    println!("[Spartan Nizk] Prove time        : {:?}", p_time);

    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes).unwrap();
    println!("[Spartan Nizk] Proof length      : {}", proof_bytes.len());

    let v_start = Instant::now();
    assert!(verify_proof(&vk, &proof, &[Fr::from(10u32)],r1cs_hash, params_hash,).unwrap());
    let v_time = v_start.elapsed();
    println!("[Spartan Nizk] Verify time       : {:?}", v_time);

    let vk2 = VerifyKey::<E>::deserialize(&vk_bytes[..]).unwrap();
    let proof2 = Proof::<E>::deserialize(&proof_bytes[..]).unwrap();
    assert!(verify_proof(&vk2, &proof2, &[Fr::from(10u32)],r1cs_hash, params_hash,).unwrap());
}
