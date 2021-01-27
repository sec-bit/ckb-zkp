use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::PrimeField;
use ark_serialize::*;
use rand::prelude::*;
use std::time::Instant;
use zkp_groth16::{
    create_random_proof, generate_random_parameters, verifier::prepare_verifying_key, verify_proof,
    Parameters, Proof, VerifyKey,
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

/// test for use groth16 & bn_256 & mimc gadget.
fn main() {
    let mut rng = thread_rng();

    // TRUSTED SETUP
    println!("TRUSTED SETUP...");
    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: 10, // 10-times constraints
    };
    let params = generate_random_parameters::<E, _, _>(c, &mut rng).unwrap();

    // you need save this verify key,
    // when verify, use it as a params.
    let mut vk_bytes = Vec::new();
    params.vk.serialize(&mut vk_bytes).unwrap();
    println!("VerifyKey serialize bytes length: {}", vk_bytes.len());

    // you need save this prove key,
    // when prove, use it as a params.
    let mut pk_bytes = Vec::new();
    params.serialize(&mut pk_bytes).unwrap();
    println!("ProveKey serialize bytes length: {}", pk_bytes.len());

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    let x = Fr::from(2u32);
    let y = Fr::from(3u32);
    let z = Fr::from(10u32);

    let circuit = Mini {
        x: Some(x),
        y: Some(y),
        z: Some(z),
        num: 10,
    };

    println!("GROTH16 START PROVE...");
    let p_start = Instant::now();
    let proof = create_random_proof(&params, circuit, &mut rng).unwrap();
    let p_time = p_start.elapsed();
    println!("GROTH16 PROVE TIME: {:?}", p_time);

    println!("GROTH16 START VERIFY...");
    let v_start = Instant::now();
    assert!(verify_proof(&pvk, &proof, &[Fr::from(10u32)]).unwrap());
    let v_time = v_start.elapsed();
    println!("GROTH16 VERIFY TIME: {:?}", v_time);

    println!("Test serialize & verify...");
    let circuit = Mini {
        x: Some(x),
        y: Some(y),
        z: Some(z),
        num: 10,
    };

    let params2 = Parameters::<E>::deserialize(&pk_bytes[..]).unwrap();
    let vk2 = VerifyKey::<E>::deserialize(&vk_bytes[..]).unwrap();
    let pvk2 = prepare_verifying_key(&vk2);
    let proof = create_random_proof(&params2, circuit, &mut rng).unwrap();
    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes).unwrap();
    println!("Proof serialize bytes length: {}", proof_bytes.len());

    let proof2 = Proof::<E>::deserialize(&proof_bytes[..]).unwrap();
    assert!(verify_proof(&pvk2, &proof2, &[Fr::from(10u32)]).unwrap());

    println!("all is ok");
}
