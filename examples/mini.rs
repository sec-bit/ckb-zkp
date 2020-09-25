use ckb_zkp::{
    bn_256::{Bn_256, Fr},
    groth16::{
        create_random_proof, generate_random_parameters, prove_to_bytes,
        verifier::prepare_verifying_key, verify_from_bytes, verify_proof,
    },
    math::{PrimeField, ToBytes},
    r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError},
};
use rand::prelude::*;
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
    let params = generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap();

    // you need save this prove key,
    // when prove, use it as a params.
    let mut pk_bytes = vec![];
    params.write(&mut pk_bytes).unwrap();

    // you need save this verify key,
    // when verify, use it as a params.
    let mut vk_bytes = vec![];
    params.vk.write(&mut vk_bytes).unwrap();

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

    println!("GROTH16 START PROVE & VERIFY WITH BYTES...");
    let circuit = Mini {
        x: Some(x),
        y: Some(y),
        z: Some(z),
        num: 10,
    };

    let (proof_bytes, publics_bytes) =
        prove_to_bytes(&params, circuit, &mut rng, &[Fr::from(10u32)]).unwrap();

    assert!(verify_from_bytes::<Bn_256>(&vk_bytes, &proof_bytes, &publics_bytes).unwrap());

    println!("all is ok");
}
