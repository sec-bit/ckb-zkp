use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::{One, PrimeField};
use ark_serialize::*;
use ark_std::test_rng;
use std::time::Instant;
use zkp_clinkv2::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

pub struct Clinkv2Mini<F: PrimeField> {
    pub x: Option<F>,
    pub y: Option<F>,
    pub z: Option<F>,
    pub num: u32,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Clinkv2Mini<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
        index: usize,
    ) -> Result<(), SynthesisError> {
        cs.alloc_input(|| "", || Ok(F::one()), index)?;

        let var_x = cs.alloc(
            || "x",
            || self.x.ok_or(SynthesisError::AssignmentMissing),
            index,
        )?;

        let var_y = cs.alloc(
            || "y",
            || self.y.ok_or(SynthesisError::AssignmentMissing),
            index,
        )?;

        let var_z = cs.alloc_input(
            || "z(output)",
            || self.z.ok_or(SynthesisError::AssignmentMissing),
            index,
        )?;

        if index == 0 {
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
fn mini_clinkv2_kzg10() {
    use zkp_clinkv2::kzg10::{
        create_random_proof, verify_proof, Proof, ProveAssignment, VerifyAssignment, VerifyKey,
        KZG10,
    };

    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    let n: usize = 100;
    let num = 10;

    let degree: usize = n.next_power_of_two();
    let kzg10_pp = KZG10::<E>::setup(degree, false, rng).unwrap();
    let (kzg10_ck, kzg10_vk) = KZG10::<E>::trim(&kzg10_pp, degree).unwrap();

    let mut vk_bytes = Vec::new();
    kzg10_vk.serialize(&mut vk_bytes).unwrap();
    println!("[Clinkv2 Kzg10] VerifyKey length : {}", vk_bytes.len());

    let p_start = Instant::now();
    let mut prover_pa = ProveAssignment::<E>::default();
    let mut io: Vec<Vec<Fr>> = vec![];
    let mut output: Vec<Fr> = vec![];

    for i in 0..n {
        // Generate a random preimage and compute the image
        {
            // Create an instance of our circuit (with the witness)
            let c = Clinkv2Mini::<Fr> {
                x: Some(Fr::from(2u32)),
                y: Some(Fr::from(3u32)),
                z: Some(Fr::from(10u32)),
                num: num,
            };

            output.push(Fr::from(10u32));
            c.generate_constraints(&mut prover_pa, i).unwrap();
        }
    }
    let one = vec![Fr::one(); n];
    io.push(one);
    io.push(output);

    let proof = create_random_proof(&prover_pa, &kzg10_ck, rng).unwrap();
    let p_time = p_start.elapsed();
    println!("[Clinkv2 Kzg10] Prove time       : {:?}", p_time);

    let mut proof_bytes = vec![];
    proof.serialize(&mut proof_bytes).unwrap();
    println!("[Clinkv2 Kzg10] Proof length     : {}", proof_bytes.len());

    let c = Clinkv2Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };

    let v_start = Instant::now();
    let mut verifier_pa = VerifyAssignment::<E>::default();
    c.generate_constraints(&mut verifier_pa, 0usize).unwrap();
    assert!(verify_proof::<E>(&verifier_pa, &kzg10_vk, &proof, &io).unwrap());
    let v_time = v_start.elapsed();
    println!("[Clinkv2 Kzg10] Verify time      : {:?}", v_time);

    let vk2 = VerifyKey::<E>::deserialize(&vk_bytes[..]).unwrap();
    let proof2 = Proof::<E>::deserialize(&proof_bytes[..]).unwrap();
    assert!(verify_proof::<E>(&verifier_pa, &vk2, &proof2, &io).unwrap());
}

#[test]
fn mini_clinkv2_ipa() {
    use blake2::Blake2s;
    use zkp_clinkv2::ipa::{
        create_random_proof, verify_proof, InnerProductArgPC, Proof, ProveAssignment,
        VerifyAssignment, VerifyKey,
    };

    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    let n: usize = 100;
    let num = 10;

    let degree: usize = n.next_power_of_two();
    let ipa_pp = InnerProductArgPC::<E, Blake2s>::setup(degree, rng).unwrap();
    let (ipa_ck, ipa_vk) = InnerProductArgPC::<E, Blake2s>::trim(&ipa_pp, degree).unwrap();

    let mut vk_bytes = Vec::new();
    ipa_vk.serialize(&mut vk_bytes).unwrap();
    println!("[Clinkv2 Ipa] VerifyKey length   : {}", vk_bytes.len());

    let p_start = Instant::now();
    let mut prover_pa = ProveAssignment::<E, Blake2s>::default();
    let mut io: Vec<Vec<Fr>> = vec![];
    let mut output: Vec<Fr> = vec![];

    for i in 0..n {
        // Generate a random preimage and compute the image
        {
            // Create an instance of our circuit (with the witness)
            let c = Clinkv2Mini::<Fr> {
                x: Some(Fr::from(2u32)),
                y: Some(Fr::from(3u32)),
                z: Some(Fr::from(10u32)),
                num: num,
            };

            output.push(Fr::from(10u32));
            c.generate_constraints(&mut prover_pa, i).unwrap();
        }
    }
    let one = vec![Fr::one(); n];
    io.push(one);
    io.push(output);

    let proof = create_random_proof(&prover_pa, &ipa_ck, rng).unwrap();
    let p_time = p_start.elapsed();
    println!("[Clinkv2 Ipa] Prove time         : {:?}", p_time);

    let mut proof_bytes = vec![];
    proof.serialize(&mut proof_bytes).unwrap();
    println!("[Clinkv2 Ipa] Proof length       : {}", proof_bytes.len());

    let c = Clinkv2Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };

    let v_start = Instant::now();
    let mut verifier_pa = VerifyAssignment::<E, Blake2s>::default();
    c.generate_constraints(&mut verifier_pa, 0usize).unwrap();
    assert!(verify_proof::<E, Blake2s>(&verifier_pa, &ipa_vk, &proof, &io).unwrap());
    let v_time = v_start.elapsed();
    println!("[Clinkv2 Ipa] Verify time        : {:?}", v_time);

    let vk2 = VerifyKey::<E>::deserialize(&vk_bytes[..]).unwrap();
    let proof2 = Proof::<E>::deserialize(&proof_bytes[..]).unwrap();
    assert!(verify_proof::<E, Blake2s>(&verifier_pa, &vk2, &proof2, &io).unwrap());
}
