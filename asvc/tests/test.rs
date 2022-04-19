use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::UniformRand;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::test_rng;
use core::ops::Add;
use std::time::Instant;
use zkp_asvc::*;

fn group_gen(domain: &GeneralEvaluationDomain<Fr>) -> Fr {
    match domain {
        GeneralEvaluationDomain::Radix2(radix) => radix.group_gen,
        GeneralEvaluationDomain::MixedRadix(mixed) => mixed.group_gen,
    }
}

#[test]
fn test_aggregatable_svc() {
    let rng = &mut test_rng();
    let size: usize = 8;
    let params = key_gen::<E, _>(size, rng).unwrap();

    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::<Fr>::new(size).unwrap();

    let mut values = Vec::<Fr>::new();
    values.push(Fr::rand(rng));
    values.push(Fr::rand(rng));
    values.push(Fr::rand(rng));
    values.push(Fr::rand(rng));
    values.push(Fr::rand(rng));
    values.push(Fr::rand(rng));
    values.push(Fr::rand(rng));
    values.push(Fr::rand(rng));

    let c = commit(&params.proving_key, values.clone()).unwrap();

    let start = Instant::now();
    let mut points = Vec::<u32>::new();
    let mut point_values = Vec::<Fr>::new();
    points.push(0);
    point_values.push(values[0]);
    points.push(1);
    point_values.push(values[1]);
    points.push(5);
    point_values.push(values[5]);
    let proof = prove_pos(&params.proving_key, values.clone(), points.clone()).unwrap();
    let rs = verify_pos(
        &params.verification_key,
        &c,
        point_values,
        points,
        &proof,
        group_gen(&domain),
    )
    .unwrap();
    let total_setup = start.elapsed();
    println!("ASVC VERIFY POSITION TIME: {:?}", total_setup);
    assert!(rs);

    let start = Instant::now();
    let index: u32 = 2;
    let rs = verify_upk(
        &params.verification_key,
        index,
        &params.proving_key.update_keys[index as usize],
        group_gen(&domain),
    )
    .unwrap();
    let total_setup = start.elapsed();
    println!("ASVC VERIFY UPK TIME: {:?}", total_setup);
    assert!(rs);

    let start = Instant::now();
    let index: u32 = 3;
    let delta = Fr::rand(rng);
    let points_i = vec![index];
    let point_values_i = vec![values[index as usize].add(&delta)];
    let uc = update_commit(
        &c,
        delta,
        index,
        &params.proving_key.update_keys[index as usize],
        group_gen(&domain),
        size,
    )
    .unwrap();
    let proof = prove_pos(&params.proving_key, values.clone(), points_i.clone()).unwrap();
    let proof = update_proof(
        &proof,
        delta,
        index,
        index,
        &params.proving_key.update_keys[index as usize],
        &params.proving_key.update_keys[index as usize],
        group_gen(&domain),
        size,
    )
    .unwrap();
    let rs = verify_pos(
        &params.verification_key,
        &uc,
        point_values_i,
        points_i,
        &proof,
        group_gen(&domain),
    )
    .unwrap();
    let total_setup = start.elapsed();
    println!("ASVC UPDATE COMMIT AND PROOF TIME: {:?}", total_setup);
    assert!(rs);

    let start = Instant::now();
    let index_i: u32 = 4;
    let points_i = vec![index_i];
    let point_values_i = vec![values[index_i as usize]];
    let proof = prove_pos(&params.proving_key, values.clone(), points_i.clone()).unwrap();
    let proof = update_proof(
        &proof,
        delta,
        index_i,
        index,
        &params.proving_key.update_keys[index_i as usize],
        &params.proving_key.update_keys[index as usize],
        group_gen(&domain),
        size,
    )
    .unwrap();
    let rs = verify_pos(
        &params.verification_key,
        &uc,
        point_values_i,
        points_i,
        &proof,
        group_gen(&domain),
    )
    .unwrap();
    let total_setup = start.elapsed();
    println!(
        "ASVC VERIFY UPDATE PROOF, DIFFERENT INDEX TIME: {:?}",
        total_setup
    );
    assert!(rs);

    let start = Instant::now();
    let mut points = Vec::new();
    let mut point_values = Vec::new();
    let mut point_proofs = Vec::new();
    let point = vec![1];
    points.push(1);
    point_values.push(values[1]);
    let proof = prove_pos(&params.proving_key, values.clone(), point.clone()).unwrap();
    point_proofs.push(proof);

    let point = vec![5];
    points.push(5);
    point_values.push(values[5]);
    let proof = prove_pos(&params.proving_key, values.clone(), point.clone()).unwrap();
    point_proofs.push(proof);
    let proofs = aggregate_proofs(points.clone(), point_proofs, group_gen(&domain)).unwrap();
    let rs = verify_pos(
        &params.verification_key,
        &c,
        point_values,
        points,
        &proofs,
        group_gen(&domain),
    )
    .unwrap();
    let total_setup = start.elapsed();
    println!("ASVC VERIFY AGGREGATE PROOFS TIME: {:?}", total_setup);
    assert!(rs);
}
