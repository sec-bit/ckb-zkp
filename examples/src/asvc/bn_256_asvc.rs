use core::ops::Add;
use curve::bn_256::Bn_256;
use math::fft::EvaluationDomain;
use math::{test_rng, PairingEngine, UniformRand};
use scheme::asvc::*;

pub fn test_aggregatable_svc() {
    let rng = &mut test_rng();
    let size: usize = 8;
    let params = key_gen::<Bn_256, _>(size, rng).unwrap();

    let domain = EvaluationDomain::<<Bn_256 as PairingEngine>::Fr>::new(size).unwrap();

    let mut values = Vec::<<Bn_256 as PairingEngine>::Fr>::new();
    values.push(<Bn_256 as PairingEngine>::Fr::rand(rng));
    values.push(<Bn_256 as PairingEngine>::Fr::rand(rng));
    values.push(<Bn_256 as PairingEngine>::Fr::rand(rng));
    values.push(<Bn_256 as PairingEngine>::Fr::rand(rng));
    values.push(<Bn_256 as PairingEngine>::Fr::rand(rng));
    values.push(<Bn_256 as PairingEngine>::Fr::rand(rng));
    values.push(<Bn_256 as PairingEngine>::Fr::rand(rng));
    values.push(<Bn_256 as PairingEngine>::Fr::rand(rng));

    let c = commit(&params.proving_key, values.clone()).unwrap();

    println!("--------verify position...");
    let mut points = Vec::<u32>::new();
    let mut point_values = Vec::<<Bn_256 as PairingEngine>::Fr>::new();
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
        domain.group_gen,
    )
    .unwrap();
    println!("--------verify position...{}\n", rs);
    assert!(rs);

    println!("--------verify updating key...");
    let index: u32 = 2;
    let rs = verify_upk(
        &params.verification_key,
        index,
        &params.proving_key.update_keys[index as usize],
        domain.group_gen,
    )
    .unwrap();
    println!("--------verify updating key...{}\n", rs);
    assert!(rs);

    println!("--------verify update proof...");
    let index: u32 = 3;
    let delta = <Bn_256 as PairingEngine>::Fr::rand(rng);
    let points_i = vec![index];
    let point_values_i = vec![values[index as usize].add(&delta)];
    let uc = update_commit(
        &c,
        delta,
        index,
        &params.proving_key.update_keys[index as usize],
        domain.group_gen,
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
        domain.group_gen,
        size,
    )
    .unwrap();
    let rs = verify_pos(
        &params.verification_key,
        &uc,
        point_values_i,
        points_i,
        &proof,
        domain.group_gen,
    )
    .unwrap();
    println!("--------verify update proof...{}\n", rs);
    assert!(rs);

    println!("--------start verify update proof, different index...");
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
        domain.group_gen,
        size,
    )
    .unwrap();
    let rs = verify_pos(
        &params.verification_key,
        &uc,
        point_values_i,
        points_i,
        &proof,
        domain.group_gen,
    )
    .unwrap();
    println!("--------verify update proof, different index...{}\n", rs);
    assert!(rs);

    println!("--------start verify aggregate proofs...");
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
    let proofs = aggregate_proofs(points.clone(), point_proofs, domain.group_gen).unwrap();
    let rs = verify_pos(
        &params.verification_key,
        &c,
        point_values,
        points,
        &proofs,
        domain.group_gen,
    )
    .unwrap();
    println!("--------verify aggregate proofs...{}\n", rs);
    assert!(rs);
}
