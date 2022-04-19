#![allow(non_snake_case)]

use merlin::Transcript;

use ark_ff::{to_bytes, Field, One};
use ark_serialize::*;
use zkp_curve::{AffineCurve, Curve, ProjectiveCurve};

use crate::Vec;

use super::{inner_product, quick_multiexp, random_bytes_to_fr};

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<G: Curve> {
    L_vec: Vec<G::Affine>,
    R_vec: Vec<G::Affine>,
    a: G::Fr,
    b: G::Fr,
}

// protocol2 should not be used independently
pub fn prove<G: Curve>(
    mut g_vec: Vec<G::Affine>,
    mut h_vec: Vec<G::Affine>,
    u: G::Affine,
    mut a_vec: Vec<G::Fr>,
    mut b_vec: Vec<G::Fr>,
) -> Proof<G> {
    let mut transcript = Transcript::new(b"protocol2");
    let mut n = a_vec.len();
    assert!(n.is_power_of_two());
    assert_eq!(n, b_vec.len());

    let lg_n = n.trailing_zeros() as usize;
    let mut L_vec: Vec<G::Affine> = Vec::with_capacity(lg_n);
    let mut R_vec: Vec<G::Affine> = Vec::with_capacity(lg_n);
    //let mut i = 1;
    while n > 1 {
        //println!("fold, i={}, full_n={}", i, n);
        //i += 1;
        // P computes:
        n = n / 2;
        let (aL, aR) = a_vec.split_at(n);
        let (bL, bR) = b_vec.split_at(n);

        let cL = inner_product::<G::Fr>(aL, bR);
        let cR = inner_product::<G::Fr>(aR, bL);

        let (gL, gR) = g_vec.split_at(n);
        let (hL, hR) = h_vec.split_at(n);

        let L: G::Projective = quick_multiexp::<G>(&aL.to_vec(), &gR.to_vec())
            + &(quick_multiexp::<G>(&bR.to_vec(), &hL.to_vec()))
            + &(u.mul(cL));
        let R: G::Projective = quick_multiexp::<G>(&aR.to_vec(), &gL.to_vec())
            + &(quick_multiexp::<G>(&bL.to_vec(), &hR.to_vec()))
            + &(u.mul(cR));

        // P -> V: L, R
        let l_aff = L.into_affine();
        let r_aff = R.into_affine();
        L_vec.push(l_aff);
        R_vec.push(r_aff);

        // V challenge x, send to P
        transcript.append_message(b"L", &to_bytes![l_aff].unwrap());
        transcript.append_message(b"R", &to_bytes![r_aff].unwrap());

        // V challenge x
        let mut buf_x = [0u8; 31];
        transcript.challenge_bytes(b"x", &mut buf_x);
        // let x = <F as PrimeField>::from_random_bytes(&buf_x).unwrap();
        let x = random_bytes_to_fr::<G::Fr>(&buf_x);
        let x_inv = x.inverse().unwrap();

        // P & V compute:
        let g_new: Vec<G::Affine> = (0..n)
            .map(|i| (gL[i].mul(x_inv) + &(gR[i].mul(x))).into_affine())
            .collect();
        let h_new: Vec<G::Affine> = (0..n)
            .map(|i| (hL[i].mul(x) + &(hR[i].mul(x_inv))).into_affine())
            .collect();
        // let P_new = L * x*x + P + R * x_inv*x_inv;

        // P computes:
        let a_new: Vec<G::Fr> = (0..n).map(|i| aL[i] * &x + &(aR[i] * &x_inv)).collect();
        let b_new: Vec<G::Fr> = (0..n).map(|i| bL[i] * &x_inv + &(bR[i] * &x)).collect();

        a_vec = a_new;
        b_vec = b_new;
        g_vec = g_new;
        h_vec = h_new;
        // P = P_new;
    }

    assert_eq!(a_vec.len(), 1);
    assert_eq!(b_vec.len(), 1);

    let a = a_vec[0];
    let b = b_vec[0];

    Proof { L_vec, R_vec, a, b }
}

pub fn verify<G: Curve>(
    g_vec: Vec<G::Affine>,
    h_vec: Vec<G::Affine>,
    u: G::Affine,
    P: &G::Projective,
    proof: &Proof<G>,
) -> bool {
    let mut transcript = Transcript::new(b"protocol2");
    let lg_n = proof.L_vec.len();
    let n = 1 << lg_n;
    assert_eq!(lg_n, proof.R_vec.len());

    let mut x_sq_vec = Vec::with_capacity(lg_n);
    let mut x_inv_sq_vec = Vec::with_capacity(lg_n);
    let mut allinv = G::Fr::one();
    for i in 0..lg_n {
        transcript.append_message(b"L", &to_bytes![proof.L_vec[i]].unwrap());
        transcript.append_message(b"R", &to_bytes![proof.R_vec[i]].unwrap());

        // V challenge x
        let mut buf_x = [0u8; 31];
        transcript.challenge_bytes(b"x", &mut buf_x);
        let x = random_bytes_to_fr::<G::Fr>(&buf_x);
        let x_inv = x.inverse().unwrap();
        x_sq_vec.push(x * &x);
        x_inv_sq_vec.push(x_inv * &x_inv);
        allinv = allinv * &x_inv;
    }

    // Compute s values inductively. Here adpots optimization from Dalek.
    let mut s: Vec<G::Fr> = Vec::with_capacity(n);
    s.push(allinv);
    for i in 1..n {
        let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
        let k = 1 << lg_i;
        // The challenges are stored in "creation order" as [u_k,...,u_1],
        // so u_{lg(i)+1} = is indexed by (lg_n-1) - lg_i
        let u_lg_i_sq = x_sq_vec[(lg_n - 1) - lg_i];
        s.push(s[i - k] * &u_lg_i_sq);
    }

    let mut inv_s = s.clone();
    inv_s.reverse();
    let a_s: Vec<G::Fr> = (0..n).map(|i| proof.a * &s[i]).collect();
    let b_s: Vec<G::Fr> = (0..n).map(|i| proof.b * &inv_s[i]).collect();

    let c_final = proof.a * &proof.b;
    let CheckP_lhs: G::Projective = quick_multiexp::<G>(&a_s, &g_vec.to_vec())
        + &(quick_multiexp::<G>(&b_s, &h_vec.to_vec()))
        + &(u.mul(c_final));
    let CheckP_rhs: G::Projective = quick_multiexp::<G>(&x_sq_vec, &proof.L_vec)
        + &(quick_multiexp::<G>(&x_inv_sq_vec, &proof.R_vec))
        + P;

    CheckP_lhs == CheckP_rhs
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_std::{test_rng, UniformRand};
    use std::time::Instant;

    use super::*;

    #[cfg(test)]
    fn run_protocol2_helper<G: Curve>(n: usize) {
        let t1 = Instant::now();
        assert!(n.is_power_of_two());

        let mut rng = test_rng();

        // generators
        let mut g_vec: Vec<G::Affine> = Vec::with_capacity(n);
        for _ in 0..n {
            g_vec.push(G::Projective::rand(&mut rng).into_affine());
        }

        let mut h_vec: Vec<G::Affine> = Vec::with_capacity(n);
        for _ in 0..n {
            h_vec.push(G::Projective::rand(&mut rng).into_affine());
        }
        let u: G::Affine = G::Projective::rand(&mut rng).into_affine();

        let duration = t1.elapsed();
        println!(
            "<<<<<<<<<<<<<<<<<<<<<<<< \n n = {}, Time elapsed in generators is: {:?}",
            n, duration
        );

        let t2 = Instant::now();
        // generate a_vec/b_vec for test
        let a_vec: Vec<G::Fr> = (0..n).map(|_| G::Fr::rand(&mut rng)).collect();
        let b_vec: Vec<G::Fr> = (0..n).map(|_| G::Fr::rand(&mut rng)).collect();
        let c = inner_product::<G::Fr>(&a_vec, &b_vec);
        let P = quick_multiexp::<G>(&a_vec, &g_vec)
            + &(quick_multiexp::<G>(&b_vec, &h_vec))
            + &(u.mul(c));
        let duration = t2.elapsed();
        println!("Time elapsed in a_vec b_vec is: {:?}", duration);

        let t3 = Instant::now();
        let proof = prove::<G>(
            g_vec.clone(),
            h_vec.clone(),
            u,
            a_vec.clone(),
            b_vec.clone(),
        );
        let duration = t3.elapsed();
        println!("Time elapsed in prove is: {:?}", duration);

        let t4 = Instant::now();
        assert!(verify::<G>(g_vec.clone(), h_vec.clone(), u, &P, &proof));
        let duration = t4.elapsed();
        println!(
            "Time elapsed in verify is: {:?} \n >>>>>>>>>>>>>>>>>>>",
            duration
        );
    }

    #[test]
    fn run_ipp_256() {
        //run_protocol2_helper::<Bn_256>(256);
        run_protocol2_helper::<Bls12_381>(256);
    }

    #[test]
    fn run_ipp_128() {
        //run_protocol2_helper::<Bn_256>(128);
        run_protocol2_helper::<Bls12_381>(128);
    }

    #[test]
    fn run_ipp_64() {
        //run_protocol2_helper::<Bn_256>(64);
        run_protocol2_helper::<Bls12_381>(64);
    }

    #[test]
    fn run_ipp_32() {
        //run_protocol2_helper::<Bn_256>(32);
        run_protocol2_helper::<Bls12_381>(32);
    }

    #[test]
    fn run_ipp_2() {
        //run_protocol2_helper::<Bn_256>(2);
        run_protocol2_helper::<Bls12_381>(2);
    }

    #[test]
    fn run_ipp_1() {
        //run_protocol2_helper::<Bn_256>(1);
        run_protocol2_helper::<Bls12_381>(1);
    }
}
