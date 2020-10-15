use merlin::Transcript;
use rand::Rng;

// DEV
//use std::time::{Duration, Instant};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use math::fft::{DensePolynomial, EvaluationDomain};
use math::{Curve, Field, One, ToBytes, UniformRand, Zero};

use super::{Proof, ProveAssignment, ProveKey, IPAPC};

use super::super::r1cs::{Index, SynthesisError};

use digest::Digest;

pub fn create_random_proof<G, D, R>(
    circuit: &ProveAssignment<G, D>,
    ipa_ck: &ProveKey<G>,
    rng: &mut R,
) -> Result<Proof<G>, SynthesisError>
where
    G: Curve,
    D: Digest,
    R: Rng,
{
    // Number of io variables (statements)
    let m_io = circuit.input_assignment.len();
    // Number of aux variables (witnesses)
    let m_mid = circuit.aux_assignment.len();
    // Number of all variables
    // let m = m_io + m_mid;
    // Number of copies
    let n = circuit.input_assignment[0].len();

    // println!("m_io: {:?}, m_mid: {:?}, n: {:?}", m_io, m_mid, n);

    let mut transcript = Transcript::new(b"CLINKv2");

    // Compute and commit witness polynomials
    let domain =
        EvaluationDomain::<G::Fr>::new(n).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

    let domain_size = domain.size();
    // println!("domain_size: {:?}", domain_size);

    let mut r_polys = vec![];
    // let mut r_mid_comms = vec![];
    let mut r_mid_q_values = vec![];
    // let mut r_mid_rands = vec![];

    let zero = G::Fr::zero();
    let one = G::Fr::one();

    let degree_bound: usize = domain_size - 1;
    let hiding_bound = 2;

    //let mut rj_commit_time = Duration::new(0, 0);
    //let mut rj_ifft_time = Duration::new(0, 0);

    for j in 0..m_io {
        //let start = Instant::now();

        // println!("circuit.input_assignment: {:?}", &circuit.input_assignment);
        let rj_coeffs = domain.ifft(&circuit.input_assignment[j]);
        // println!("rj_coeffs: {:?}", rj_coeffs);

        //rj_ifft_time += start.elapsed();

        let rj_poly = DensePolynomial::from_coefficients_vec(rj_coeffs);
        r_polys.push(rj_poly);
    }

    for j in 0..m_mid {
        // IFFT
        //let start = Instant::now();

        let rj_coeffs = domain.ifft(&circuit.aux_assignment[j]);

        //rj_ifft_time += start.elapsed();

        let mut rj_poly = DensePolynomial::from_coefficients_vec(rj_coeffs);

        let rho = zero;

        let rho_poly = DensePolynomial::from_coefficients_vec(vec![rho; 1]);
        let vanishing_poly = domain.vanishing_polynomial();
        rj_poly += &(&rho_poly * &vanishing_poly.into());

        //let start2 = Instant::now();
        // let (rj_comm, rj_rand) = IPAPC::<G, D>::commit(&ipa_ck, &rj_poly, hiding_bound, Some(rng))?;
        //rj_commit_time += start2.elapsed();
        r_polys.push(rj_poly);
        // r_mid_comms.push(rj_comm);
        // r_mid_rands.push(rj_rand);
    }
    //println!("rj_ifft_time: {:?}", rj_ifft_time);
    //println!("rj_commit_time: {:?}", rj_commit_time);
    let (r_mid_comms, r_mid_rands) = IPAPC::<G, D>::commit(
        &ipa_ck,
        &r_polys[m_io..],
        hiding_bound,
        degree_bound,
        Some(rng),
    )
    .unwrap();

    let mut r_mid_comms_bytes = vec![];
    r_mid_comms.write(&mut r_mid_comms_bytes)?;
    transcript.append_message(b"witness polynomial commitments", &r_mid_comms_bytes);

    let mut c = [0u8; 31];
    transcript.challenge_bytes(b"batching challenge", &mut c);
    let eta = G::Fr::from_random_bytes(&c).unwrap();

    // Compute and commit quotient polynomials
    let m_abc = circuit.at.len();
    let mut sum_coset_ab = vec![zero; domain_size];
    let mut sum_c = vec![zero; domain_size];

    let mut eta_i = one;

    //let mut q_commit_time = Duration::new(0, 0);
    //let mut abci_fft_time = Duration::new(0, 0);
    //let start = Instant::now();

    // println!("r_polys: {:?} * {:?}", &r_polys.len(), &r_polys[0].len());
    // println!("r_polys: {:?}", &r_polys);

    for i in 0..m_abc {
        let mut ai_coeffs = vec![zero; domain_size];
        for (coeff, index) in (&circuit.at[i]).into_iter() {
            let id = match index {
                Index::Input(j) => *j,
                Index::Aux(j) => m_io + *j,
            };
            for k in 0..r_polys[id].coeffs.len() {
                ai_coeffs[k] += &(r_polys[id].coeffs[k] * coeff);
            }
        }
        let mut ai = DensePolynomial::from_coefficients_vec(ai_coeffs);

        let mut bi_coeffs = vec![zero; domain_size];
        for (coeff, index) in (&circuit.bt[i]).into_iter() {
            let id = match index {
                Index::Input(j) => *j,
                Index::Aux(j) => m_io + *j,
            };
            for k in 0..r_polys[id].coeffs.len() {
                bi_coeffs[k] += &(r_polys[id].coeffs[k] * coeff);
            }
        }
        let mut bi = DensePolynomial::from_coefficients_vec(bi_coeffs);

        domain.coset_fft_in_place(&mut ai.coeffs);
        domain.coset_fft_in_place(&mut bi.coeffs);

        // on coset: n values of a*b on coset
        let mut coset_ab_values = domain.mul_polynomials_in_evaluation_domain(&ai, &bi);

        drop(ai);
        drop(bi);

        // on coset: n values of \sum{eta^i * ab} on coset
        cfg_iter_mut!(coset_ab_values)
            .zip(&mut sum_coset_ab)
            .for_each(|(coset_abij, sum_coset_ab_j)| *sum_coset_ab_j += &(eta_i * *coset_abij));

        let mut ci_values = vec![zero; domain_size];
        for (coeff, index) in (&circuit.ct[i]).into_iter() {
            match index {
                Index::Input(j) => {
                    cfg_iter_mut!(&mut ci_values)
                        .zip(&circuit.input_assignment[*j])
                        .for_each(|(cij, rij)| *cij += &(*rij * coeff));
                }
                Index::Aux(j) => {
                    cfg_iter_mut!(&mut ci_values)
                        .zip(&circuit.aux_assignment[*j])
                        .for_each(|(cij, rij)| *cij += &(*rij * coeff));
                }
            };
        }
        // on original domain: n values of \sum{eta^i * c} on original domain
        cfg_iter_mut!(ci_values)
            .zip(&mut sum_c)
            .for_each(|(cij, sum_c_j)| *sum_c_j += &(eta_i * *cij));

        eta_i = eta_i * &eta;
    }

    domain.ifft_in_place(&mut sum_c);
    // on coset: n values of \sum{eta^i * c} on coset
    domain.coset_fft_in_place(&mut sum_c);

    // on coset: n values of \sum{eta^i * (ab - c)} on coset
    cfg_iter_mut!(sum_coset_ab)
        .zip(sum_c)
        .for_each(|(sum_coset_ab_j, sum_coset_c_j)| *sum_coset_ab_j -= &sum_coset_c_j);

    domain.divide_by_vanishing_poly_on_coset_in_place(&mut sum_coset_ab);
    domain.coset_ifft_in_place(&mut sum_coset_ab);

    //abci_fft_time += start.elapsed();
    //println!("abci_fft_time: {:?}", abci_fft_time);

    let q_poly_v = [DensePolynomial::from_coefficients_vec(sum_coset_ab)];

    // Commit to quotient polynomial
    //let start2 = Instant::now();

    let (q_comm_v, q_rand_v) = IPAPC::<G, D>::commit(
        &ipa_ck,
        &q_poly_v[..],
        hiding_bound,
        degree_bound,
        Some(rng),
    )?;

    //q_commit_time += start2.elapsed();
    //println!("q_commit_time: {:?}", q_commit_time);

    let mut q_comm_bytes = vec![];
    q_comm_v[0].write(&mut q_comm_bytes)?;
    transcript.append_message(b"quotient polynomial commitments", &q_comm_bytes);

    // Prove
    // Generate a challenge
    let mut c = [0u8; 31];
    transcript.challenge_bytes(b"random point", &mut c);
    let zeta = G::Fr::from_random_bytes(&c).unwrap();

    // r_polys.push(q_poly);
    // r_mid_rands.push(q_rand);

    //let mut open_r_mid_q_time = Duration::new(0, 0);
    //let start = Instant::now();

    for j in 0..m_mid {
        let value = r_polys[j + m_io].evaluate(zeta);
        r_mid_q_values.push(value);
    }
    let q_value = q_poly_v[0].evaluate(zeta);
    r_mid_q_values.push(q_value);

    let r_mid_q_comms = [&r_mid_comms[..], &q_comm_v[..]].concat();
    let r_mid_q_polys = [&r_polys[m_io..], &q_poly_v[..]].concat();
    let r_mid_q_rands = [&r_mid_rands[..], &q_rand_v[..]].concat();

    let opening_challenge = G::Fr::rand(rng);
    let r_mid_q_proof = IPAPC::<G, D>::open(
        &ipa_ck,
        &r_mid_q_polys[..],
        &r_mid_q_comms[..],
        zeta,
        opening_challenge,
        &r_mid_q_rands,
        degree_bound,
        Some(rng),
    )?;

    //open_r_mid_q_time += start.elapsed();
    //println!("open_r_mid_q_time: {:?}", open_r_mid_q_time);

    let proof = Proof {
        r_mid_comms: r_mid_comms,
        q_comm: q_comm_v[0],
        r_mid_q_values: r_mid_q_values,
        r_mid_q_proof: r_mid_q_proof,
        opening_challenge: opening_challenge,
    };

    Ok(proof)
}
