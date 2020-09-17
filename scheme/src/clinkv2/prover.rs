//use poly_commit::{Error, LabeledPolynomial, PCRandomness, Polynomial};

use crate::Vec;

use super::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable,
};
use super::{push_constraints, Proof};

use math::msm::{FixedBaseMSM, VariableBaseMSM};
use math::{
    AffineCurve, Field, Group, One, PairingEngine, PrimeField, ProjectiveCurve, UniformRand, Zero,
};

use math::fft::domain::*;
use math::fft::polynomial::*;
use math::fft::{DensePolynomial, EvaluationDomain, SparsePolynomial};

// Transcript
use merlin::Transcript;
use rand::Rng;

// KZG10
use super::kzg10::{self, KZG10};

use std::time::{Duration, Instant};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub type KZG10_Proof<E> = kzg10::Proof<E>;
pub type KZG10_Comm<E> = kzg10::Commitment<E>;
pub type KZG10_ck<'a, E> = kzg10::Powers<'a, E>;
pub type KZG10_vk<E> = kzg10::VerifierKey<E>;

// #[derive(Default)]
pub struct ProvingAssignment<E: PairingEngine> {
    // Constraints
    pub at: Vec<Vec<(E::Fr, Index)>>,
    pub bt: Vec<Vec<(E::Fr, Index)>>,
    pub ct: Vec<Vec<(E::Fr, Index)>>,

    // Assignments of variables
    // Two-demension vector
    pub input_assignment: Vec<Vec<E::Fr>>,
    pub aux_assignment: Vec<Vec<E::Fr>>,

    pub(crate) io_cur: usize,
    pub(crate) aux_cur: usize,
}

impl<E: PairingEngine> Default for ProvingAssignment<E> {
    fn default() -> ProvingAssignment<E> {
        ProvingAssignment {
            at: vec![],
            bt: vec![],
            ct: vec![],
            input_assignment: vec![],
            aux_assignment: vec![],
            io_cur: 0usize,
            aux_cur: 0usize,
        }
    }
}

fn as_bytes<T>(x: &T) -> &[u8] {
    use core::mem;
    use core::slice;

    unsafe { slice::from_raw_parts(x as *const T as *const u8, mem::size_of_val(x)) }
}

impl<E: PairingEngine> ConstraintSystem<E::Fr> for ProvingAssignment<E> {
    type Root = Self;

    #[inline]
    fn alloc<F, A, AR>(&mut self, _: A, f: F, i: usize) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        if i == 0 {
            if self.aux_assignment.len() == 0 {
                self.aux_cur = 0;
            }
            let mut aux_varj_vec = vec![];
            aux_varj_vec.push(f()?);
            self.aux_assignment.push(aux_varj_vec);
            let index = self.aux_cur;
            self.aux_cur += 1;
            Ok(Variable::new_unchecked(Index::Aux(index)))
        } else {
            if i == self.aux_assignment[0].len() {
                self.aux_cur = 0;
            }
            self.aux_assignment[self.aux_cur].push(f()?);
            let index = self.aux_cur;
            self.aux_cur += 1;
            Ok(Variable::new_unchecked(Index::Aux(index)))
        }
    }

    #[inline]
    fn alloc_input<F, A, AR>(&mut self, _: A, f: F, i: usize) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        if i == 0 {
            if self.input_assignment.len() == 0 {
                self.io_cur = 0;
            }
            let mut io_varj_vec = vec![];
            io_varj_vec.push(f()?);
            self.input_assignment.push(io_varj_vec);
            let index = self.io_cur;
            self.io_cur += 1;
            Ok(Variable::new_unchecked(Index::Input(index)))
        } else {
            if i == self.input_assignment[0].len() {
                self.io_cur = 0;
            }
            self.input_assignment[self.io_cur].push(f()?);
            let index = self.io_cur;
            self.io_cur += 1;
            Ok(Variable::new_unchecked(Index::Input(index)))
        }
    }

    #[inline]
    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
        LB: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
        LC: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
    {
        let num_constraints = self.num_constraints();

        self.at.push(Vec::new());
        self.bt.push(Vec::new());
        self.ct.push(Vec::new());

        push_constraints(a(LinearCombination::zero()), &mut self.at, num_constraints);
        push_constraints(b(LinearCombination::zero()), &mut self.bt, num_constraints);
        push_constraints(c(LinearCombination::zero()), &mut self.ct, num_constraints);
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }

    fn num_constraints(&self) -> usize {
        self.at.len()
    }
}

impl<E: PairingEngine> ProvingAssignment<E> {
    pub fn create_proof<R: Rng>(
        &self,
        kzg10_ck: &KZG10_ck<E>,
        rng: &mut R,
    ) -> Result<Proof<E>, SynthesisError> {
        // Number of io variables (statements)
        let m_io = self.input_assignment.len();
        // Number of aux variables (witnesses)
        let m_mid = self.aux_assignment.len();
        // Number of all variables
        let m = m_io + m_mid;
        // Number of copies
        let n = self.input_assignment[0].len();

        //println!("m_io: {:?}, m_mid: {:?}, m: {:?}, n: {:?}", m_io, m_mid, m, n);

        let mut transcript = Transcript::new(b"CLINKv2");

        // Compute and commit witness polynomials
        let domain =
            EvaluationDomain::<E::Fr>::new(n).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        let domain_size = domain.size();

        let mut r_q_polys = vec![];
        let mut r_mid_comms = vec![];
        let mut r_mid_q_values = vec![];
        let mut r_mid_q_rands = vec![];

        let zero = E::Fr::zero();
        let one = E::Fr::one();
        let hiding_bound = Some(2);

        let mut rj_commit_time = Duration::new(0, 0);
        let mut rj_ifft_time = Duration::new(0, 0);

        for j in 0..m_io {
            let start = Instant::now();

            let rj_coeffs = domain.ifft(&self.input_assignment[j]);

            rj_ifft_time += start.elapsed();

            let mut rj_poly = DensePolynomial::from_coefficients_vec(rj_coeffs);
            r_q_polys.push(rj_poly);
        }

        for j in 0..m_mid {
            // IFFT
            let start = Instant::now();

            let rj_coeffs = domain.ifft(&self.aux_assignment[j]);

            rj_ifft_time += start.elapsed();

            let mut rj_poly = DensePolynomial::from_coefficients_vec(rj_coeffs);

            // Random shift
            // rj(x) = rj(x) + ρ*t(x)

            // let rho = E::Fr::rand(&mut rng);
            let rho = zero;

            // let mut rho_vanishing_coeffs = vec![zero; n + 1];
            // rho_vanishing_coeffs[0] = -rho;
            // rho_vanishing_coeffs[n] = rho;
            // let rho_vanishing_poly = DensePolynomial::from_coefficients_vec(rho_vanishing_coeffs);
            // rj_poly += &rho_vanishing_poly;

            let rho_poly = DensePolynomial::from_coefficients_vec(vec![rho; 1]);
            let vanishing_poly = domain.vanishing_polynomial();
            rj_poly += &(&rho_poly * &vanishing_poly.into());

            // let mut vanishing_coeffs = vec![zero; n + 1];
            // vanishing_coeffs[0] = -one;
            // vanishing_coeffs[n] = one;
            // let vanishing_poly = DensePolynomial::from_coefficients_vec(vanishing_coeffs);
            // rj_poly += &(&vanishing_poly * &(DensePolynomial::from_coefficients_vec(vec![rho; 1])));

            //println!("r_q_polys[{:?}]: {:?}", j, &rj_poly);
            // Commit to rj mid polynomial
            let start2 = Instant::now();
            let (rj_comm, rj_rand) =
                KZG10::<E>::commit(&kzg10_ck, &rj_poly, hiding_bound, Some(rng))?;
            rj_commit_time += start2.elapsed();
            r_q_polys.push(rj_poly);
            r_mid_comms.push(rj_comm);
            r_mid_q_rands.push(rj_rand);
        }
        println!("rj_ifft_time: {:?}", rj_ifft_time);
        println!("rj_commit_time: {:?}", rj_commit_time);

        transcript.append_message(b"witness polynomial commitments", as_bytes(&r_mid_comms));
        // println!("r_mid_comms: \n{:?}",&r_mid_comms);
        // println!("as_bytes(r_mid_comms): \n{:?}",as_bytes(&r_mid_comms));

        let mut c = [0u8; 31];
        transcript.challenge_bytes(b"batching challenge", &mut c);
        let eta = E::Fr::from_random_bytes(&c).unwrap();

        // Compute and commit quotient polynomials
        let m_abc = self.at.len();
        let mut sum_coset_ab = vec![zero; domain_size];
        let mut sum_c = vec![zero; domain_size];

        let mut eta_i = one;

        let mut q_commit_time = Duration::new(0, 0);
        let mut abci_fft_time = Duration::new(0, 0);
        let start = Instant::now();

        for i in 0..m_abc {
            // let start3 = Instant::now();

            let mut ai_coeffs = vec![zero; domain_size];
            for (coeff, index) in (&self.at[i]).into_iter() {
                let id = match index {
                    Index::Input(j) => *j,
                    Index::Aux(j) => m_io + *j,
                };
                for k in 0..ai_coeffs.len() {
                    ai_coeffs[k] += &(r_q_polys[id].coeffs[k] * coeff);
                }
            }
            let mut ai = DensePolynomial::from_coefficients_vec(ai_coeffs);

            let mut bi_coeffs = vec![zero; domain_size];
            for (coeff, index) in (&self.bt[i]).into_iter() {
                let id = match index {
                    Index::Input(j) => *j,
                    Index::Aux(j) => m_io + *j,
                };
                for k in 0..bi_coeffs.len() {
                    bi_coeffs[k] += &(r_q_polys[id].coeffs[k] * coeff);
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
                .for_each(|(coset_abij, sum_coset_ab_j)| *sum_coset_ab_j += &(eta_i * coset_abij));

            let mut ci_values = vec![zero; domain_size];
            for (coeff, index) in (&self.ct[i]).into_iter() {
                match index {
                    Index::Input(j) => {
                        cfg_iter_mut!(&mut ci_values)
                            .zip(&self.input_assignment[*j])
                            .for_each(|(cij, rij)| *cij += &(*rij * coeff));
                    }
                    Index::Aux(j) => {
                        cfg_iter_mut!(&mut ci_values)
                            .zip(&self.aux_assignment[*j])
                            .for_each(|(cij, rij)| *cij += &(*rij * coeff));
                    }
                };
            }
            // on original domain: n values of \sum{eta^i * c} on original domain
            cfg_iter_mut!(ci_values)
                .zip(&mut sum_c)
                .for_each(|(cij, sum_c_j)| *sum_c_j += &(eta_i * cij));

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

        abci_fft_time += start.elapsed();
        println!("abci_fft_time: {:?}", abci_fft_time);

        let q_poly = DensePolynomial::from_coefficients_vec(sum_coset_ab);
        // println!("q_ploy: {:?}", q_poly.coeffs);

        //let q = qi_poly.evaluate(alpha);

        // Commit to quotient polynomial
        let start2 = Instant::now();

        let (q_comm, q_rand) = KZG10::<E>::commit(&kzg10_ck, &q_poly, hiding_bound, Some(rng))?;

        q_commit_time += start2.elapsed();
        println!("q_commit_time: {:?}", q_commit_time);

        // let m_mid_q = &r_mid_comms.len();
        // println!("m_mid_q:{}", m_mid_q);
        // println!("m_mid:{}", m_mid);

        // println!("&r_mid_comms[0..m_mid].to_vec(): \n{:?}", &r_mid_comms[0..m_mid]);
        // println!("as_bytes(r_mid_comms): \n{:?}",as_bytes(&r_mid_comms));

        //let vanishing_poly = domain.vanishing_polynomial();
        //let t = vanishing_poly.evaluate(alpha);

        //println!("verifying q(x)");
        //assert_eq!(a * &b - &c, q * &t);

        transcript.append_message(b"quotient polynomial commitments", as_bytes(&q_comm));

        // Prove
        // Generate a challenge
        let mut c = [0u8; 31];
        transcript.challenge_bytes(b"random point", &mut c);
        let zeta = E::Fr::from_random_bytes(&c).unwrap();
        // println!("zeta: {:?}", zeta);

        r_q_polys.push(q_poly);
        r_mid_q_rands.push(q_rand);

        let mut open_r_mid_q_time = Duration::new(0, 0);
        let start = Instant::now();

        // println!("m:{}", m);
        // println!("r_q_polys.len():{}",r_q_polys.len());
        for j in 0..(m_mid + 1) {
            let value = r_q_polys[j + m_io].evaluate(zeta);
            r_mid_q_values.push(value);
        }

        // println!("r_mid_q_values[m_io+m_mid]:{:?}", r_mid_q_values[m_mid]);

        let opening_challenge = E::Fr::rand(rng);
        let r_mid_q_proof = KZG10::<E>::batch_open(
            &kzg10_ck,
            &r_q_polys[m_io..],
            zeta,
            opening_challenge,
            &r_mid_q_rands,
        )?;

        open_r_mid_q_time += start.elapsed();
        println!("open_r_mid_q_time: {:?}", open_r_mid_q_time);

        // let mut open_q_time = Duration::new(0, 0);
        // let start = Instant::now();

        // let q_value = q_poly.evaluate(zeta);
        // let q_proof = KZG10::<E>::open(&kzg10_ck, &q_poly, zeta, &q_rand)?;

        // open_q_time += start.elapsed();
        // println!("open_q_time: {:?}", open_q_time);

        // let proof_size = mem::size_of_val(&*r_mid_comms)
        //                 + mem::size_of_val(&*r_mid_q_values)
        //                 + mem::size_of_val(&r_mid_q_proof)
        //                 + mem::size_of_val(&opening_challenge);
        // println!("{:?}", proof_size);

        let proof = Proof {
            r_mid_comms,
            q_comm,
            r_mid_q_values,
            r_mid_q_proof,
            opening_challenge,
        };

        Ok(proof)
    }

    pub fn verify_proof(
        self,
        kzg10_vk: &KZG10_vk<E>,
        proof: &Proof<E>,
        io: &Vec<Vec<E::Fr>>,
    ) -> Result<bool, SynthesisError> {
        let mut transcript = Transcript::new(b"CLINKv2");
        let zero = E::Fr::zero();
        let one = E::Fr::one();
        let m_abc = self.at.len();
        let m_io = io.len();
        let m_mid = proof.r_mid_comms.len();
        let n = io[0].len();

        // println!("&proof.r_mid_comms[..(m_mid_q - 1)].to_vec(): \n{:?}",&proof.r_mid_comms[0..(m_mid_q - 1)]);
        // println!("as_bytes(&proof.r_mid_comms[..(m_mid_q - 1)].to_vec()): \n{:?}",as_bytes(&proof.r_mid_comms[0..(m_mid_q - 1)].to_vec()));
        // println!("as_bytes(&proof.r_mid_comms[..(m_mid_q - 1)].to_vec()): \n{:?}",as_bytes(&proof.r_mid_comms));
        // transcript.append_message(b"witness polynomial commitments", as_bytes(&proof.r_mid_comms[0..m_mid].to_vec()));
        transcript.append_message(
            b"witness polynomial commitments",
            as_bytes(&proof.r_mid_comms),
        );
        let mut c = [0u8; 31];
        transcript.challenge_bytes(b"batching challenge", &mut c);
        let eta = E::Fr::from_random_bytes(&c).unwrap();

        transcript.append_message(b"quotient polynomial commitments", as_bytes(&proof.q_comm));
        c = [0u8; 31];
        transcript.challenge_bytes(b"random point", &mut c);
        let zeta = E::Fr::from_random_bytes(&c).unwrap();

        // println!("zeta: {:?}", zeta);

        let r_mid_q_comms = [&proof.r_mid_comms, &[proof.q_comm][..]].concat();

        assert!(KZG10::<E>::batch_check(
            &kzg10_vk,
            &r_mid_q_comms,
            zeta,
            &proof.r_mid_q_values,
            &proof.r_mid_q_proof,
            proof.opening_challenge
        )?);

        let domain =
            EvaluationDomain::<E::Fr>::new(n).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        let domain_size = domain.size();

        let mut r_io_values = vec![];
        let mut lag_values = domain.evaluate_all_lagrange_coefficients(zeta);
        for j in 0..m_io {
            let mut rj_value = zero;
            for i in 0..io[j].len() {
                rj_value += &(lag_values[i] * &io[j][i]);
            }
            r_io_values.push(rj_value);
        }

        let vanishing_poly = domain.vanishing_polynomial();
        let vanishing_value = vanishing_poly.evaluate(zeta);

        let mut ab_c = zero;
        let mut eta_i = one;

        for i in 0..m_abc {
            let mut ai = zero;
            for (coeff, index) in (&self.at[i]).into_iter() {
                let id = match index {
                    Index::Input(j) => ai += &(r_io_values[*j] * coeff),
                    Index::Aux(j) => ai += &(proof.r_mid_q_values[*j] * coeff),
                };
            }

            let mut bi = zero;
            for (coeff, index) in (&self.bt[i]).into_iter() {
                let id = match index {
                    Index::Input(j) => bi += &(r_io_values[*j] * coeff),
                    Index::Aux(j) => bi += &(proof.r_mid_q_values[*j] * coeff),
                };
            }

            let mut ci = zero;
            for (coeff, index) in (&self.ct[i]).into_iter() {
                let id = match index {
                    Index::Input(j) => ci += &(r_io_values[*j] * coeff),
                    Index::Aux(j) => ci += &(proof.r_mid_q_values[*j] * coeff),
                };
            }

            ab_c += &(eta_i * &(ai * &bi - &ci));
            eta_i = eta_i * &eta;
        }
        assert_eq!(ab_c, proof.r_mid_q_values[m_mid] * &vanishing_value);

        Ok(true)
    }
}
