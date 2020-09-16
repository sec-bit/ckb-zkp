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

// KZG10
use super::kzg10::{self, KZG10};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use rand::Rng;

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

        println!("=== DEBUG 1 ===");

        // let mut transpose_time = Duration::new(0, 0);
        // let start = Instant::now();

        // let mut r_assignment:Vec<Vec<E::Fr>> = vec![];
        // for j in 0..m_io {
        //     let mut tmp:Vec<E::Fr> = vec![];
        //     for i in 0..n {
        //         tmp.push(self.input_assignment[i][j].clone());
        //     }
        //     r_assignment.push(tmp);
        // }

        // for j in 0..m_mid {
        //     let mut tmp:Vec<E::Fr> = vec![];
        //     for i in 0..n {
        //         tmp.push(self.aux_assignment[i][j].clone());
        //     }
        //     r_assignment.push(tmp);
        // }

        // transpose_time += start.elapsed();
        // let transpose_time =
        // transpose_time.subsec_nanos() as f64 / 1_000_000_000f64 + (transpose_time.as_secs() as f64);
        // println!("transpose_time: {:?}", transpose_time);

        //let pp = KZG10::<E>::setup(degree, false, & mut rng)?;
        //let (ck, _) = KZG10::<E>::trim(&kzg10_params, degree)?;

        // Compute and commit witness polynomials

        // 对rj做ifft，rj长度为n，domain_size为n
        let domain =
            EvaluationDomain::<E::Fr>::new(n).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        let domain_size = domain.size();

        let mut r_polys = vec![];
        let mut r_mid_comms = vec![];
        let mut r_mid_values = vec![];
        let mut r_mid_rands = vec![];

        let zero = E::Fr::zero();
        let one = E::Fr::one();
        let hiding_bound = Some(2);

        println!("=== DEBUG 2 ===");

        //let mut rj_commit_time = Duration::new(0, 0);

        //let mut rj_ifft_time = Duration::new(0, 0);

        for j in 0..m_io {
            //let start = Instant::now();

            let rj_coeffs = domain.ifft(&self.input_assignment[j]);

            //rj_ifft_time += start.elapsed();

            let mut rj_poly = DensePolynomial::from_coefficients_vec(rj_coeffs);
            r_polys.push(rj_poly);
        }

        println!("=== DEBUG 3 ===");

        for j in 0..m_mid {
            // IFFT
            //let start = Instant::now();

            let rj_coeffs = domain.ifft(&self.aux_assignment[j]);

            //rj_ifft_time += start.elapsed();

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

            //println!("r_polys[{:?}]: {:?}", j, &rj_poly);
            // Commit to rj mid polynomial
            //let start2 = Instant::now();
            let (rj_comm, rj_rand) =
                KZG10::<E>::commit(&kzg10_ck, &rj_poly, hiding_bound, Some(rng))?;
            //rj_commit_time += start2.elapsed();
            r_polys.push(rj_poly);
            r_mid_comms.push(rj_comm);
            r_mid_rands.push(rj_rand);
        }

        println!("=== DEBUG 4 ===");

        // let rj_ifft_commit_time =
        // rj_ifft_commit_time.subsec_nanos() as f64 / 1_000_000_000f64 + (rj_ifft_commit_time.as_secs() as f64);
        //println!("rj_ifft_time: {:?}", rj_ifft_time);

        // let rj_commit_time =
        // rj_commit_time.subsec_nanos() as f64 / 1_000_000_000f64 + (rj_commit_time.as_secs() as f64);
        //println!("rj_commit_time: {:?}", rj_commit_time);

        //println!("r_polys.len(): {:?}", r_polys.len());
        transcript.append_message(b"witness polynomial commitments", as_bytes(&r_mid_comms));

        let mut c = [0u8; 31];
        transcript.challenge_bytes(b"opening challenge", &mut c);
        let opening_challenge = E::Fr::from_random_bytes(&c).unwrap();
        let eta = E::Fr::from_random_bytes(&c).unwrap();

        // Compute and commit quotient polynomials
        let m_abc = self.at.len();
        // let mut q_polys = vec![];
        // let mut q_comms = vec![];
        // let mut q_values = vec![];
        // let mut q_rands = vec![];

        // for i in 0..self.at.len() {
        //     println!("at[{:?}]: {:?}", i, &self.at[i]);
        //     println!("---------------------------------------------");
        // }

        // println!("self.at[i].len(): {:?}", &self.at.len());
        // println!("self.at[i].len(): {:?}", &self.bt.len());
        // println!("self.at[i].len(): {:?}", &self.ct.len());

        // Test Passed
        // for i in 0..m_abc {
        //     let mut ai = vec![zero; n];
        //     for (coeff, index) in (&self.at[i]).into_iter() {
        //         let id = match index {
        //             Index::Input(j) => *j,
        //             Index::Aux(j) => m_io + *j,
        //         };

        //         for k in 0..n {
        //             ai[k] += &(r_assignment[id][k] * coeff);
        //         }
        //     }

        //     let mut bi = vec![zero; n];
        //     for (coeff, index) in (&self.bt[i]).into_iter() {
        //         let id = match index {
        //             Index::Input(j) => *j,
        //             Index::Aux(j) => m_io + *j,
        //         };

        //         for k in 0..n {
        //             bi[k] += &(r_assignment[id][k] * coeff);
        //         }
        //     }

        //     let mut ci = vec![zero; n];
        //     for (coeff, index) in (&self.ct[i]).into_iter() {
        //         let id = match index {
        //             Index::Input(j) => *j,
        //             Index::Aux(j) => m_io + *j,
        //         };

        //         for k in 0..n {
        //             ci[k] += &(r_assignment[id][k] * coeff);
        //         }
        //     }

        //     for k in 0..n {
        //         assert_eq!(ai[k] * &bi[k], ci[k]);
        //     }
        // }

        //let mut q_commit_time = Duration::new(0, 0);
        // let mut rj_lc_time = Duration::new(0, 0);

        //let mut abci_fft_time = Duration::new(0, 0);

        // let mut ab_c_poly = DensePolynomial::from_coefficients_vec(vec![zero; domain_size]);
        let mut ab_c_coeffs = vec![zero; domain_size];
        // println!("domain_size:{}", domain_size);

        //let start = Instant::now();

        let mut mul = one;

        println!("=== DEBUG 5 ===");

        for i in 0..m_abc {
            // let start3 = Instant::now();

            let mut ai_coeffs = vec![zero; domain_size];
            for (coeff, index) in (&self.at[i]).into_iter() {
                let id = match index {
                    Index::Input(j) => *j,
                    Index::Aux(j) => m_io + *j,
                };
                // ai += &(&r_polys[id] * &(DensePolynomial::from_coefficients_vec(vec![*coeff; 1])));
                for k in 0..ai_coeffs.len() {
                    ai_coeffs[k] += &(r_polys[id].coeffs[k] * coeff);
                }
            }
            //println!("ai_coeffs: {:?}", ai_coeffs);
            let mut ai = DensePolynomial::from_coefficients_vec(ai_coeffs);

            let mut bi_coeffs = vec![zero; domain_size];
            for (coeff, index) in (&self.bt[i]).into_iter() {
                let id = match index {
                    Index::Input(j) => *j,
                    Index::Aux(j) => m_io + *j,
                };
                // bi += &(&r_polys[id] * &(DensePolynomial::from_coefficients_vec(vec![*coeff; 1])));
                for k in 0..bi_coeffs.len() {
                    bi_coeffs[k] += &(r_polys[id].coeffs[k] * coeff);
                }
            }
            let mut bi = DensePolynomial::from_coefficients_vec(bi_coeffs);
            //println!("bi.coeffs: {:?}", bi.coeffs);

            let mut ci_coeffs = vec![zero; domain_size];
            for (coeff, index) in (&self.ct[i]).into_iter() {
                let id = match index {
                    Index::Input(j) => *j,
                    Index::Aux(j) => m_io + *j,
                };
                //ci += &(&r_polys[id] * &(DensePolynomial::from_coefficients_vec(vec![*coeff; 1])));
                for k in 0..ci_coeffs.len() {
                    ci_coeffs[k] += &(r_polys[id].coeffs[k] * coeff);
                }
            }
            let mut ci = DensePolynomial::from_coefficients_vec(ci_coeffs);

            // rj_lc_time += start3.elapsed();

            // let alpha = E::Fr::rand(&mut rng);
            // let a = ai.evaluate(alpha);
            // let b = bi.evaluate(alpha);
            // let c = ci.evaluate(alpha);

            domain.coset_fft_in_place(&mut ai.coeffs);
            domain.coset_fft_in_place(&mut bi.coeffs);
            domain.coset_fft_in_place(&mut ci.coeffs);

            let mut abi = domain.mul_polynomials_in_evaluation_domain(&ai, &bi);

            // println!("ai.coeffs.len():{}", &ai.coeffs.len());

            // println!("abi: {:?}", abi);
            // println!("ci: {:?}", ci.coeffs);

            drop(ai);
            drop(bi);

            cfg_iter_mut!(abi)
                .zip(ci.coeffs)
                .zip(&mut ab_c_coeffs)
                .for_each(|((abij, cij), ab_c_j)| *ab_c_j += &(mul * &(*abij - &cij)));

            // cfg_iter_mut!(abi)
            //     .zip(ci.coeffs)
            //     .for_each(|(abij, cij)| *abij -= &cij);

            // let eta_mul_poly = DensePolynomial::from_coefficients_vec(vec![mul; 1]);
            // ab_c_poly += &(&eta_mul_poly * &DensePolynomial::from_coefficients_vec(abi));

            mul = mul * &eta;
        }

        println!("=== DEBUG 6 ===");

        println!("ab_c_coeffs: {:?}", ab_c_coeffs.last());

        let mut ab_c_poly = DensePolynomial::from_coefficients_vec(ab_c_coeffs);

        println!("=== DEBUG 6-1 ===");

        domain.divide_by_vanishing_poly_on_coset_in_place(&mut ab_c_poly.coeffs);
        println!("ab_c_poly: {:?}", ab_c_poly.coeffs.last());
        println!("=== DEBUG 6-2 ===");
        domain.coset_ifft_in_place(&mut ab_c_poly.coeffs);
        println!("ab_c_poly: {:?}", ab_c_poly.coeffs.last());
        println!("=== DEBUG 6-3 ===");
        //abci_fft_time += start.elapsed();

        // println!("ab_c_poly: {:?}", ab_c_poly.coeffs);

        let q_poly = ab_c_poly;
        // println!("q_poly: {:?}", q_poly.coeffs);

        //let q = qi_poly.evaluate(alpha);

        // Commit to quotient polynomial
        //let qi_poly = Polynomial::from_coefficients_slice(&abi[..]);
        //let start2 = Instant::now();
        println!("=== DEBUG 6-4 ===");
        let (q_comm, q_rand) = KZG10::<E>::commit(&kzg10_ck, &q_poly, hiding_bound, Some(rng))?;

        //q_commit_time += start2.elapsed();

        // q_comms.push(qi_comm);
        // q_rands.push(qi_rand);
        // q_polys.push(qi_poly);

        //let vanishing_poly = domain.vanishing_polynomial();
        //let t = vanishing_poly.evaluate(alpha);

        //println!("verifying q[{:?}](x): {:?}", i, &q_polys[i]);
        //assert_eq!(a * &b - &c, q * &t);

        // let qi_4fft_commit_time =
        // qi_4fft_commit_time.subsec_nanos() as f64 / 1_000_000_000f64 + (qi_4fft_commit_time.as_secs() as f64);
        //println!("abci_fft_time: {:?}", abci_fft_time);

        // let rj_lc_time =
        // rj_lc_time.subsec_nanos() as f64 / 1_000_000_000f64 + (rj_lc_time.as_secs() as f64);
        // println!("rj_lc_time: {:?}", rj_lc_time);

        // let q_commit_time =
        // q_commit_time.subsec_nanos() as f64 / 1_000_000_000f64 + (q_commit_time.as_secs() as f64);
        //println!("q_commit_time: {:?}", q_commit_time);
        //println!("qi_fft_time: {:?}", qi_4fft_commit_time - qi_4fft_commit_time);
        println!("=== DEBUG 7 ===");

        transcript.append_message(b"quotient polynomial commitments", as_bytes(&q_comm));

        // Prove

        // let mut transcript_hash_time = Duration::new(0, 0);
        // let start = Instant::now();

        // Generate a challenge
        let mut c = [0u8; 31];
        transcript.challenge_bytes(b"random point", &mut c);
        //println!("c: {:?}", c);
        let zeta = E::Fr::from_random_bytes(&c).unwrap();
        //println!("zeta: {:?}", zeta);

        // transcript_hash_time += start.elapsed();
        // let transcript_hash_time =
        // transcript_hash_time.subsec_nanos() as f64 / 1_000_000_000f64 + (transcript_hash_time.as_secs() as f64);
        // println!("transcript_hash_time: {:?}", transcript_hash_time);

        // let mut r_mid_values = vec![];
        //let mut r_mid_combined_proof = vec![];
        //let mut q_values = vec![];
        //let mut q_combined_proof = vec![];

        //let mut open_r_mid_time = Duration::new(0, 0);
        //let start = Instant::now();

        //rintln!("r_mid_rands.len(): {:?}", r_mid_rands.len());
        for j in 0..m_mid {
            //let rj_poly = Polynomial::from_coefficients_slice(&r_assignment[j][..]);
            let rj_value = r_polys[j + m_io].evaluate(zeta);
            // //println!("j: {:?}", j);
            // let rj_proof = KZG10::<E>::open(&kzg10_ck, &rj_poly, zeta, &r_mid_rands[j])?;
            r_mid_values.push(rj_value);
            // r_mid_combined_proof.push(rj_proof);
        }

        println!("=== DEBUG 8 ===");

        let r_mid_combined_proof = KZG10::<E>::batch_open(
            &kzg10_ck,
            &r_polys[m_io..m],
            zeta,
            opening_challenge,
            &r_mid_rands,
        )?;

        println!("=== DEBUG 9 ===");

        //open_r_mid_time += start.elapsed();
        //println!("open_r_mid_time: {:?}", open_r_mid_time);

        //let mut open_q_time = Duration::new(0, 0);
        //let start = Instant::now();

        // for i in 0..m_abc {
        //     let qi_value = q_polys[i].evaluate(zeta);
        //     // let qi_proof = KZG10::<E>::open(&kzg10_ck, &qi_poly, zeta, &q_rands[i])?;
        //     q_values.push(qi_value);
        //     // q_combined_proof.push(qi_proof);
        // }

        let q_value = q_poly.evaluate(zeta);

        let q_proof = KZG10::<E>::open(&kzg10_ck, &q_poly, zeta, &q_rand)?;

        //open_q_time += start.elapsed();
        //println!("open_q_time: {:?}", open_q_time);

        // let mut io:Vec<Vec<E::Fr>> = vec![];
        //println!("io.len(): {:?}", io.len());
        //let io = Cow::Owned(r_assignment[..m_io]);//r_assignment[..m_io].to_owned();
        // for i in 0..m_io {
        //     io.push((&r_assignment[i]).to_vec());
        // }
        //println!("io: {:?}", io);
        //println!("io.len(): {:?}", io.len());

        println!("=== DEBUG 10 ===");

        let proof = Proof {
            r_mid_comms,
            r_mid_values,
            r_mid_combined_proof,
            q_comm,
            q_value,
            q_proof,
            opening_challenge,
        };
        // println!("size_of_val(proof.r_mid_comms): {:?}", mem::size_of_val(&proof.r_mid_comms));
        // println!("proof.r_mid_comms.len(): {:?}", proof.r_mid_comms.len());

        Ok(proof)
    }

    pub fn verify_proof<R: Rng>(
        self,
        kzg10_vk: &KZG10_vk<E>,
        proof: &Proof<E>,
        io: &Vec<Vec<E::Fr>>,
        rng: &mut R,
    ) -> Result<bool, SynthesisError> {
        let mut transcript = Transcript::new(b"CLINKv2");

        transcript.append_message(
            b"witness polynomial commitments",
            as_bytes(&proof.r_mid_comms),
        );
        let mut c = [0u8; 31];
        transcript.challenge_bytes(b"opening challenge", &mut c);
        let opening_challenge = E::Fr::from_random_bytes(&c).unwrap();
        let eta = E::Fr::from_random_bytes(&c).unwrap();

        transcript.append_message(b"quotient polynomial commitments", as_bytes(&proof.q_comm));
        c = [0u8; 31];
        transcript.challenge_bytes(b"random point", &mut c);
        let zeta = E::Fr::from_random_bytes(&c).unwrap();

        // println!("opening challenge: {:?}", opening_challenge);
        // println!("zeta: {:?}", zeta);

        let one = E::Fr::one();

        let m_io = io.len();
        let m = m_io + proof.r_mid_values.len();
        let n = io[0].len();

        //println!("m_io: {:?}, m: {:?}, n: {:?}", m_io, m, n);

        //let mut points = vec![zeta; proof.r_mid_comms.len()];
        assert!(KZG10::<E>::batch_check(
            &kzg10_vk,
            &proof.r_mid_comms,
            zeta,
            &proof.r_mid_values,
            &proof.r_mid_combined_proof,
            opening_challenge
        )?);

        //points = vec![zeta; proof.q_comms.len()];
        assert!(KZG10::<E>::check(
            &kzg10_vk,
            &proof.q_comm,
            zeta,
            proof.q_value,
            &proof.q_proof
        )?);

        let domain =
            EvaluationDomain::<E::Fr>::new(n).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        let domain_size = domain.size();

        let mut r_io_values = vec![];

        // for j in 0..m_io {
        //     // IFFT
        //     let rj_coeffs = domain.ifft(&io[j][..]);
        //     let rj_poly = DensePolynomial::from_coefficients_vec(rj_coeffs);
        //     let rj_value = rj_poly.evaluate(zeta);
        //     //println!("r_io_values[{:?}]: {:?}", j, &rj_value);
        //     r_io_values.push(rj_value);
        //     //println!("r_polys[{:?}]: {:?}", j, rj_poly);
        // }

        let zero = E::Fr::zero();
        let mut lag_values = domain.evaluate_all_lagrange_coefficients(zeta);
        for j in 0..m_io {
            let mut rj_value = zero;
            for i in 0..io[j].len() {
                rj_value += &(lag_values[i] * &io[j][i]);
            }
            r_io_values.push(rj_value);
        }

        //let r_values = [&r_io_values[..], &proof.r_mid_values[..]].concat();

        let vanishing_poly = domain.vanishing_polynomial();
        let vanishing_value = vanishing_poly.evaluate(zeta);

        let zero = E::Fr::zero();

        let m_abc = self.at.len();

        let mut ab_c = zero;

        let mut mul = one;

        for i in 0..m_abc {
            let mut ai = zero;
            for (coeff, index) in (&self.at[i]).into_iter() {
                let id = match index {
                    Index::Input(j) => ai += &(r_io_values[*j] * coeff),
                    Index::Aux(j) => ai += &(proof.r_mid_values[*j] * coeff),
                };
            }

            let mut bi = zero;
            for (coeff, index) in (&self.bt[i]).into_iter() {
                let id = match index {
                    Index::Input(j) => bi += &(r_io_values[*j] * coeff),
                    Index::Aux(j) => bi += &(proof.r_mid_values[*j] * coeff),
                };
            }

            let mut ci = zero;
            for (coeff, index) in (&self.ct[i]).into_iter() {
                let id = match index {
                    Index::Input(j) => ci += &(r_io_values[*j] * coeff),
                    Index::Aux(j) => ci += &(proof.r_mid_values[*j] * coeff),
                };
            }

            ab_c += &(mul * &(ai * &bi - &ci));
            mul = mul * &eta;
        }

        assert_eq!(ab_c, proof.q_value * &vanishing_value);

        Ok(true)
    }
}
