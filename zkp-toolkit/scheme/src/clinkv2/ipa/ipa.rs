use math::{
    fft::DensePolynomial as Polynomial,
    msm::VariableBaseMSM,
    AffineCurve, Curve, Field, One, PrimeField, ProjectiveCurve, ToBytes, UniformRand,
    Zero,
};

// use rand::Rng;
use digest::Digest;
use rand_core::RngCore;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use core::marker::PhantomData;

use crate::*;

/// `UniversalParams` are the universal parameters for the inner product arg scheme.
#[derive(Derivative, Serialize, Deserialize)]
#[derivative(Default(bound = ""), Clone(bound = ""), Debug(bound = ""))]
pub struct UniversalParams<G: Curve> {
    /// The key used to commit to polynomials.
    pub comm_key: Vec<G::Affine>,
    /// Some group generator.
    pub h: G::Affine,
    /// Some group generator specifically used for hiding.
    pub s: G::Affine,
}

impl<G: Curve> UniversalParams<G> {
    //PCUniversalParams for
    pub fn max_degree(&self) -> usize {
        self.comm_key.len() - 1
    }
}

/// `CommitterKey` is used to commit to, and create evaluation proofs for, a given
/// polynomial.
#[derive(Derivative, Serialize, Deserialize)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Debug(bound = "")
)]
pub struct CommitterKey<G: Curve> {
    /// The key used to commit to polynomials.
    pub comm_key: Vec<G::Affine>,
    /// A random group generator.
    pub h: G::Affine,
    /// A random group generator that is to be used to make
    /// a commitment hiding.
    pub s: G::Affine,
    /// The maximum degree supported by the parameters
    /// this key was derived from.
    pub max_degree: usize,
}

impl<G: Curve> CommitterKey<G> {
    //PCCommitterKey for
    pub fn max_degree(&self) -> usize {
        self.max_degree
    }
    pub fn supported_degree(&self) -> usize {
        self.comm_key.len() - 1
    }
}

impl<G: Curve> PartialEq for CommitterKey<G> {
    fn eq(&self, other: &Self) -> bool {
        self.comm_key == other.comm_key
            && self.h == other.h
            && self.s == other.s
            && self.max_degree == other.max_degree
    }
}

impl<G: Curve> Eq for CommitterKey<G> {}

/// `VerifierKey` is used to check evaluation proofs for a given commitment.
pub type VerifierKey<G> = CommitterKey<G>;

/// Commitment to a polynomial that optionally enforces a degree bound.
#[derive(Derivative, Serialize, Deserialize)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct Commitment<G: Curve> {
    /// A Pedersen commitment to the polynomial.
    pub comm: G::Affine,
    /// A Pedersen commitment to the shifted polynomial.
    /// This is `none` if the committed polynomial does not
    /// enforce a strict degree bound.
    pub shifted_comm: G::Affine, //Option<G::Affine>,
}

impl<G: Curve> ToBytes for Commitment<G> {
    #[inline]
    fn write<W: math::io::Write>(&self, mut writer: W) -> math::io::Result<()> {
        self.comm.write(&mut writer)?;
        self.shifted_comm.write(&mut writer)
    }
}

/// `Randomness` hides the polynomial inside a commitment and is outputted by `InnerProductArg::commit`.
#[derive(Derivative)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct Randomness<G: Curve> {
    /// Randomness is some scalar field element.
    pub rand: G::Fr,
    /// Randomness applied to the shifted commitment is some scalar field element.
    pub shifted_rand: Option<G::Fr>,
}

impl<G: Curve> Randomness<G> {
    //PCRandomness for
    pub fn empty() -> Self {
        Self {
            rand: G::Fr::zero(),
            shifted_rand: None,
        }
    }

    pub fn rand<R: RngCore>(_num_queries: usize, has_degree_bound: bool, rng: &mut R) -> Self {
        let rand = G::Fr::rand(rng);
        let shifted_rand = if has_degree_bound {
            Some(G::Fr::rand(rng))
        } else {
            None
        };

        Self { rand, shifted_rand }
    }
}

/// `Proof` is an evaluation proof that is output by `InnerProductArg::open`.
#[derive(Derivative, Serialize, Deserialize)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    // Copy(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct Proof<G: Curve> {
    /// Vector of left elements for each of the log_d iterations in `open`
    pub l_vec: Vec<G::Affine>,
    /// Vector of right elements for each of the log_d iterations within `open`
    pub r_vec: Vec<G::Affine>,
    /// Committer key from the last iteration within `open`
    pub final_comm_key: G::Affine,
    /// Coefficient from the last iteration within withinopen`
    pub c: G::Fr,
    /// Commitment to the blinding polynomial.
    pub hiding_comm: Option<G::Affine>,
    /// Linear combination of all the randomness used for commitments
    /// to the opened polynomials, along with the randomness used for the
    /// commitment to the hiding polynomial.
    pub rand: Option<G::Fr>,
}

/// `SuccinctCheckPolynomial` is a succinctly-representated polynomial
/// generated from the `log_d` random oracle challenges generated in `open`.
/// It has the special property that can be evaluated in `O(log_d)` time.
pub struct SuccinctCheckPolynomial<F: Field>(pub Vec<F>);

impl<F: Field> SuccinctCheckPolynomial<F> {
    /// Computes the coefficients of the underlying degree `d` polynomial.
    pub fn compute_coeffs(&self) -> Vec<F> {
        let challenges = &self.0;
        let log_d = challenges.len();

        let mut coeffs = vec![F::one(); 1 << log_d];
        for (i, challenge) in challenges.iter().enumerate() {
            let i = i + 1;
            let elem_degree = 1 << (log_d - i);
            for start in (elem_degree..coeffs.len()).step_by(elem_degree * 2) {
                for offset in 0..elem_degree {
                    coeffs[start + offset] *= challenge;
                }
            }
        }

        coeffs
    }

    /// Evaluate `self` at `point` in time `O(log_d)`.
    pub fn evaluate(&self, point: F) -> F {
        let challenges = &self.0;
        let log_d = challenges.len();

        let mut product = F::one();
        for (i, challenge) in challenges.iter().enumerate() {
            let i = i + 1;
            let elem_degree: u64 = (1 << (log_d - i)) as u64;
            let elem = point.pow([elem_degree]);
            product *= &(F::one() + &(elem * challenge));
        }

        product
    }
}

// Inner product argument-based polynomial commitment
pub struct InnerProductArgPC<G: Curve, D: Digest> {
    _projective: PhantomData<G>,
    _digest: PhantomData<D>,
}

impl<G: Curve, D: Digest> InnerProductArgPC<G, D> {
    /// `PROTOCOL_NAME` is used as a seed for the setup function.
    pub const PROTOCOL_NAME: &'static [u8] = b"PC-DL-2020";

    /// Create a Pedersen commitment to `scalars` using the commitment key `comm_key`.
    /// Optionally, randomize the commitment using `hiding_generator` and `randomizer`.
    fn cm_commit(
        comm_key: &[G::Affine],
        scalars: &[G::Fr],
        hiding_generator: Option<G::Affine>,
        randomizer: Option<G::Fr>,
    ) -> G::Projective {
        let scalars_bigint = math::cfg_iter!(scalars)
            .map(|s| s.into_repr())
            .collect::<Vec<_>>();

        let mut comm = VariableBaseMSM::multi_scalar_mul(comm_key, &scalars_bigint);

        if randomizer.is_some() {
            assert!(hiding_generator.is_some());
            comm += &hiding_generator.unwrap().mul(randomizer.unwrap());
        }

        comm
    }

    fn compute_random_oracle_challenge(bytes: &[u8]) -> G::Fr {
        let mut i = 0u64;
        let mut challenge = None;
        while challenge.is_none() {
            let hash_input = math::to_bytes![bytes, i].unwrap();
            let hash = D::digest(&hash_input);
            challenge = <G::Fr as Field>::from_random_bytes(&hash);

            i += 1;
        }

        challenge.unwrap()
    }

    #[inline]
    fn inner_product(l: &[G::Fr], r: &[G::Fr]) -> G::Fr {
        math::cfg_iter!(l).zip(r).map(|(li, ri)| *li * ri).sum()
    }

    /// The succinct portion of `PC::check`. This algorithm runs in time
    /// O(log d), where d is the degree of the committed polynomials.
    fn succinct_check<'a>(
        vk: &VerifierKey<G>,
        commitments: impl IntoIterator<Item = &'a Commitment<G>>,
        point: G::Fr,
        values: impl IntoIterator<Item = &'a G::Fr>,
        proof: &Proof<G>,
        degree_bound: usize,
        opening_challenge: G::Fr,
    ) -> Option<SuccinctCheckPolynomial<G::Fr>> {
        let d = vk.supported_degree();

        // `log_d` is ceil(log2 (d + 1)), which is the number of steps to compute all of the challenges
        let log_d = math::log2(d + 1) as usize;

        let mut combined_commitment_proj = G::Projective::zero();
        let mut combined_v = G::Fr::zero();

        let mut cur_challenge = opening_challenge;
        let commitments_iter = commitments.into_iter();
        let values = values.into_iter();

        for (commitment, value) in commitments_iter.zip(values) {
            combined_v += &(cur_challenge * value);
            combined_commitment_proj += &commitment.comm.mul(cur_challenge);
            cur_challenge *= &opening_challenge;

            let shift = point.pow([(vk.supported_degree() - degree_bound) as u64]);
            combined_v += &(cur_challenge * value * &shift);
            combined_commitment_proj += &commitment.shifted_comm.mul(cur_challenge);

            cur_challenge *= &opening_challenge;
        }

        let mut combined_commitment = combined_commitment_proj.into_affine();

        assert_eq!(proof.hiding_comm.is_some(), proof.rand.is_some());
        if proof.hiding_comm.is_some() {
            let hiding_comm = proof.hiding_comm.unwrap();
            let rand = proof.rand.unwrap();

            let hiding_challenge = Self::compute_random_oracle_challenge(
                &math::to_bytes![combined_commitment, point, combined_v, hiding_comm].unwrap(),
            );
            combined_commitment_proj += &(hiding_comm.mul(hiding_challenge) - &vk.s.mul(rand));
            combined_commitment = combined_commitment_proj.into_affine();
        }

        // Challenge for each round
        let mut round_challenges = Vec::with_capacity(log_d);
        let mut round_challenge = Self::compute_random_oracle_challenge(
            &math::to_bytes![combined_commitment, point, combined_v].unwrap(),
        );

        let h_prime = vk.h.mul(round_challenge);

        let mut round_commitment_proj = combined_commitment_proj + &h_prime.mul(combined_v);

        let l_iter = proof.l_vec.iter();
        let r_iter = proof.r_vec.iter();

        for (l, r) in l_iter.zip(r_iter) {
            round_challenge = Self::compute_random_oracle_challenge(
                &math::to_bytes![round_challenge, l, r].unwrap(),
            );
            round_challenges.push(round_challenge);
            round_commitment_proj +=
                &(l.mul(round_challenge.inverse().unwrap()) + &r.mul(round_challenge));
        }

        let check_poly = SuccinctCheckPolynomial::<G::Fr>(round_challenges);
        let v_prime = check_poly.evaluate(point) * &proof.c;
        let h_prime = h_prime.into_affine();

        let check_commitment_elem: G::Projective = Self::cm_commit(
            &[proof.final_comm_key.clone(), h_prime],
            &[proof.c.clone(), v_prime],
            None,
            None,
        );

        if !(round_commitment_proj - &check_commitment_elem).is_zero() {
            return None;
        }

        Some(check_poly)
    }

    fn shift_polynomial(
        ck: &CommitterKey<G>,
        p: &Polynomial<G::Fr>,
        degree_bound: usize,
    ) -> Polynomial<G::Fr> {
        if p.is_zero() {
            Polynomial::zero()
        } else {
            let mut shifted_polynomial_coeffs =
                vec![G::Fr::zero(); ck.supported_degree() - degree_bound];
            shifted_polynomial_coeffs.extend_from_slice(&p.coeffs);
            Polynomial::from_coefficients_vec(shifted_polynomial_coeffs)
        }
    }

    fn sample_generators(num_generators: usize) -> Vec<G::Affine> {
        let generators: Vec<_> = math::cfg_into_iter!(0..num_generators)
            .map(|i| {
                let i = i as u64;
                let mut hash = D::digest(&to_bytes![&Self::PROTOCOL_NAME, i].unwrap());
                let mut g = G::Affine::from_random_bytes(&hash);
                let mut j = 0u64;
                while g.is_none() {
                    hash = D::digest(&to_bytes![&Self::PROTOCOL_NAME, i, j].unwrap());
                    g = G::Affine::from_random_bytes(&hash);
                    j += 1;
                }
                let generator = g.unwrap();
                generator.mul_by_cofactor().into_projective()
            })
            .collect();

        G::Projective::batch_normalization_into_affine(&generators)
    }

    pub fn setup<R: RngCore>(max_degree: usize, _rng: &mut R) -> Result<UniversalParams<G>, Error> {
        // Ensure that max_degree + 1 is a power of 2
        let max_degree = (max_degree + 1).next_power_of_two() - 1;

        let mut generators = Self::sample_generators(max_degree + 3);

        let h = generators.pop().unwrap();
        let s = generators.pop().unwrap();

        let pp = UniversalParams {
            comm_key: generators,
            h,
            s,
        };

        Ok(pp)
    }

    pub fn trim(
        pp: &UniversalParams<G>,
        supported_degree: usize,
    ) -> Result<(CommitterKey<G>, VerifierKey<G>), Error> {
        // Ensure that supported_degree + 1 is a power of two
        let supported_degree = (supported_degree + 1).next_power_of_two() - 1;
        if supported_degree > pp.max_degree() {
            return Err(Error::TrimmingDegreeTooLarge);
        }

        let ck = CommitterKey {
            comm_key: pp.comm_key[0..(supported_degree + 1)].to_vec(),
            h: pp.h.clone(),
            s: pp.s.clone(),
            max_degree: pp.max_degree(),
        };

        let vk = VerifierKey {
            comm_key: pp.comm_key[0..(supported_degree + 1)].to_vec(),
            h: pp.h.clone(),
            s: pp.s.clone(),
            max_degree: pp.max_degree(),
        };

        Ok((ck, vk))
    }

    /// Outputs a commitment to `polynomial`.
    pub fn commit<'a>(
        ck: &CommitterKey<G>,
        polynomials: impl IntoIterator<Item = &'a Polynomial<G::Fr>>,
        hiding_bound: usize,
        degree_bound: usize,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<(Vec<Commitment<G>>, Vec<Randomness<G>>), Error> {
        // let rng = &mut crate::optional_rng::OptionalRng(rng);
        let mut rng = rng.expect("hiding commitments require randomness");
        let mut comms = Vec::new();
        let mut rands = Vec::new();

        for polynomial in polynomials {
            let randomness = Randomness::rand(hiding_bound, true, &mut rng);

            let comm = Self::cm_commit(
                &ck.comm_key[..(polynomial.degree() + 1)],
                &polynomial.coeffs,
                Some(ck.s),
                Some(randomness.rand),
            )
            .into();

            assert!(ck.supported_degree() >= degree_bound);

            let shifted_comm = Self::cm_commit(
                &ck.comm_key[(ck.supported_degree() - degree_bound)..],
                &polynomial.coeffs,
                Some(ck.s),
                randomness.shifted_rand,
            )
            .into();

            let commitment = Commitment { comm, shifted_comm };

            comms.push(commitment);
            rands.push(randomness);
        }

        Ok((comms, rands))
    }

    pub fn open<'a>(
        ck: &CommitterKey<G>,
        polynomials: impl IntoIterator<Item = &'a Polynomial<G::Fr>>,
        commitments: impl IntoIterator<Item = &'a Commitment<G>>,
        point: G::Fr,
        opening_challenge: G::Fr,
        rands: impl IntoIterator<Item = &'a Randomness<G>>,
        degree_bound: usize,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<Proof<G>, Error>
    where
        Commitment<G>: 'a,
        Randomness<G>: 'a,
    {
        let mut combined_polynomial = Polynomial::zero();
        let mut combined_rand = G::Fr::zero();
        let mut combined_commitment_proj = G::Projective::zero();

        let polys_iter = polynomials.into_iter();
        let rands_iter = rands.into_iter();
        let comms_iter = commitments.into_iter();

        let mut cur_challenge = opening_challenge;
        for (polynomial, (commitment, randomness)) in polys_iter.zip(comms_iter.zip(rands_iter)) {
            combined_polynomial += (cur_challenge, polynomial);
            combined_commitment_proj += &commitment.comm.mul(cur_challenge);

            combined_rand += &(cur_challenge * &randomness.rand);

            cur_challenge *= &opening_challenge;

            let shifted_polynomial = Self::shift_polynomial(ck, polynomial, degree_bound);
            combined_polynomial += (cur_challenge, &shifted_polynomial);
            combined_commitment_proj += &commitment.shifted_comm.mul(cur_challenge);

            let shifted_rand = randomness.shifted_rand;
            assert!(shifted_rand.is_some(), "shifted_rand.is_none()",);
            combined_rand += &(cur_challenge * &shifted_rand.unwrap());

            cur_challenge *= &opening_challenge;
        }

        let combined_v = combined_polynomial.evaluate(point);

        // Pad the coefficients to the appropriate vector size
        let d = ck.supported_degree();

        // `log_d` is ceil(log2 (d + 1)), which is the number of steps to compute all of the challenges
        let log_d = math::log2(d + 1) as usize;

        let mut combined_commitment;

        let mut rng = rng.expect("hiding commitments require randomness");
        let mut hiding_polynomial = Polynomial::rand(d, &mut rng);
        hiding_polynomial -=
            &Polynomial::from_coefficients_slice(&[hiding_polynomial.evaluate(point)]);

        let hiding_rand = G::Fr::rand(rng);
        let hiding_commitment_proj = Self::cm_commit(
            ck.comm_key.as_slice(),
            hiding_polynomial.coeffs.as_slice(),
            Some(ck.s),
            Some(hiding_rand),
        );

        let mut batch = G::Projective::batch_normalization_into_affine(&[
            combined_commitment_proj,
            hiding_commitment_proj,
        ]);
        let hiding_commitment = Some(batch.pop().unwrap());
        combined_commitment = batch.pop().unwrap();

        let hiding_challenge = Self::compute_random_oracle_challenge(
            &math::to_bytes![
                combined_commitment,
                point,
                combined_v,
                hiding_commitment.unwrap()
            ]
            .unwrap(),
        );
        combined_polynomial += (hiding_challenge, &hiding_polynomial);
        combined_rand += &(hiding_challenge * &hiding_rand);
        combined_commitment_proj +=
            &(hiding_commitment_proj.mul(hiding_challenge) - &ck.s.mul(combined_rand));

        let combined_rand = Some(combined_rand);

        combined_commitment = combined_commitment_proj.into_affine();

        // ith challenge
        let mut round_challenge = Self::compute_random_oracle_challenge(
            &math::to_bytes![combined_commitment, point, combined_v].unwrap(),
        );

        let h_prime = ck.h.mul(round_challenge).into_affine();

        // Pads the coefficients with zeroes to get the number of coeff to be d+1
        let mut coeffs = combined_polynomial.coeffs;
        if coeffs.len() < d + 1 {
            for _ in coeffs.len()..(d + 1) {
                coeffs.push(G::Fr::zero());
            }
        }
        let mut coeffs = coeffs.as_mut_slice();

        // Powers of z
        let mut z: Vec<G::Fr> = Vec::with_capacity(d + 1);
        let mut cur_z: G::Fr = G::Fr::one();
        for _ in 0..(d + 1) {
            z.push(cur_z);
            cur_z *= &point;
        }
        let mut z = z.as_mut_slice();

        // This will be used for transforming the key in each step
        let mut key_proj: Vec<G::Projective> = ck.comm_key.iter().map(|x| (*x).into()).collect();
        let mut key_proj = key_proj.as_mut_slice();

        let mut temp;

        // Key for MSM
        // We initialize this to capacity 0 initially because we want to use the key slice first
        let mut comm_key = &ck.comm_key;

        let mut l_vec = Vec::with_capacity(log_d);
        let mut r_vec = Vec::with_capacity(log_d);

        let mut n = d + 1;
        while n > 1 {
            let (coeffs_l, coeffs_r) = coeffs.split_at_mut(n / 2);
            let (z_l, z_r) = z.split_at_mut(n / 2);
            let (key_l, key_r) = comm_key.split_at(n / 2);
            let (key_proj_l, _) = key_proj.split_at_mut(n / 2);

            let l = Self::cm_commit(key_l, coeffs_r, None, None)
                + &h_prime.mul(Self::inner_product(coeffs_r, z_l));

            let r = Self::cm_commit(key_r, coeffs_l, None, None)
                + &h_prime.mul(Self::inner_product(coeffs_l, z_r));

            let lr = G::Projective::batch_normalization_into_affine(&[l, r]);
            l_vec.push(lr[0]);
            r_vec.push(lr[1]);

            round_challenge = Self::compute_random_oracle_challenge(
                &math::to_bytes![round_challenge, lr[0], lr[1]].unwrap(),
            );
            let round_challenge_inv = round_challenge.inverse().unwrap();

            math::cfg_iter_mut!(coeffs_l)
                .zip(coeffs_r)
                .for_each(|(c_l, c_r)| *c_l += &(round_challenge_inv * (*c_r)));

            math::cfg_iter_mut!(z_l)
                .zip(z_r)
                .for_each(|(z_l, z_r)| *z_l += &(round_challenge * (*z_r)));

            math::cfg_iter_mut!(key_proj_l)
                .zip(key_r)
                .for_each(|(k_l, k_r)| *k_l += &(k_r.mul(round_challenge)));

            coeffs = coeffs_l;
            z = z_l;

            key_proj = key_proj_l;
            temp = G::Projective::batch_normalization_into_affine(key_proj);
            comm_key = &temp;

            n /= 2;
        }

        Ok(Proof {
            l_vec,
            r_vec,
            final_comm_key: comm_key[0],
            c: coeffs[0],
            hiding_comm: hiding_commitment,
            rand: combined_rand,
        })
    }

    pub fn check<'a>(
        vk: &VerifierKey<G>,
        commitments: impl IntoIterator<Item = &'a Commitment<G>>,
        point: G::Fr,
        values: impl IntoIterator<Item = &'a G::Fr>,
        proof: &Proof<G>,
        opening_challenge: G::Fr,
        degree_bound: usize,
    ) -> Result<bool, Error>
    where
        Commitment<G>: 'a,
    {
        let d = vk.supported_degree();

        // `log_d` is ceil(log2 (d + 1)), which is the number of steps to compute all of the challenges

        let log_d = math::log2(d + 1) as usize;

        if proof.l_vec.len() != proof.r_vec.len() || proof.l_vec.len() != log_d {
            return Err(Error::IncorrectInputLength(
                format!(
                    "Expected proof vectors to be {:}. Instead, l_vec size is {:} and r_vec size is {:}, supported_degree is {:}",
                    log_d,
                    proof.l_vec.len(),
                    proof.r_vec.len(),
                    d
                )
            ));
        }

        let check_poly = Self::succinct_check(
            vk,
            commitments,
            point,
            values,
            proof,
            degree_bound,
            opening_challenge,
        );

        if check_poly.is_none() {
            return Ok(false);
        }

        let check_poly_coeffs = check_poly.unwrap().compute_coeffs();
        let final_key = Self::cm_commit(
            vk.comm_key.as_slice(),
            check_poly_coeffs.as_slice(),
            None,
            None,
        );
        if !(final_key - &proof.final_comm_key.into()).is_zero() {
            return Ok(false);
        }

        Ok(true)
    }
}

/// The error type for `PolynomialCommitment`.
#[derive(Debug)]
pub enum Error {
    /// The query set contains a label for a polynomial that was not provided as
    /// input to the `PC::open`.
    MissingPolynomial {
        /// The label of the missing polynomial.
        label: String,
    },

    /// `Evaluations` does not contain an evaluation for the polynomial labelled
    /// `label` at a particular query.
    MissingEvaluation {
        /// The label of the missing polynomial.
        label: String,
    },

    /// The LHS of the equation is empty.
    MissingLHS {
        /// The label of the equation.
        label: String,
    },

    /// The provided polynomial was meant to be hiding, but `rng` was `None`.
    MissingRng,

    /// The degree provided in setup was too small; degree 0 polynomials
    /// are not supported.
    DegreeIsZero,

    /// The degree of the polynomial passed to `commit` or `open`
    /// was too large.
    TooManyCoefficients {
        /// The number of coefficients in the polynomial.
        num_coefficients: usize,
        /// The maximum number of powers provided in `Powers`.
        num_powers: usize,
    },

    /// The hiding bound was not `None`, but the hiding bound was zero.
    HidingBoundIsZero,

    /// The hiding bound was too large for the given `Powers`.
    HidingBoundToolarge {
        /// The hiding bound
        hiding_poly_degree: usize,
        /// The number of powers.
        num_powers: usize,
    },

    /// The degree provided to `trim` was too large.
    TrimmingDegreeTooLarge,

    /// The provided `enforced_degree_bounds` was `Some<&[]>`.
    EmptyDegreeBounds,

    /// The provided equation contained multiple polynomials, of which least one
    /// had a strict degree bound.
    EquationHasDegreeBounds(String),

    /// The required degree bound is not supported by ck/vk
    UnsupportedDegreeBound(usize),

    /// The degree bound for the `index`-th polynomial passed to `commit`, `open`
    /// or `check` was incorrect, that is, `degree_bound >= poly_degree` or
    /// `degree_bound <= max_degree`.
    IncorrectDegreeBound {
        /// Degree of the polynomial.
        poly_degree: usize,
        /// Degree bound.
        degree_bound: usize,
        /// Maximum supported degree.
        supported_degree: usize,
        /// Index of the offending polynomial.
        label: String,
    },

    /// The inputs to `commit`, `open` or `verify` had incorrect lengths.
    IncorrectInputLength(String),

    /// The commitment was generated incorrectly, tampered with, or doesn't support the polynomial.
    MalformedCommitment(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::MissingPolynomial { label } => write!(
                f,
                "`QuerySet` refers to polynomial \"{}\", but it was not provided.",
                label
            ),
            Error::MissingEvaluation { label } => write!(
                f,
                "`QuerySet` refers to polynomial \"{}\", but `Evaluations` does not contain an evaluation for it.",
                label
            ),
            Error::MissingLHS { label } => {
                write!(f, "Equation \"{}\" does not have a LHS.", label)
            },
            Error::MissingRng => write!(f, "hiding commitments require `Some(rng)`"),
            Error::DegreeIsZero => write!(
                f,
                "this scheme does not support committing to degree 0 polynomials"
            ),
            Error::TooManyCoefficients {
                num_coefficients,
                num_powers,
            } => write!(
                f,
                "the number of coefficients in the polynomial ({:?}) is greater than\
                 the maximum number of powers in `Powers` ({:?})",
                num_coefficients, num_powers
            ),
            Error::HidingBoundIsZero => write!(
                f,
                "this scheme does not support non-`None` hiding bounds that are 0"
            ),
            Error::HidingBoundToolarge {
                hiding_poly_degree,
                num_powers,
            } => write!(
                f,
                "the degree of the hiding poly ({:?}) is not less than the maximum number of powers in `Powers` ({:?})",
                hiding_poly_degree, num_powers
            ),
            Error::TrimmingDegreeTooLarge => {
                write!(f, "the degree provided to `trim` was too large")
            }
            Error::EmptyDegreeBounds => {
                write!(f, "provided `enforced_degree_bounds` was `Some<&[]>`")
            }
            Error::EquationHasDegreeBounds(e) => write!(
                f,
                "the eqaution \"{}\" contained degree-bounded polynomials",
                e
            ),
            Error::UnsupportedDegreeBound(bound) => write!(
                f,
                "the degree bound ({:?}) is not supported by the parameters",
                bound,
            ),
            Error::IncorrectDegreeBound {
                poly_degree,
                degree_bound,
                supported_degree,
                label,
            } => write!(
                f,
                "the degree bound ({:?}) for the polynomial {} \
                 (having degree {:?}) is greater than the maximum \
                 supported degree ({:?})",
                degree_bound, label, poly_degree, supported_degree
            ),
            Error::IncorrectInputLength(err) => write!(f, "{}", err),
            Error::MalformedCommitment(err) => write!(f, "{}", err)
        }
    }
}

impl math::Error for Error {}
