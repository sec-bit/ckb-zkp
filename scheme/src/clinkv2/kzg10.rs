//! Here we construct a polynomial commitment that enables users to commit to a
//! single polynomial `p`, and then later provide an evaluation proof that
//! convinces verifiers that a claimed value `v` is the true evaluation of `p`
//! at a chosen point `x`. Our construction follows the template of the construction
//! proposed by Kate, Zaverucha, and Goldberg ([KZG11](http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf)).
//! This construction achieves extractability in the algebraic group model (AGM).

use math::{
    fft::DensePolynomial as Polynomial,
    io::Result as IoResult,
    msm::{FixedBaseMSM, VariableBaseMSM},
    serialize::*,
    AffineCurve, Field, FromBytes, Group, One, PairingEngine, PrimeField, ProjectiveCurve, ToBytes,
    UniformRand, Zero,
};

use rand::Rng;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use core::marker::PhantomData;
use core::ops::{Add, AddAssign};

use crate::*;

/// `UniversalParams` are the universal parameters for the KZG10 scheme.
#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Debug(bound = ""))]
pub struct UniversalParams<E: PairingEngine> {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to `degree`.
    pub powers_of_g: Vec<E::G1Affine>,
    /// Group elements of the form `{ \beta^i \gamma G }`, where `i` ranges from 0 to `degree`.
    pub powers_of_gamma_g: Vec<E::G1Affine>,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
    /// Group elements of the form `{ \beta^i G2 }`, where `i` ranges from `0` to `-degree`.
    pub prepared_neg_powers_of_h: Option<Vec<E::G2Prepared>>,
    /// The generator of G2, prepared for use in pairings.
    #[derivative(Debug = "ignore")]
    pub prepared_h: E::G2Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    #[derivative(Debug = "ignore")]
    pub prepared_beta_h: E::G2Prepared,
}

impl<E: PairingEngine> UniversalParams<E> {
    fn _max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }
}

/// `Powers` is used to commit to and create evaluation proofs for a given
/// polynomial.
#[derive(Derivative)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Debug(bound = "")
)]
pub struct Powers<'a, E: PairingEngine> {
    /// Group elements of the form `β^i G`, for different values of `i`.
    pub powers_of_g: Cow<'a, [E::G1Affine]>,
    /// Group elements of the form `β^i γG`, for different values of `i`.
    pub powers_of_gamma_g: Cow<'a, [E::G1Affine]>,
}

impl<E: PairingEngine> Powers<'_, E> {
    /// The number of powers in `self`.
    pub fn size(&self) -> usize {
        self.powers_of_g.len()
    }
}

/// `VerifierKey` is used to check evaluation proofs for a given commitment.
#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Debug(bound = ""))]
pub struct VerifierKey<E: PairingEngine> {
    /// The generator of G1.
    pub g: E::G1Affine,
    /// The generator of G1 that is used for making a commitment hiding.
    pub gamma_g: E::G1Affine,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
    /// The generator of G2, prepared for use in pairings.
    #[derivative(Debug = "ignore")]
    pub prepared_h: E::G2Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    #[derivative(Debug = "ignore")]
    pub prepared_beta_h: E::G2Prepared,
}

impl<E: PairingEngine> PartialEq for VerifierKey<E> {
    fn eq(&self, other: &Self) -> bool {
        self.g == other.g
            && self.gamma_g == other.gamma_g
            && self.h == other.h
            && self.beta_h == other.beta_h
    }
}
impl<E: PairingEngine> Eq for VerifierKey<E> {}

impl<E: PairingEngine> ToBytes for VerifierKey<E> {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.g.write(&mut writer)?;
        self.gamma_g.write(&mut writer)?;
        self.h.write(&mut writer)?;
        self.beta_h.write(&mut writer)?;
        self.prepared_h.write(&mut writer)?;
        self.prepared_beta_h.write(&mut writer)
    }
}

impl<E: PairingEngine> FromBytes for VerifierKey<E> {
    #[inline]
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let g = E::G1Affine::read(&mut reader)?;
        let gamma_g = E::G1Affine::read(&mut reader)?;
        let h = E::G2Affine::read(&mut reader)?;
        let beta_h = E::G2Affine::read(&mut reader)?;
        let prepared_h = E::G2Prepared::read(&mut reader)?;
        let prepared_beta_h = E::G2Prepared::read(&mut reader)?;

        Ok(Self {
            g,
            gamma_g,
            h,
            beta_h,
            prepared_h,
            prepared_beta_h,
        })
    }
}

/// `Commitment` commits to a polynomial. It is output by `KZG10::commit`.
#[derive(Derivative)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct Commitment<E: PairingEngine>(
    /// The commitment is a group element.
    pub E::G1Affine,
);

impl<E: PairingEngine> ToBytes for Commitment<E> {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.0.write(&mut writer)
    }
}

impl<E: PairingEngine> FromBytes for Commitment<E> {
    #[inline]
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let g = E::G1Affine::read(&mut reader)?;
        Ok(Self(g))
    }
}

impl<E: PairingEngine> Commitment<E> {
    #[inline]
    fn _empty() -> Self {
        Commitment(E::G1Affine::zero())
    }

    fn _has_degree_bound(&self) -> bool {
        false
    }

    fn _size_in_bytes(&self) -> usize {
        math::to_bytes![E::G1Affine::zero()].unwrap().len() / 2
    }
}

impl<'a, E: PairingEngine> AddAssign<(E::Fr, &'a Commitment<E>)> for Commitment<E> {
    #[inline]
    fn add_assign(&mut self, (f, other): (E::Fr, &'a Commitment<E>)) {
        let mut other = other.0.mul(f.into_repr());
        other.add_assign_mixed(&self.0);
        self.0 = other.into();
    }
}

/// `Randomness` hides the polynomial inside a commitment. It is output by `KZG10::commit`.
#[derive(Derivative)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct Randomness<E: PairingEngine> {
    /// For KZG10, the commitment randomness is a random polynomial.
    pub blinding_polynomial: Polynomial<E::Fr>,
}

impl<E: PairingEngine> Randomness<E> {
    /// Does `self` provide any hiding properties to the corresponding commitment?
    /// `self.is_hiding() == true` only if the underlying polynomial is non-zero.
    #[inline]
    pub fn is_hiding(&self) -> bool {
        !self.blinding_polynomial.is_zero()
    }

    /// What is the degree of the hiding polynomial for a given hiding bound?
    #[inline]
    pub fn calculate_hiding_polynomial_degree(hiding_bound: usize) -> usize {
        hiding_bound + 1
    }

    fn empty() -> Self {
        Self {
            blinding_polynomial: Polynomial::zero(),
        }
    }

    fn rand<R: Rng>(hiding_bound: usize, _: bool, rng: &mut R) -> Self {
        let mut randomness = Randomness::empty();
        let hiding_poly_degree = Self::calculate_hiding_polynomial_degree(hiding_bound);
        randomness.blinding_polynomial = Polynomial::rand(hiding_poly_degree, rng);
        randomness
    }
}

impl<'a, E: PairingEngine> Add<&'a Randomness<E>> for Randomness<E> {
    type Output = Self;

    #[inline]
    fn add(mut self, other: &'a Self) -> Self {
        self.blinding_polynomial += &other.blinding_polynomial;
        self
    }
}

impl<'a, E: PairingEngine> Add<(E::Fr, &'a Randomness<E>)> for Randomness<E> {
    type Output = Self;

    #[inline]
    fn add(mut self, other: (E::Fr, &'a Randomness<E>)) -> Self {
        self += other;
        self
    }
}

impl<'a, E: PairingEngine> AddAssign<&'a Randomness<E>> for Randomness<E> {
    #[inline]
    fn add_assign(&mut self, other: &'a Self) {
        self.blinding_polynomial += &other.blinding_polynomial;
    }
}

impl<'a, E: PairingEngine> AddAssign<(E::Fr, &'a Randomness<E>)> for Randomness<E> {
    #[inline]
    fn add_assign(&mut self, (f, other): (E::Fr, &'a Randomness<E>)) {
        self.blinding_polynomial += (f, &other.blinding_polynomial);
    }
}

/// `Proof` is an evaluation proof that is output by `KZG10::open`.
#[derive(Derivative)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct Proof<E: PairingEngine> {
    /// This is a commitment to the witness polynomial; see [KZG10] for more details.
    pub w: E::G1Affine,
    /// This is the evaluation of the random polynomial at the point for which
    /// the evaluation proof was produced.
    pub random_v: Option<E::Fr>,
}

impl<E: PairingEngine> Proof<E> {
    fn _size_in_bytes(&self) -> usize {
        let hiding_size = if self.random_v.is_some() {
            math::to_bytes![E::Fr::zero()].unwrap().len()
        } else {
            0
        };
        math::to_bytes![E::G1Affine::zero()].unwrap().len() / 2 + hiding_size
    }
}

impl<E: PairingEngine> ToBytes for Proof<E> {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.w.write(&mut writer)?;
        let v_exists = self.random_v.is_some();
        v_exists.write(&mut writer)?;
        self.random_v
            .as_ref()
            .unwrap_or(&E::Fr::zero())
            .write(&mut writer)
    }
}

impl<E: PairingEngine> FromBytes for Proof<E> {
    #[inline]
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let w = E::G1Affine::read(&mut reader)?;
        let v_exists = bool::read(&mut reader)?;
        let random_value = E::Fr::read(&mut reader)?;
        let random_v = if v_exists { Some(random_value) } else { None };

        Ok(Self { w, random_v })
    }
}

/// `KZG10` is an implementation of the polynomial commitment scheme of
/// [Kate, Zaverucha and Goldbgerg][kzg10]
///
/// [kzg10]: http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf
pub struct KZG10<E: PairingEngine> {
    _engine: PhantomData<E>,
}

impl<E: PairingEngine> KZG10<E> {
    /// Constructs public parameters when given as input the maximum degree `degree`
    /// for the polynomial commitment scheme.
    pub fn setup<R: Rng>(
        max_degree: usize,
        produce_g2_powers: bool,
        rng: &mut R,
    ) -> Result<UniversalParams<E>, Error> {
        if max_degree < 1 {
            return Err(Error::DegreeIsZero);
        }
        //let setup_time = start_timer!(|| format!("KZG10::Setup with degree {}", max_degree));
        let beta = E::Fr::rand(rng);
        let g = E::G1Projective::rand(rng);
        let gamma_g = E::G1Projective::rand(rng);
        let h = E::G2Projective::rand(rng);

        let mut powers_of_beta = vec![E::Fr::one()];

        let mut cur = beta;
        for _ in 0..max_degree {
            powers_of_beta.push(cur);
            cur *= &beta;
        }

        let window_size = FixedBaseMSM::get_mul_window_size(max_degree + 1);

        let scalar_bits = E::Fr::size_in_bits();
        //let g_time = start_timer!(|| "Generating powers of G");
        let g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, g);
        let powers_of_g = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(
            scalar_bits,
            window_size,
            &g_table,
            &powers_of_beta,
        );
        //end_timer!(g_time);
        //let gamma_g_time = start_timer!(|| "Generating powers of gamma * G");
        let gamma_g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, gamma_g);
        let mut powers_of_gamma_g = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(
            scalar_bits,
            window_size,
            &gamma_g_table,
            &powers_of_beta,
        );
        // Add an additional power of gamma_g, because we want to be able to support
        // up to D queries.
        powers_of_gamma_g.push(powers_of_gamma_g.last().unwrap().mul(&beta));
        //end_timer!(gamma_g_time);

        let powers_of_g = E::G1Projective::batch_normalization_into_affine(&powers_of_g);
        let powers_of_gamma_g =
            E::G1Projective::batch_normalization_into_affine(&powers_of_gamma_g);

        // let prepared_neg_powers_of_h_time =
        //     start_timer!(|| "Generating negative powers of h in G2");
        let prepared_neg_powers_of_h = if produce_g2_powers {
            let mut neg_powers_of_beta = vec![E::Fr::one()];
            let mut cur = E::Fr::one() / &beta;
            for _ in 0..max_degree {
                neg_powers_of_beta.push(cur);
                cur /= &beta;
            }

            let neg_h_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, h);
            let neg_powers_of_h = FixedBaseMSM::multi_scalar_mul::<E::G2Projective>(
                scalar_bits,
                window_size,
                &neg_h_table,
                &neg_powers_of_beta,
            );

            let affines = E::G2Projective::batch_normalization_into_affine(&neg_powers_of_h);
            Some(affines.into_iter().map(|a| a.into()).collect())
        } else {
            None
        };

        //end_timer!(prepared_neg_powers_of_h_time);

        let beta_h = h.mul(beta).into_affine();
        let h = h.into_affine();
        let prepared_h = h.into();
        let prepared_beta_h = beta_h.into();

        let pp = UniversalParams {
            powers_of_g,
            powers_of_gamma_g,
            h,
            beta_h,
            prepared_neg_powers_of_h,
            prepared_h,
            prepared_beta_h,
        };
        //end_timer!(setup_time);
        Ok(pp)
    }

    pub fn trim(
        pp: &UniversalParams<E>,
        mut supported_degree: usize,
    ) -> Result<(Powers<E>, VerifierKey<E>), Error> {
        if supported_degree == 1 {
            supported_degree += 1;
        }
        let powers_of_g = pp.powers_of_g[..=supported_degree].to_vec();
        let powers_of_gamma_g = pp.powers_of_gamma_g[..=supported_degree].to_vec();

        let powers = Powers {
            powers_of_g: Cow::Owned(powers_of_g),
            powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
        };
        let vk = VerifierKey {
            g: pp.powers_of_g[0],
            gamma_g: pp.powers_of_gamma_g[0],
            h: pp.h,
            beta_h: pp.beta_h,
            prepared_h: pp.prepared_h.clone(),
            prepared_beta_h: pp.prepared_beta_h.clone(),
        };
        Ok((powers, vk))
    }

    /// Outputs a commitment to `polynomial`.
    pub fn commit<R: Rng>(
        powers: &Powers<E>,
        polynomial: &Polynomial<E::Fr>,
        hiding_bound: Option<usize>,
        rng: Option<&mut R>,
    ) -> Result<(Commitment<E>, Randomness<E>), Error> {
        Self::check_degree_is_within_bounds(polynomial.degree(), powers.size())?;

        // let commit_time = start_timer!(|| format!(
        //     "Committing to polynomial of degree {} with hiding_bound: {:?}",
        //     polynomial.degree(),
        //     hiding_bound,
        // ));

        let (num_leading_zeros, plain_coeffs) =
            skip_leading_zeros_and_convert_to_bigints(&polynomial);

        //let msm_time = start_timer!(|| "MSM to compute commitment to plaintext poly");
        let mut commitment = VariableBaseMSM::multi_scalar_mul(
            &powers.powers_of_g[num_leading_zeros..],
            &plain_coeffs,
        );
        //end_timer!(msm_time);

        let mut randomness = Randomness::empty();
        if let Some(hiding_degree) = hiding_bound {
            let mut rng = rng.ok_or(Error::MissingRng)?;
            // let sample_random_poly_time = start_timer!(|| format!(
            //     "Sampling a random polynomial of degree {}",
            //     hiding_degree
            // ));

            randomness = Randomness::rand(hiding_degree, false, &mut rng);
            Self::check_hiding_bound(
                randomness.blinding_polynomial.degree(),
                powers.powers_of_gamma_g.len(),
            )?;
            //end_timer!(sample_random_poly_time);
        }

        let random_ints = convert_to_bigints(&randomness.blinding_polynomial.coeffs);
        //let msm_time = start_timer!(|| "MSM to compute commitment to random poly");
        let random_commitment =
            VariableBaseMSM::multi_scalar_mul(&powers.powers_of_gamma_g, random_ints.as_slice())
                .into_affine();
        //end_timer!(msm_time);

        commitment.add_assign_mixed(&random_commitment);

        //end_timer!(commit_time);
        Ok((Commitment(commitment.into()), randomness))
    }

    /// Compute witness polynomial.
    ///
    /// The witness polynomial w(x) the quotient of the division (p(x) - p(z)) / (x - z)
    /// Observe that this quotient does not change with z because
    /// p(z) is the remainder term. We can therefore omit p(z) when computing the quotient.
    pub fn compute_witness_polynomial(
        p: &Polynomial<E::Fr>,
        point: E::Fr,
        randomness: &Randomness<E>,
    ) -> Result<(Polynomial<E::Fr>, Option<Polynomial<E::Fr>>), Error> {
        let divisor = Polynomial::from_coefficients_vec(vec![-point, E::Fr::one()]);

        //let witness_time = start_timer!(|| "Computing witness polynomial");
        let witness_polynomial = p / &divisor;
        //end_timer!(witness_time);

        let random_witness_polynomial = if randomness.is_hiding() {
            let random_p = &randomness.blinding_polynomial;

            //let witness_time = start_timer!(|| "Computing random witness polynomial");
            let random_witness_polynomial = random_p / &divisor;
            //end_timer!(witness_time);
            Some(random_witness_polynomial)
        } else {
            None
        };

        Ok((witness_polynomial, random_witness_polynomial))
    }

    pub(crate) fn open_with_witness_polynomial<'a>(
        powers: &Powers<E>,
        point: E::Fr,
        randomness: &Randomness<E>,
        witness_polynomial: &Polynomial<E::Fr>,
        hiding_witness_polynomial: Option<&Polynomial<E::Fr>>,
    ) -> Result<Proof<E>, Error> {
        Self::check_degree_is_too_large(witness_polynomial.degree(), powers.size())?;
        let (num_leading_zeros, witness_coeffs) =
            skip_leading_zeros_and_convert_to_bigints(&witness_polynomial);

        //let witness_comm_time = start_timer!(|| "Computing commitment to witness polynomial");
        let mut w = VariableBaseMSM::multi_scalar_mul(
            &powers.powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        );
        //end_timer!(witness_comm_time);

        let random_v = if let Some(hiding_witness_polynomial) = hiding_witness_polynomial {
            let blinding_p = &randomness.blinding_polynomial;
            //let blinding_eval_time = start_timer!(|| "Evaluating random polynomial");
            let blinding_evaluation = blinding_p.evaluate(point);
            //end_timer!(blinding_eval_time);

            let random_witness_coeffs = convert_to_bigints(&hiding_witness_polynomial.coeffs);
            // let witness_comm_time =
            //     start_timer!(|| "Computing commitment to random witness polynomial");
            w += &VariableBaseMSM::multi_scalar_mul(
                &powers.powers_of_gamma_g,
                &random_witness_coeffs,
            );
            //end_timer!(witness_comm_time);
            Some(blinding_evaluation)
        } else {
            None
        };

        Ok(Proof {
            w: w.into_affine(),
            random_v,
        })
    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the same.
    // pub(crate) fn open<'a>(
    pub fn open<'a>(
        powers: &Powers<E>,
        p: &Polynomial<E::Fr>,
        point: E::Fr,
        rand: &Randomness<E>,
    ) -> Result<Proof<E>, Error> {
        Self::check_degree_is_within_bounds(p.degree(), powers.size())?;
        //let open_time = start_timer!(|| format!("Opening polynomial of degree {}", p.degree()));

        //let witness_time = start_timer!(|| "Computing witness polynomials");
        let (witness_poly, hiding_witness_poly) = Self::compute_witness_polynomial(p, point, rand)?;
        //end_timer!(witness_time);

        let proof = Self::open_with_witness_polynomial(
            powers,
            point,
            rand,
            &witness_poly,
            hiding_witness_poly.as_ref(),
        );

        //end_timer!(open_time);
        proof
    }

    pub fn batch_open<'a>(
        powers: &Powers<E>,
        polynomials: &[Polynomial<E::Fr>],
        point: E::Fr,
        opening_challenge: E::Fr,
        rands: &Vec<Randomness<E>>,
    ) -> Result<Proof<E>, Error> {
        let mut p = Polynomial::zero();
        let mut r = Randomness::empty();
        // let mut shifted_w = Polynomial::zero();
        // let mut shifted_r = Randomness::empty();
        // let mut shifted_r_witness = Polynomial::zero();

        let mut challenge_j = E::Fr::one();

        for (polynomial, rand) in polynomials.into_iter().zip(rands) {
            Self::check_degree_is_within_bounds(polynomial.degree(), powers.size())?;
            // compute challenge^j and challenge^{j+1}.
            //let challenge_j = opening_challenge.pow([2 * j as u64]);
            p += (challenge_j, polynomial);
            r += (challenge_j, rand);

            challenge_j *= &opening_challenge.square();
        }

        //let proof_time = start_timer!(|| "Creating proof for unshifted polynomials");
        let proof = Self::open(powers, &p, point, &r)?;
        let w = proof.w.into_projective();
        let random_v = proof.random_v;
        //end_timer!(proof_time);

        Ok(Proof {
            w: w.into_affine(),
            random_v,
        })
    }

    /// Verifies that `value` is the evaluation at `point` of the polynomial
    /// committed inside `comm`.
    pub fn check(
        vk: &VerifierKey<E>,
        comm: &Commitment<E>,
        point: E::Fr,
        value: E::Fr,
        proof: &Proof<E>,
    ) -> Result<bool, Error> {
        //let check_time = start_timer!(|| "Checking evaluation");
        let mut inner = comm.0.into_projective() - &vk.g.into_projective().mul(value);
        if let Some(random_v) = proof.random_v {
            inner -= &vk.gamma_g.mul(random_v);
        }
        let lhs = E::pairing(inner, vk.h);

        let inner = vk.beta_h.into_projective() - &vk.h.mul(point);
        let rhs = E::pairing(proof.w, inner);

        //end_timer!(check_time, || format!("Result: {}", lhs == rhs));
        Ok(lhs == rhs)
    }

    fn accumulate_commitments_and_values<'a>(
        _vk: &VerifierKey<E>,
        commitments: &[Commitment<E>],
        values: &[E::Fr],
        opening_challenge: E::Fr,
    ) -> Result<(E::G1Projective, E::Fr), Error> {
        //let acc_time = start_timer!(|| "Accumulating commitments and values");
        let mut combined_comm = E::G1Projective::zero();
        let mut combined_value = E::Fr::zero();
        let mut challenge_i = E::Fr::one();
        for (commitment, value) in commitments.into_iter().zip(values) {
            combined_comm += &commitment.0.mul(challenge_i);
            combined_value += &(*value * &challenge_i);
            challenge_i *= &opening_challenge.square();
        }

        //end_timer!(acc_time);
        Ok((combined_comm, combined_value))
    }

    pub fn batch_check<'a>(
        vk: &VerifierKey<E>,
        commitments: &[Commitment<E>],
        point: E::Fr,
        values: &[E::Fr],
        proof: &Proof<E>,
        opening_challenge: E::Fr,
    ) -> Result<bool, Error> {
        //let check_time = start_timer!(|| "Checking evaluations");
        let (combined_comm, combined_value) =
            Self::accumulate_commitments_and_values(vk, commitments, values, opening_challenge)?;
        let combined_comm = Commitment(combined_comm.into());
        let result = Self::check(vk, &combined_comm, point, combined_value, proof)?;
        //end_timer!(check_time);
        Ok(result)
    }

    /// Check that each `proof_i` in `proofs` is a valid proof of evaluation for
    /// `commitment_i` at `point_i`.
    pub fn batch_check_to_mul_values<R: Rng>(
        vk: &VerifierKey<E>,
        commitments: &[Commitment<E>],
        points: &[E::Fr],
        values: &[E::Fr],
        proofs: &[Proof<E>],
        rng: &mut R,
    ) -> Result<bool, Error> {
        // let check_time =
        //     start_timer!(|| format!("Checking {} evaluation proofs", commitments.len()));
        let g = vk.g.into_projective();
        let gamma_g = vk.gamma_g.into_projective();

        let mut total_c = <E::G1Projective>::zero();
        let mut total_w = <E::G1Projective>::zero();

        //let combination_time = start_timer!(|| "Combining commitments and proofs");
        let mut randomizer = E::Fr::one();
        // Instead of multiplying g and gamma_g in each turn, we simply accumulate
        // their coefficients and perform a final multiplication at the end.
        let mut g_multiplier = E::Fr::zero();
        let mut gamma_g_multiplier = E::Fr::zero();
        for (((c, z), v), proof) in commitments.iter().zip(points).zip(values).zip(proofs) {
            let w = proof.w;
            let mut temp = w.mul(*z);
            temp.add_assign_mixed(&c.0);
            let c = temp;
            g_multiplier += &(randomizer * &v);
            if let Some(random_v) = proof.random_v {
                gamma_g_multiplier += &(randomizer * &random_v);
            }
            total_c += &c.mul(randomizer);
            total_w += &w.mul(randomizer);
            // We don't need to sample randomizers from the full field,
            // only from 128-bit strings.
            randomizer = u128::rand(rng).into();
        }
        total_c -= &g.mul(g_multiplier);
        total_c -= &gamma_g.mul(gamma_g_multiplier);
        //end_timer!(combination_time);

        //let to_affine_time = start_timer!(|| "Converting results to affine for pairing");
        let affine_points = E::G1Projective::batch_normalization_into_affine(&[-total_w, total_c]);
        let (total_w, total_c) = (affine_points[0], affine_points[1]);
        //end_timer!(to_affine_time);

        //let pairing_time = start_timer!(|| "Performing product of pairings");
        let result = E::product_of_pairings(&[
            (total_w.into(), vk.prepared_beta_h.clone()),
            (total_c.into(), vk.prepared_h.clone()),
        ])
        .is_one();
        //end_timer!(pairing_time);
        //end_timer!(check_time, || format!("Result: {}", result));
        Ok(result)
    }

    // Functions for checking errors
    pub(crate) fn check_degree_is_within_bounds(
        num_coefficients: usize,
        num_powers: usize,
    ) -> Result<(), Error> {
        if num_coefficients < 1 {
            Err(Error::DegreeIsZero)
        } else {
            Self::check_degree_is_too_large(num_coefficients, num_powers)
        }
    }

    pub(crate) fn check_degree_is_too_large(
        num_coefficients: usize,
        num_powers: usize,
    ) -> Result<(), Error> {
        if num_coefficients > num_powers {
            Err(Error::TooManyCoefficients {
                num_coefficients,
                num_powers,
            })
        } else {
            Ok(())
        }
    }

    pub(crate) fn check_hiding_bound(
        hiding_poly_degree: usize,
        num_powers: usize,
    ) -> Result<(), Error> {
        if hiding_poly_degree == 0 {
            Err(Error::HidingBoundIsZero)
        } else if hiding_poly_degree >= num_powers {
            // The above check uses `>=` because committing to a hiding poly with
            // degree `hiding_poly_degree` requires `hiding_poly_degree + 1`
            // powers.
            Err(Error::HidingBoundToolarge {
                hiding_poly_degree,
                num_powers,
            })
        } else {
            Ok(())
        }
    }
}

fn skip_leading_zeros_and_convert_to_bigints<F: PrimeField>(
    p: &Polynomial<F>,
) -> (usize, Vec<F::BigInt>) {
    let mut num_leading_zeros = 0;
    while p.coeffs[num_leading_zeros].is_zero() && num_leading_zeros < p.coeffs.len() {
        num_leading_zeros += 1;
    }
    let coeffs = convert_to_bigints(&p.coeffs[num_leading_zeros..]);
    (num_leading_zeros, coeffs)
}

fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    //let to_bigint_time = start_timer!(|| "Converting polynomial coeffs to bigints");
    let coeffs = math::cfg_iter!(p)
        .map(|s| s.into_repr())
        .collect::<Vec<_>>();
    //end_timer!(to_bigint_time);
    coeffs
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
