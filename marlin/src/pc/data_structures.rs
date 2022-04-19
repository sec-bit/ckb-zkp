use ark_ec::PairingEngine;
use ark_ff::{Field, ToBytes, Zero};
use ark_poly::{polynomial::univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_serialize::*;
use ark_std::io;
use core::ops::AddAssign;
use rand::RngCore;

use crate::{BTreeMap, BTreeSet, Cow, String, Vec};

#[derive(Debug)]
pub enum Error {
    MissingPolynomial { label: String },
    MissingEvaluation { label: String },
    DegreeIsZero,
    DegreeOutOfBound,
    HidingBoundIsZero,
    HidingBoundTooLarge,
    MissingRng,
    TrimmingDegreeTooLarge,
    Unclassified,
}

#[derive(Clone, Debug)]
pub struct UniversalParams<E: PairingEngine> {
    // `{ \beta^i G }`, where `i` ranges from `0` to `degree`
    pub powers_of_g: Vec<E::G1Affine>,
    // `{ \beta^i \gamma G }`, where `i` ranges from `0` to `degree`
    pub powers_of_gamma_g: Vec<E::G1Affine>,
    pub h: E::G2Affine,
    pub beta_h: E::G2Affine,
    // for paring
    pub prepared_h: E::G2Prepared,
    pub prepared_beta_h: E::G2Prepared,
}

impl<E: PairingEngine> UniversalParams<E> {
    pub fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }
}

#[derive(Clone, Debug)]
pub struct Powers<'a, E: PairingEngine> {
    pub powers_of_g: Cow<'a, [E::G1Affine]>,
    pub powers_of_gamma_g: Cow<'a, [E::G1Affine]>,
}

impl<'a, E: PairingEngine> Powers<'a, E> {
    pub fn size(&self) -> usize {
        self.powers_of_g.len()
    }

    pub fn supported_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitterKey<E: PairingEngine> {
    pub powers_of_g: Vec<E::G1Affine>,
    pub powers_of_gamma_g: Vec<E::G1Affine>,

    pub supported_degree: usize,
}

impl<E: PairingEngine> ToBytes for CommitterKey<E> {
    #[inline]
    fn write<W: io::Write>(&self, mut w: W) -> io::Result<()> {
        self.powers_of_g.write(&mut w)?;
        self.powers_of_gamma_g.write(&mut w)?;
        (self.supported_degree as u64).write(&mut w)
    }
}

impl<E: PairingEngine> CommitterKey<E> {
    pub fn supported_degree(&self) -> usize {
        self.supported_degree
    }

    pub fn powers(&self) -> Powers<'_, E> {
        Powers {
            powers_of_g: self.powers_of_g.as_slice().into(),
            powers_of_gamma_g: self.powers_of_gamma_g.as_slice().into(),
        }
    }

    pub fn shifted_powers(&self, degree_bound: usize) -> Option<Powers<'_, E>> {
        if degree_bound > self.supported_degree {
            return None;
        }
        let power_range = (self.supported_degree - degree_bound)..;

        let powers = Powers {
            powers_of_g: (self.powers_of_g[power_range]).into(),
            powers_of_gamma_g: self.powers_of_gamma_g.as_slice().into(),
        };
        Some(powers)
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierKey<E: PairingEngine> {
    pub g: E::G1Affine,
    pub gamma_g: E::G1Affine,
    pub h: E::G2Affine,
    pub beta_h: E::G2Affine,
    pub supported_degree: usize,
}

impl<E: PairingEngine> ToBytes for VerifierKey<E> {
    fn write<W: io::Write>(&self, mut w: W) -> io::Result<()> {
        self.g.write(&mut w)?;
        self.gamma_g.write(&mut w)?;
        self.h.write(&mut w)?;
        self.beta_h.write(&mut w)?;
        (self.supported_degree as u64).write(&mut w)
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Comm<E: PairingEngine>(pub E::G1Affine);

impl<E: PairingEngine> Comm<E> {
    pub fn empty() -> Self {
        Comm(E::G1Affine::zero())
    }
}

impl<E: PairingEngine> ToBytes for Comm<E> {
    #[inline]
    fn write<W: io::Write>(&self, mut w: W) -> io::Result<()> {
        self.0.write(&mut w)
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment<E: PairingEngine> {
    pub comm: Comm<E>,
    pub shifted_comm: Option<Comm<E>>,
}

impl<E: PairingEngine> ToBytes for Commitment<E> {
    #[inline]
    fn write<W: io::Write>(&self, mut w: W) -> io::Result<()> {
        self.comm.write(&mut w)?;
        let shifted_exists = self.shifted_comm.is_some();
        shifted_exists.write(&mut w)?;
        self.shifted_comm
            .as_ref()
            .unwrap_or(&Comm::empty())
            .write(&mut w)
    }
}

#[derive(Clone, Debug)]
pub struct Rand<F: Field> {
    pub blinding_polynomial: DensePolynomial<F>,
}

impl<F: Field> ToBytes for Rand<F> {
    #[inline]
    fn write<W: io::Write>(&self, mut w: W) -> io::Result<()> {
        self.blinding_polynomial.serialize(&mut w).unwrap();
        Ok(())
    }
}

impl<F: Field> Rand<F> {
    pub fn empty() -> Self {
        Self {
            blinding_polynomial: DensePolynomial::zero(),
        }
    }

    pub fn rand<R: RngCore>(hiding_bound: usize, rng: &mut R) -> Self {
        let mut randomness = Self::empty();
        randomness.blinding_polynomial = DensePolynomial::rand(hiding_bound, rng);
        randomness
    }

    pub fn is_hiding(&self) -> bool {
        !self.blinding_polynomial.is_zero()
    }
}

impl<'a, F: Field> AddAssign<&'a Rand<F>> for Rand<F> {
    fn add_assign(&mut self, other: &'a Self) {
        self.blinding_polynomial += &other.blinding_polynomial;
    }
}

impl<'a, F: Field> AddAssign<(F, &'a Rand<F>)> for Rand<F> {
    fn add_assign(&mut self, (f, other): (F, &'a Rand<F>)) {
        self.blinding_polynomial += (f, &other.blinding_polynomial);
    }
}

#[derive(Clone, Debug)]
pub struct Randomness<F: Field> {
    pub rand: Rand<F>,
    pub shifted_rand: Option<Rand<F>>,
}

impl<F: Field> ToBytes for Randomness<F> {
    #[inline]
    fn write<W: io::Write>(&self, mut w: W) -> io::Result<()> {
        self.rand.write(&mut w)?;
        let shifted_exists = self.shifted_rand.is_some();
        shifted_exists.write(&mut w)?;
        self.shifted_rand
            .as_ref()
            .unwrap_or(&Rand::empty())
            .write(&mut w)
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct LabeledPolynomial<'a, F: Field> {
    label: String,
    polynomial: Cow<'a, DensePolynomial<F>>,
    degree_bound: Option<usize>,
    hiding_bound: Option<usize>,
}

impl<'a, F: Field> LabeledPolynomial<'a, F> {
    pub fn new_owned(
        label: String,
        polynomial: DensePolynomial<F>,
        degree_bound: Option<usize>,
        hiding_bound: Option<usize>,
    ) -> Self {
        Self {
            label,
            polynomial: Cow::Owned(polynomial),
            degree_bound,
            hiding_bound,
        }
    }
    pub fn label(&self) -> &String {
        &self.label
    }

    pub fn polynomial(&self) -> &DensePolynomial<F> {
        &self.polynomial
    }

    pub fn evaluate(&self, point: F) -> F {
        self.polynomial.evaluate(&point)
    }

    pub fn degree_bound(&self) -> Option<usize> {
        self.degree_bound
    }

    pub fn is_hiding(&self) -> bool {
        self.hiding_bound.is_some()
    }

    pub fn hiding_bound(&self) -> Option<usize> {
        self.hiding_bound
    }
}

#[derive(Clone, Debug)]
pub struct LabeledCommitment<E: PairingEngine> {
    label: String,
    commitment: Commitment<E>,
    degree_bound: Option<usize>,
}

impl<E: PairingEngine> LabeledCommitment<E> {
    pub fn new(label: String, commitment: Commitment<E>, degree_bound: Option<usize>) -> Self {
        Self {
            label,
            commitment,
            degree_bound,
        }
    }
    pub fn label(&self) -> &String {
        &self.label
    }

    pub fn commitment(&self) -> &Commitment<E> {
        &self.commitment
    }

    pub fn degree_bound(&self) -> Option<usize> {
        self.degree_bound
    }
}

impl<E: PairingEngine> ToBytes for LabeledCommitment<E> {
    #[inline]
    fn write<W: io::Write>(&self, writer: W) -> io::Result<()> {
        self.commitment.write(writer)
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: PairingEngine> {
    pub w: E::G1Affine,
    pub rand_v: Option<E::Fr>,
}

pub type QuerySet<F> = BTreeSet<(String, F)>;

pub type Evaluations<F> = BTreeMap<(String, F), F>;
