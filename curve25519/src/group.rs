use ark_ff::{FromBytes, PrimeField, ToBytes, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use zeroize::Zeroize;
use zkp_curve::{AffineCurve, Curve, ProjectiveCurve};

use crate::Vec;

use super::Fr;

#[derive(Clone)]
pub struct Curve25519;

impl Curve for Curve25519 {
    type Fq = Fr;
    type Fr = Fr;
    type Affine = Curve25519Point;
    type Projective = Curve25519Point;

    fn vartime_multiscalar_mul(s: &[Self::Fr], p: &[Self::Affine]) -> Self::Projective {
        let size = core::cmp::min(s.len(), p.len());
        let ss = &s[0..size];
        let pp = &p[0..size];

        let scalars: Vec<Scalar> = ss
            .iter()
            .map(|s| {
                let mut bytes = [0u8; 32];
                let mut vec = Vec::new();
                let _ = s.write(&mut vec);
                bytes.copy_from_slice(&vec[..]);
                Scalar::from_bytes_mod_order(bytes)
            })
            .collect();
        let points: Vec<RistrettoPoint> = pp.iter().map(|p| p.0).collect();
        let point = RistrettoPoint::vartime_multiscalar_mul(scalars, points);
        Curve25519Point(point)
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Default, Debug)]
pub struct Curve25519Point(pub RistrettoPoint);

impl AffineCurve for Curve25519Point {
    type ScalarField = Fr;
    type BaseField = Fr;
    type Projective = Curve25519Point;
    // not use in curve25519
    const COFACTOR: &'static [u64] = &[0, 0, 0, 0];

    fn prime_subgroup_generator() -> Self {
        Self(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
    }

    fn into_projective(&self) -> Self::Projective {
        *self
    }

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self(RistrettoPoint::hash_from_bytes::<sha2::Sha512>(bytes)))
    }

    fn mul<S: Into<<Self::ScalarField as PrimeField>::BigInt>>(
        &self,
        other: S,
    ) -> Self::Projective {
        let mut p = self.clone();
        p *= Fr::from_repr(other.into()).unwrap();
        p
    }

    fn mul_by_cofactor(&self) -> Self {
        let mut p = self.clone();
        p *= Fr::from(8u32);
        p.into()
    }

    fn mul_by_cofactor_inv(&self) -> Self {
        //self *= (Fr::from(8u32).inverse().unwrap())
        panic!("Curve mul_by_cofactor_inv");
    }

    fn mul_by_cofactor_to_projective(&self) -> Self::Projective {
        panic!("Curve mul_by_cofactor_to_projective");
    }
}

impl ProjectiveCurve for Curve25519Point {
    type ScalarField = Fr;
    type BaseField = Fr;
    type Affine = Curve25519Point;
    // not use in curve25519
    const COFACTOR: &'static [u64] = &[0, 0, 0, 0];

    fn prime_subgroup_generator() -> Self {
        panic!("Curve prime_subgroup_generator");
    }

    fn batch_normalization(_v: &mut [Self]) {
        panic!("Curve batch normalization");
    }

    fn batch_normalization_into_affine(v: &[Self]) -> crate::Vec<Self::Affine> {
        let mut v = v.to_vec();
        Self::batch_normalization(&mut v);
        v
    }

    fn is_normalized(&self) -> bool {
        panic!("Curve is_normalized");
    }

    fn double(&self) -> Self {
        let mut copy = *self;
        copy.double_in_place();
        copy
    }

    fn double_in_place(&mut self) -> &mut Self {
        panic!("Curve double_in_place");
    }

    fn into_affine(&self) -> Self::Affine {
        *self
    }

    fn add_mixed(mut self, other: &Self::Affine) -> Self {
        self.add_assign_mixed(other);
        self
    }

    fn add_assign_mixed(&mut self, other: &Self::Affine) {
        *self += other;
    }

    fn mul<S: AsRef<[u64]>>(mut self, other: S) -> Self {
        assert_eq!(other.as_ref().len(), 4);
        let mut vec = Vec::new();
        for i in other.as_ref().iter() {
            let _ = i.serialize(&mut vec);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&vec[..]);
        self.0 *= Scalar::from_canonical_bytes(bytes).unwrap();
        self
    }
}

impl ToBytes for Curve25519Point {
    #[inline]
    fn write<W: io::Write>(&self, mut w: W) -> io::Result<()> {
        self.0.compress().as_bytes().write(&mut w)
    }
}

impl FromBytes for Curve25519Point {
    #[inline]
    fn read<R: io::Read>(mut r: R) -> io::Result<Self> {
        let bytes = <[u8; 32]>::read(&mut r)?;
        Ok(Self(CompressedRistretto(bytes).decompress().ok_or(
            io::Error::new(io::ErrorKind::UnexpectedEof, "from bytes error"),
        )?))
    }
}

impl Zero for Curve25519Point {
    fn zero() -> Self {
        Self(RistrettoPoint::identity())
    }

    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }
}

impl core::fmt::Display for Curve25519Point {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "(Curve25519 Projective {:?})", self.0)
    }
}

impl core::ops::Add<Curve25519Point> for Curve25519Point {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl core::ops::Sub<Curve25519Point> for Curve25519Point {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl core::ops::AddAssign<Curve25519Point> for Curve25519Point {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl core::ops::SubAssign<Curve25519Point> for Curve25519Point {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0
    }
}

impl core::ops::MulAssign<<Self as ProjectiveCurve>::ScalarField> for Curve25519Point {
    fn mul_assign(&mut self, rhs: <Self as ProjectiveCurve>::ScalarField) {
        let mut bytes = [0u8; 32];
        let mut vec = Vec::new();
        let _ = rhs.write(&mut vec);
        bytes.copy_from_slice(&vec[..]);
        self.0 *= Scalar::from_bytes_mod_order(bytes)
    }
}

impl<'b> core::ops::Add<&'b Self> for Curve25519Point {
    type Output = Self;
    fn add(self, rhs: &'b Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<'b> core::ops::Sub<&'b Self> for Curve25519Point {
    type Output = Self;
    fn sub(self, rhs: &'b Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<'b> core::ops::AddAssign<&'b Self> for Curve25519Point {
    fn add_assign(&mut self, rhs: &'b Self) {
        self.0 += rhs.0
    }
}

impl<'b> core::ops::SubAssign<&'b Self> for Curve25519Point {
    fn sub_assign(&mut self, rhs: &'b Self) {
        self.0 -= rhs.0
    }
}

impl core::ops::Neg for Curve25519Point {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl<T> core::iter::Sum<T> for Curve25519Point
where
    T: core::borrow::Borrow<Curve25519Point>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Curve25519Point::zero(), |acc, item| acc + item.borrow())
    }
}

impl Distribution<Curve25519Point> for Standard {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Curve25519Point {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        Curve25519Point(RistrettoPoint::from_uniform_bytes(&bytes))
    }
}

impl core::hash::Hash for Curve25519Point {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.compress().as_bytes().hash(state);
    }
}

impl Zeroize for Curve25519Point {
    fn zeroize(&mut self) {
        // RistrettoPoint has zeroize
    }
}

impl CanonicalSerialize for Curve25519Point {
    #[inline]
    fn serialize<W: io::Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.0.compress().as_bytes().serialize(writer)
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        32
    }

    #[inline]
    fn serialize_uncompressed<W: io::Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.0.compress().as_bytes().serialize(writer)
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        32
    }
}

impl CanonicalDeserialize for Curve25519Point {
    fn deserialize<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let bytes = <[u8; 32]>::read(&mut reader)?;
        Ok(Self(CompressedRistretto(bytes).decompress().ok_or(
            io::Error::new(io::ErrorKind::UnexpectedEof, "deserialize bytes error"),
        )?))
    }

    fn deserialize_uncompressed<R: io::Read>(
        mut reader: R,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let bytes = <[u8; 32]>::read(&mut reader)?;
        Ok(Self(CompressedRistretto(bytes).decompress().ok_or(
            io::Error::new(io::ErrorKind::UnexpectedEof, "deserialize bytes error"),
        )?))
    }

    fn deserialize_unchecked<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let bytes = <[u8; 32]>::read(&mut reader)?;
        Ok(Self(CompressedRistretto(bytes).decompress().ok_or(
            io::Error::new(io::ErrorKind::UnexpectedEof, "deserialize bytes error"),
        )?))
    }
}
