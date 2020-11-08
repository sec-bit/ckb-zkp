use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use math::{
    curves::{AffineCurve, Curve, ProjectiveCurve},
    PrimeField, ToBytes, Zero,
};
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};

use crate::Vec;

use super::Fr;

#[derive(Serialize, Deserialize)]
pub struct Curve25519;

impl Curve for Curve25519 {
    type Fq = Fr;
    type Fr = Fr;
    type Affine = Curve25519Affine;
    type Projective = Curve25519Projective;

    fn vartime_multiscalar_mul(s: &[Self::Fr], p: &[Self::Affine]) -> Self::Projective {
        let scalars: Vec<Scalar> = s
            .iter()
            .map(|s| {
                let mut bytes = [0u8; 32];
                let mut vec = Vec::new();
                let _ = s.write(&mut vec);
                bytes.copy_from_slice(&vec[..]);
                Scalar::from_bytes_mod_order(bytes)
            })
            .collect();
        let points: Vec<RistrettoPoint> = p.iter().map(|p| p.0.decompress().unwrap()).collect();
        let point = RistrettoPoint::vartime_multiscalar_mul(scalars, points);
        Curve25519Projective(point.into())
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Copy, Clone, Default, Hash, Debug)]
pub struct Curve25519Affine(pub CompressedRistretto); // compressd ristrettopoint.

#[derive(Serialize, Deserialize, Eq, PartialEq, Copy, Clone, Default, Debug)]
pub struct Curve25519Projective(pub RistrettoPoint);

impl AffineCurve for Curve25519Affine {
    type ScalarField = Fr;
    type BaseField = Fr;
    type Projective = Curve25519Projective;

    fn prime_subgroup_generator() -> Self {
        Self(curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED)
    }

    fn into_projective(&self) -> Self::Projective {
        (*self).into()
    }

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self(
            RistrettoPoint::hash_from_bytes::<sha2::Sha512>(bytes).compress(),
        ))
    }

    fn mul<S: Into<<Self::ScalarField as PrimeField>::BigInt>>(
        &self,
        other: S,
    ) -> Self::Projective {
        let mut p = Curve25519Projective::from(*self);
        p *= Fr::from_repr(other.into());
        p
    }

    fn mul_by_cofactor(&self) -> Self {
        panic!("Curve mul_by_cofactor");
    }

    fn mul_by_cofactor_inv(&self) -> Self {
        panic!("Curve mul_by_cofactor_inv");
    }
}

impl ProjectiveCurve for Curve25519Projective {
    type ScalarField = Fr;
    type BaseField = Fr;
    type Affine = Curve25519Affine;

    fn prime_subgroup_generator() -> Self {
        panic!("Curve prime_subgroup_generator");
    }

    fn batch_normalization(_v: &mut [Self]) {
        panic!("Curve batch normalization");
    }

    fn batch_normalization_into_affine(v: &[Self]) -> crate::Vec<Self::Affine> {
        let mut v = v.to_vec();
        Self::batch_normalization(&mut v);
        v.into_iter().map(|v| v.into()).collect()
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
        (*self).into()
    }

    fn add_mixed(mut self, other: &Self::Affine) -> Self {
        self.add_assign_mixed(other);
        self
    }

    fn add_assign_mixed(&mut self, other: &Self::Affine) {
        *self += other.into_projective();
    }

    fn mul<S: Into<<Self::ScalarField as PrimeField>::BigInt>>(mut self, other: S) -> Self {
        self *= Fr::from_repr(other.into());
        self
    }
}

impl math::ToBytes for Curve25519Affine {
    #[inline]
    fn write<W: math::io::Write>(&self, mut w: W) -> math::io::Result<()> {
        self.0.as_bytes().write(&mut w)
    }
}

impl math::FromBytes for Curve25519Affine {
    #[inline]
    fn read<R: math::io::Read>(mut r: R) -> math::io::Result<Self> {
        let bytes = <[u8; 32]>::read(&mut r)?;
        Ok(Self(CompressedRistretto(bytes)))
    }
}

impl math::ToBytes for Curve25519Projective {
    #[inline]
    fn write<W: math::io::Write>(&self, mut w: W) -> math::io::Result<()> {
        self.0.compress().as_bytes().write(&mut w)
    }
}

impl math::FromBytes for Curve25519Projective {
    #[inline]
    fn read<R: math::io::Read>(mut r: R) -> math::io::Result<Self> {
        let bytes = <[u8; 32]>::read(&mut r)?;
        Ok(Self(
            CompressedRistretto(bytes)
                .decompress()
                .ok_or(math::error("from bytes error"))?,
        ))
    }
}

impl Zero for Curve25519Affine {
    fn zero() -> Self {
        Self(CompressedRistretto::identity())
    }

    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }
}

impl core::ops::Add<Curve25519Affine> for Curve25519Affine {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        (self.into_projective() + rhs.into_projective()).into()
    }
}

impl core::ops::Neg for Curve25519Affine {
    type Output = Self;
    fn neg(self) -> Self::Output {
        self.into_projective().neg().into()
    }
}

impl From<Curve25519Projective> for Curve25519Affine {
    fn from(p: Curve25519Projective) -> Curve25519Affine {
        Self(p.0.compress())
    }
}

impl core::fmt::Display for Curve25519Affine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "(Curve25519 Affine {:?})", self.0)
    }
}

impl Zero for Curve25519Projective {
    fn zero() -> Self {
        Self(RistrettoPoint::identity())
    }

    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }
}

impl From<Curve25519Affine> for Curve25519Projective {
    fn from(p: Curve25519Affine) -> Curve25519Projective {
        p.0.decompress()
            .map(|s| Self(s))
            .unwrap_or(Curve25519Projective::zero())
    }
}

impl core::fmt::Display for Curve25519Projective {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "(Curve25519 Projective {:?})", self.0)
    }
}

impl core::ops::Add<Curve25519Projective> for Curve25519Projective {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl core::ops::Sub<Curve25519Projective> for Curve25519Projective {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl core::ops::AddAssign<Curve25519Projective> for Curve25519Projective {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl core::ops::SubAssign<Curve25519Projective> for Curve25519Projective {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0
    }
}

impl core::ops::MulAssign<<Self as ProjectiveCurve>::ScalarField> for Curve25519Projective {
    fn mul_assign(&mut self, rhs: <Self as ProjectiveCurve>::ScalarField) {
        let mut bytes = [0u8; 32];
        let mut vec = Vec::new();
        let _ = rhs.write(&mut vec);
        bytes.copy_from_slice(&vec[..]);
        self.0 *= Scalar::from_bytes_mod_order(bytes)
    }
}

impl<'b> core::ops::Add<&'b Self> for Curve25519Projective {
    type Output = Self;
    fn add(self, rhs: &'b Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<'b> core::ops::Sub<&'b Self> for Curve25519Projective {
    type Output = Self;
    fn sub(self, rhs: &'b Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<'b> core::ops::AddAssign<&'b Self> for Curve25519Projective {
    fn add_assign(&mut self, rhs: &'b Self) {
        self.0 += rhs.0
    }
}

impl<'b> core::ops::SubAssign<&'b Self> for Curve25519Projective {
    fn sub_assign(&mut self, rhs: &'b Self) {
        self.0 -= rhs.0
    }
}

impl core::ops::Neg for Curve25519Projective {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl<T> core::iter::Sum<T> for Curve25519Projective
where
    T: core::borrow::Borrow<Curve25519Projective>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Curve25519Projective::zero(), |acc, item| {
            acc + item.borrow()
        })
    }
}

impl Distribution<Curve25519Projective> for Standard {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Curve25519Projective {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        Curve25519Projective(RistrettoPoint::from_uniform_bytes(&bytes))
    }
}

impl core::hash::Hash for Curve25519Projective {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.compress().as_bytes().hash(state);
    }
}
