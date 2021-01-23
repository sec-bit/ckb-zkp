//! An general zkp curve traint. and implemented the pairing curve.
#![cfg_attr(not(feature = "std"), no_std)]

use ark_ec::{msm::VariableBaseMSM, PairingEngine};
use ark_ff::{PrimeField, SquareRootField};
use core::ops::MulAssign;

// re-export.
pub use ark_ec::{AffineCurve, ProjectiveCurve};

pub trait Curve: 'static + Clone {
    /// The base field that hosts.
    type Fq: PrimeField + SquareRootField;

    /// This is the scalar field of the groups.
    type Fr: PrimeField + SquareRootField;

    /// The projective representation of an element.
    type Projective: From<Self::Affine>
        + Into<Self::Affine>
        + MulAssign<Self::Fr>
        + ProjectiveCurve<BaseField = Self::Fq, ScalarField = Self::Fr, Affine = Self::Affine>;

    /// The affine representation of an element.
    type Affine: From<Self::Projective>
        + Into<Self::Projective>
        + AffineCurve<BaseField = Self::Fq, ScalarField = Self::Fr, Projective = Self::Projective>;

    fn vartime_multiscalar_mul(scalars: &[Self::Fr], points: &[Self::Affine]) -> Self::Projective {
        let uints = scalars
            .into_iter()
            .map(|s| s.into_repr())
            .collect::<Vec<_>>();

        VariableBaseMSM::multi_scalar_mul(points, &uints[..])
    }
}

impl<P: PairingEngine> Curve for P {
    type Fq = P::Fq;
    type Fr = P::Fr;
    type Projective = P::G1Projective;
    type Affine = P::G1Affine;
}
