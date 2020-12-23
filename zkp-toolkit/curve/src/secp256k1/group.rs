use crate::{
    biginteger::BigInteger320 as BigInteger,
    curves::{
        models::{ModelParameters, SWModelParameters},
        short_weierstrass_jacobian::{GroupAffine, GroupProjective},
    },
    field_new,
};

use super::fq::Fq;
use super::fr::Fr;

pub type Affine = GroupAffine<Parameters>;
pub type Projective = GroupProjective<Parameters>;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Parameters;

impl ModelParameters for Parameters {
    type BaseField = Fq;
    type ScalarField = Fr;
}

impl SWModelParameters for Parameters {
    /// COEFF_A = 0
    const COEFF_A: Fq = field_new!(Fq, BigInteger([0, 0, 0, 0, 0]));

    /// COEFF_B = 7
    const COEFF_B: Fq = field_new!(Fq, BigInteger([0, 30064777911, 0, 0, 0]));

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[1];

    /// COFACTOR^(-1) mod r =
    const COFACTOR_INV: Fr = field_new!(Fr, BigInteger([0, 4294968273, 0, 0, 0]));

    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) =
        (G1_GENERATOR_X, G1_GENERATOR_Y);
}

/// G1_GENERATOR_X = 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
pub const G1_GENERATOR_X: Fq = field_new!(
    Fq,
    BigInteger([
        13963525493596086728,
        15507633334770469156,
        2530505477788034779,
        10925531211367256732,
        0
    ])
);

/// G1_GENERATOR_Y = 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
pub const G1_GENERATOR_Y: Fq = field_new!(
    Fq,
    BigInteger([
        14272066994263577270,
        12780836220428825624,
        10231155108014310989,
        8121878653926228278,
        0
    ])
);
