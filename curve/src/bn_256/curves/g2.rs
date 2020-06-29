use crate::{
    biginteger::BigInteger256,
    bn_256,
    bn_256::*,
    curves::{
        bn,
        models::{ModelParameters, SWModelParameters},
    },
    field_new, Zero,
};

pub type G2Affine = bn::G2Affine<bn_256::Parameters>;
pub type G2Projective = bn::G2Projective<bn_256::Parameters>;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Parameters;

impl ModelParameters for Parameters {
    type BaseField = Fq2;
    type ScalarField = Fr;
}

impl SWModelParameters for Parameters {
    /// TODO
    /// COEFF_A = 0
    const COEFF_A: Fq2 = field_new!(Fq2, g1::Parameters::COEFF_A, g1::Parameters::COEFF_A);

    /// TODO
    const COEFF_B: Fq2 = field_new!(
        Fq2,
        field_new!(
            Fq,
            BigInteger256([
                0x3bf938e377b802a8,
                0x020b1b273633535d,
                0x26b7edf049755260,
                0x2514c6324384a86d,
            ])
        ),
        field_new!(
            Fq,
            BigInteger256([
                0x38e7ecccd1dcff67,
                0x65f0b37d93ce0d3e,
                0xd749d0dd22ac00aa,
                0x0141b9ce4a688d4d,
            ])
        ),
    );

    /// TODO
    const COFACTOR: &'static [u64] = &[
        0x345f2299c0f9fa8d,
        0x06ceecda572a2489,
        0xb85045b68181585e,
        0x30644e72e131a029,
    ];

    /// TODO
    /// COFACTOR_INV = COFACTOR^{-1} mod r
    #[rustfmt::skip]
    const COFACTOR_INV: Fr = field_new!(Fr, BigInteger256([
        0x0,
        0x0,
        0x0,
        0x0,
    ]));

    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) =
        (G2_GENERATOR_X, G2_GENERATOR_Y);

    #[inline(always)]
    fn mul_by_a(_: &Self::BaseField) -> Self::BaseField {
        Self::BaseField::zero()
    }
}

pub const G2_GENERATOR_X: Fq2 = field_new!(Fq2, G2_GENERATOR_X_C0, G2_GENERATOR_X_C1);
pub const G2_GENERATOR_Y: Fq2 = field_new!(Fq2, G2_GENERATOR_Y_C0, G2_GENERATOR_Y_C1);

// Generator of G2
//
// x = 11559732032986387107991004021392285783925812861821192530917403151452391805634*u
//     + 10857046999023057135944570762232829481370756359578518086990519993285655852781
//
// y = 4082367875863433681332203403145435568316851327593401208105741076214120093531*u
//     + 8495653923123431417604973247489272438418190587263600148770280649306958101930
pub const G2_GENERATOR_X_C0: Fq = field_new!(
    Fq,
    BigInteger256([
        0x8e83b5d102bc2026,
        0xdceb1935497b0172,
        0xfbb8264797811adf,
        0x19573841af96503b,
    ])
);

pub const G2_GENERATOR_X_C1: Fq = field_new!(
    Fq,
    BigInteger256([
        0xafb4737da84c6140,
        0x6043dd5a5802d8c4,
        0x09e950fc52a02f86,
        0x14fef0833aea7b6b,
    ])
);

pub const G2_GENERATOR_Y_C0: Fq = field_new!(
    Fq,
    BigInteger256([
        0x619dfa9d886be9f6,
        0xfe7fd297f59e9b78,
        0xff9e1a62231b7dfe,
        0x28fd7eebae9e4206,
    ])
);

pub const G2_GENERATOR_Y_C1: Fq = field_new!(
    Fq,
    BigInteger256([
        0x64095b56c71856ee,
        0xdc57f922327d3cbb,
        0x55f935be33351076,
        0x0da4a0e693fd6482,
    ])
);
