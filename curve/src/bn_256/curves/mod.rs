use math::{
    biginteger::BigInteger256,
    curves::bn::{Bn, BnParameters},
    field_new,
};

use crate::bn_256::{Fq, Fq12Parameters, Fq2, Fq2Parameters, Fq6Parameters};

pub mod g1;
pub mod g2;

#[cfg(test)]
mod tests;

pub use self::{
    g1::{G1Affine, G1Projective},
    g2::{G2Affine, G2Projective},
};

pub type Bn_256 = Bn<Parameters>;

pub struct Parameters;

impl BnParameters for Parameters {
    const U: &'static [u64] = &[4965661367192848881];
    const SIX_U_PLUS_2_NAF: &'static [i8] = &[
        0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0,
        0, 1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 1, 1, 0,
        -1, 0, 0, 1, 0, 1, 1,
    ];

    /// XI_TO_Q_MINUS_1_OVER_2
    const CUBIC_NONRESIDUE_TO_Q_MINUS_1_OVER_2: Fq2 = field_new!(
        Fq2,
        field_new!(
            Fq,
            BigInteger256([
                0xe4bbdd0c2936b629,
                0xbb30f162e133bacb,
                0x31a9d1b6f9645366,
                0x253570bea500f8dd,
            ])
        ),
        field_new!(
            Fq,
            BigInteger256([
                0xa1d77ce45ffe77c7,
                0x07affd117826d1db,
                0x6d16bd27bb7edc6b,
                0x2c87200285defecc,
            ])
        ),
    );

    type Fp = Fq;
    type Fp2Params = Fq2Parameters;
    type Fp6Params = Fq6Parameters;
    type Fp12Params = Fq12Parameters;
    type G1Parameters = self::g1::Parameters;
    type G2Parameters = self::g2::Parameters;
}
