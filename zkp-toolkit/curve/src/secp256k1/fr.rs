use math::{
    biginteger::BigInteger320 as BigInteger,
    fields::{Fp320, Fp320Parameters, FpParameters},
};

pub type Fr = Fp320<FrParameters>;

pub struct FrParameters;

impl Fp320Parameters for FrParameters {}

impl FpParameters for FrParameters {
    type BigInt = BigInteger;

    /// Constant representing the modulus
    /// r = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
    ///     115792089237316195423570985008687907852837564279074904382605163141518161494337
    const MODULUS: BigInteger = BigInteger([
        13822214165235122497u64,
        13451932020343611451u64,
        18446744073709551614u64,
        18446744073709551615u64,
        0u64,
    ]);

    /// 256
    const MODULUS_BITS: u32 = 256;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 64;

    /// R = 2^256 mod q
    const R: BigInteger = BigInteger([
        0u64,
        4624529908474429119u64,
        4994812053365940164u64,
        1u64,
        0u64,
    ]);

    /// R^2 = 2^512 mod q
    const R2: BigInteger = BigInteger([
        2161815027462274937u64,
        647662477280039658u64,
        2865435121925625427u64,
        4330881270917637700u64,
        0u64,
    ]);

    /// INV = -(q^{-1} mod 2^64) mod 2^64
    const INV: u64 = 5408259542528602431u64;

    /// GENERATOR = 4
    const GENERATOR: BigInteger = BigInteger([
        0u64,
        51375560188164860u64,
        1532504139754209041u64,
        5u64,
        0u64,
    ]);

    /// 2^s ? s=6
    const TWO_ADICITY: u32 = 6;

    /// 2^s root of unity computed by GENERATOR^t TODO
    const ROOT_OF_UNITY: BigInteger = BigInteger([
        0u64,
        4624529908474429119u64,
        4994812053365940164u64,
        1u64,
        0u64,
    ]);

    /// (Self::MODULUS - 1) / 2
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        16134479119472337056u64,
        6725966010171805725u64,
        18446744073709551615u64,
        9223372036854775807u64,
        0u64,
    ]);

    /// t for 2^s * t = MODULUS - 1
    const T: BigInteger = BigInteger([
        17221564289282791685u64,
        18080469759223997056u64,
        18446744073709551615u64,
        288230376151711743u64,
        0u64,
    ]);

    /// (t - 1) / 2
    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        15996384504856031752u64,
        17714195444738442497u64,
        18446744073709551615u64,
        576460752303423487u64,
        0u64,
    ]);
}
