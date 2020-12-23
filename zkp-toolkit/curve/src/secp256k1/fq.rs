use math::{
    biginteger::BigInteger320 as BigInteger,
    fields::{Fp320, Fp320Parameters, FpParameters},
};

pub type Fq = Fp320<FqParameters>;

pub struct FqParameters;

impl Fp320Parameters for FqParameters {}

impl FpParameters for FqParameters {
    type BigInt = BigInteger;

    /// Constant representing the modulus
    /// p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
    ///     115792089237316195423570985008687907853269984665640564039457584007908834671663
    const MODULUS: BigInteger = BigInteger([
        18446744069414583343u64,
        18446744073709551615u64,
        18446744073709551615u64,
        18446744073709551615u64,
        0u64,
    ]);

    /// 256
    const MODULUS_BITS: u32 = 256;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 64;

    /// R = 2^256 mod q
    const R: BigInteger = BigInteger([0u64, 4294968273u64, 0u64, 0u64, 0u64]);

    /// R^2 = 2^512 mod q
    const R2: BigInteger = BigInteger([0u64, 0u64, 8392367050913u64, 1u64, 0u64]);

    /// INV = -(q^{-1} mod 2^64) mod 2^64
    const INV: u64 = 15580212934572586289u64;

    /// GENERATOR = 4
    const GENERATOR: BigInteger = BigInteger([0u64, 17179873092u64, 0u64, 0u64, 0u64]);

    /// 2^s ? s=1
    const TWO_ADICITY: u32 = 1;

    /// 2^s root of unity computed by GENERATOR^t TODO
    const ROOT_OF_UNITY: BigInteger = BigInteger([0u64, 4294968273u64, 0u64, 0u64, 0u64]);

    /// (Self::MODULUS - 1) / 2
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        18446744071562067479u64,
        18446744073709551615u64,
        18446744073709551615u64,
        9223372036854775807u64,
        0u64,
    ]);

    /// t for 2^s * t = MODULUS - 1
    const T: BigInteger = BigInteger([0, 0, 0, 0, 0]);

    /// (t - 1) / 2
    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([0, 0, 0, 0, 0]);
}
