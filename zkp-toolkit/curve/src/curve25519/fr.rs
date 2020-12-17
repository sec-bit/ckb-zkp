use math::{
    biginteger::BigInteger256 as BigInteger,
    fields::{Fp256, Fp256Parameters, FpParameters},
};

pub type Fr = Fp256<FrParameters>;

pub struct FrParameters;

impl Fp256Parameters for FrParameters {}

impl FpParameters for FrParameters {
    type BigInt = BigInteger;

    /// q = 2^255 - 19
    /// r = 2^252 + 27742317777372353535851937790883648493
    /// 7237005577332262213973186563042994240857116359379907606001950938285454250989
    /// 0x1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed
    const MODULUS: BigInteger = BigInteger([
        6346243789798364141u64,
        1503914060200516822u64,
        0u64,
        1152921504606846976u64,
    ]);

    /// 255
    const MODULUS_BITS: u32 = 253;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 3;

    /// R = 2^256 mod q
    const R: BigInteger = BigInteger([
        15486807595281847581u64,
        14334777244411350896u64,
        18446744073709551614u64,
        1152921504606846975u64,
    ]);

    /// R^2 = 2^512 mod q
    const R2: BigInteger = BigInteger([
        11819153939886771969u64,
        14991950615390032711u64,
        14910419812499177061u64,
        259310039853996605u64,
    ]);

    /// INV = -(q^{-1} mod 2^64) mod 2^64
    const INV: u64 = 15183074304973897243u64;

    /// GENERATOR = 9
    const GENERATOR: BigInteger = BigInteger([
        14824341744311508637u64,
        6301218275840713796u64,
        18446744073709551604u64,
        1152921504606846975u64,
    ]);

    /// 2^s ? s=2
    const TWO_ADICITY: u32 = 4;

    /// 2^s root of unity computed by GENERATOR^t
    const ROOT_OF_UNITY: BigInteger = BigInteger([
        15486807595281847581u64,
        14334777244411350896u64,
        18446744073709551614u64,
        1152921504606846975u64,
    ]);

    /// (Self::MODULUS - 1) / 2
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger =
        BigInteger([13876462170967809896, 12031312481604134578, 0, 0]);

    /// t for 2^s * t = MODULUS - 1
    const T: BigInteger = BigInteger([6938231085483904948, 6015656240802067289, 0, 0]);

    /// (t - 1) / 2
    const T_MINUS_ONE_DIV_TWO: BigInteger =
        BigInteger([2367949182742163228, 18046968722406201868, 0, 0]);
}
