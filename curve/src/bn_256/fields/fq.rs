use math::{
    biginteger::BigInteger256 as BigInteger,
    fields::{Fp256, Fp256Parameters, FpParameters},
};

pub type Fq = Fp256<FqParameters>;

pub struct FqParameters;

impl Fp256Parameters for FqParameters {}

impl FpParameters for FqParameters {
    type BigInt = BigInteger;

    // 21888242871839275222246405745257275088696311157297823662689037894645226208583
    const MODULUS: BigInteger = BigInteger([
        4332616871279656263u64,
        10917124144477883021u64,
        13281191951274694749u64,
        3486998266802970665u64,
    ]);

    const MODULUS_BITS: u32 = 254;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 2;

    const R: BigInteger = BigInteger([
        15230403791020821917u64,
        754611498739239741u64,
        7381016538464732716u64,
        1011752739694698287u64,
    ]);

    const R2: BigInteger = BigInteger([
        17522657719365597833u64,
        13107472804851548667u64,
        5164255478447964150u64,
        493319470278259999u64,
    ]);

    const INV: u64 = 9786893198990664585u64;

    // GENERATOR = 2
    const GENERATOR: BigInteger = BigInteger([
        12014063508332092218u64,
        1509222997478479483u64,
        14762033076929465432u64,
        2023505479389396574u64,
    ]);

    const TWO_ADICITY: u32 = 1;

    // -((2**256) mod q) mod q
    const ROOT_OF_UNITY: BigInteger = BigInteger([
        15230403791020821917u64,
        754611498739239741u64,
        7381016538464732716u64,
        1011752739694698287u64,
    ]);

    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        11389680472494603939u64,
        14681934109093717318u64,
        15863968012492123182u64,
        1743499133401485332u64,
    ]);

    // T and T_MINUS_ONE_DIV_TWO, where MODULUS - 1 = 2^S * T

    const T: BigInteger = BigInteger([
        11389680472494603939u64,
        14681934109093717318u64,
        15863968012492123182u64,
        1743499133401485332u64,
    ]);

    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        5694840236247301969u64,
        7340967054546858659u64,
        7931984006246061591u64,
        871749566700742666u64,
    ]);
}
