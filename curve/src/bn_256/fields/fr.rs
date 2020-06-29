use math::{
    biginteger::BigInteger256 as BigInteger,
    fields::{Fp256, Fp256Parameters, FpParameters},
};

pub type Fr = Fp256<FrParameters>;

pub struct FrParameters;

impl Fp256Parameters for FrParameters {}

impl FpParameters for FrParameters {
    type BigInt = BigInteger;

    const MODULUS: BigInteger = BigInteger([
        0x43e1f593f0000001,
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ]);

    const MODULUS_BITS: u32 = 254;

    const CAPACITY: u32 = 253;

    const REPR_SHAVE_BITS: u32 = 2;

    const R: BigInteger = BigInteger([
        0xac96341c4ffffffb,
        0x36fc76959f60cd29,
        0x666ea36f7879462e,
        0xe0a77c19a07df2f,
    ]);

    const R2: BigInteger = BigInteger([
        0x1bb8e645ae216da7,
        0x53fe3ab1e35c59e3,
        0x8c49833d53bb8085,
        0x0216d0b17f4e44a5,
    ]);

    // 0x6586864b4c6911b3c2e1f593efffffff
    const INV: u64 = 14042775128853446655;

    const GENERATOR: BigInteger = BigInteger([
        0x3057819e4fffffdb,
        0x307f6d866832bb01,
        0x5c65ec9f484e3a89,
        0x180a96573d3d9f8,
    ]);

    const TWO_ADICITY: u32 = 28;

    const ROOT_OF_UNITY: BigInteger = BigInteger([
        0x9632c7c5b639feb8,
        0x985ce3400d0ff299,
        0xb2dd880001b0ecd8,
        0x1d69070d6d98ce29,
    ]);

    // use in (also bellman) - SqrtFiled - legendre
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        11669102379873075200u64,
        10671829228508198984u64,
        15863968012492123182u64,
        1743499133401485332u64,
    ]);

    // use in SqrtField - sqrt
    const T: BigInteger = BigInteger([
        11211439779908376895u64,
        1735440370612733063u64,
        1376415503089949544u64,
        12990080814u64,
    ]);

    // use in SqrtField - sqrt
    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        14829091926808964255u64,
        867720185306366531u64,
        688207751544974772u64,
        6495040407u64,
    ]);
}
