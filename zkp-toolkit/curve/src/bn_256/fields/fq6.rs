use crate::bn_256::*;
use math::{biginteger::BigInteger256 as BigInteger, field_new, fields::*};

pub type Fq6 = Fp6<Fq6Parameters>;

#[derive(Clone, Copy)]
pub struct Fq6Parameters;

impl Fp6Parameters for Fq6Parameters {
    type Fp2Params = Fq2Parameters;

    /// (Not used)
    /// NONRESIDUE = (U + 9)
    const NONRESIDUE: Fq2 = field_new!(
        Fq2,
        field_new!(Fq, BigInteger([0x0, 0x0, 0x0, 0x0])),
        field_new!(Fq, BigInteger([0x0, 0x0, 0x0, 0x0])),
    );

    const FROBENIUS_COEFF_FP6_C1: [Fq2; 6] = [
        // Fq2(u + 9)**(((q^0) - 1) / 3)
        field_new!(
            Fq2,
            field_new!(
                Fq,
                BigInteger([
                    0xd35d438dc58f0d9d,
                    0x0a78eb28f5c70b3d,
                    0x666ea36f7879462c,
                    0x0e0a77c19a07df2f,
                ])
            ),
            field_new!(Fq, BigInteger([0x0, 0x0, 0x0, 0x0,])),
        ),
        // Fq2(u + 9)**(((q^1) - 1) / 3)
        // taken from go-ethereum and also re-calculated manually
        field_new!(
            Fq2,
            field_new!(
                Fq,
                BigInteger([
                    0xb5773b104563ab30,
                    0x347f91c8a9aa6454,
                    0x7a007127242e0991,
                    0x1956bcd8118214ec,
                ])
            ),
            field_new!(
                Fq,
                BigInteger([
                    0x6e849f1ea0aa4757,
                    0xaa1c7b6d89f89141,
                    0xb6e713cdfae0ca3a,
                    0x26694fbb4e82ebc3,
                ])
            ),
        ),
        // Fq2(u + 9)**(((q^2) - 1) / 3)
        // this one and other below are recalculated manually
        field_new!(
            Fq2,
            field_new!(
                Fq,
                BigInteger([
                    0x3350c88e13e80b9c,
                    0x7dce557cdb5e56b9,
                    0x6001b4b8b615564a,
                    0x2682e617020217e0,
                ])
            ),
            field_new!(Fq, BigInteger([0x0, 0x0, 0x0, 0x0])),
        ),
        // Fq2(u + 9)**(((q^3) - 1) / 3)
        field_new!(
            Fq2,
            field_new!(
                Fq,
                BigInteger([
                    0xc9af22f716ad6bad,
                    0xb311782a4aa662b2,
                    0x19eeaf64e248c7f4,
                    0x20273e77e3439f82,
                ])
            ),
            field_new!(
                Fq,
                BigInteger([
                    0xacc02860f7ce93ac,
                    0x3933d5817ba76b4c,
                    0x69e6188b446c8467,
                    0x0a46036d4417cc55,
                ])
            ),
        ),
        // Fq2(u + 9)**(((q^4) - 1) / 3)
        field_new!(
            Fq2,
            field_new!(
                Fq,
                BigInteger([
                    0x71930c11d782e155,
                    0xa6bb947cffbe3323,
                    0xaa303344d4741444,
                    0x2c3b3f0d26594943,
                ])
            ),
            field_new!(Fq, BigInteger([0x0, 0x0, 0x0, 0x0])),
        ),
        // Fq2(u + 9)**(((q^5) - 1) / 3)
        field_new!(
            Fq2,
            field_new!(
                Fq,
                BigInteger([
                    0xf91aba2654e8e3b1,
                    0x4771cb2fdc92ce12,
                    0xdcb16ae0fc8bdf35,
                    0x274aa195cd9d8be4,
                ])
            ),
            field_new!(
                Fq,
                BigInteger([
                    0x5cfc50ae18811f8b,
                    0x4bb28433cb43988c,
                    0x4fd35f13c3b56219,
                    0x301949bd2fc8883a,
                ])
            ),
        ),
    ];

    const FROBENIUS_COEFF_FP6_C2: [Fq2; 6] = [
        // Fq2(u + 1)**(((2q^0) - 2) / 3)
        field_new!(
            Fq2,
            field_new!(
                Fq,
                BigInteger([
                    0xd35d438dc58f0d9d,
                    0x0a78eb28f5c70b3d,
                    0x666ea36f7879462c,
                    0x0e0a77c19a07df2f,
                ])
            ),
            field_new!(Fq, BigInteger([0x0, 0x0, 0x0, 0x0])),
        ),
        // Fq2(u + 1)**(((2q^1) - 2) / 3)
        field_new!(
            Fq2,
            field_new!(
                Fq,
                BigInteger([
                    0x7361d77f843abe92,
                    0xa5bb2bd3273411fb,
                    0x9c941f314b3e2399,
                    0x15df9cddbb9fd3ec,
                ])
            ),
            field_new!(
                Fq,
                BigInteger([
                    0x5dddfd154bd8c949,
                    0x62cb29a5a4445b60,
                    0x37bc870a0c7dd2b9,
                    0x24830a9d3171f0fd,
                ])
            ),
        ),
        // Fq2(u + 1)**(((2q^2) - 2) / 3)
        field_new!(
            Fq2,
            field_new!(
                Fq,
                BigInteger([
                    0x71930c11d782e155,
                    0xa6bb947cffbe3323,
                    0xaa303344d4741444,
                    0x2c3b3f0d26594943,
                ])
            ),
            field_new!(Fq, BigInteger([0x0, 0x0, 0x0, 0x0])),
        ),
        // Fq2(u + 1)**(((2q^3) - 2) / 3)
        field_new!(
            Fq2,
            field_new!(
                Fq,
                BigInteger([
                    0x448a93a57b6762df,
                    0xbfd62df528fdeadf,
                    0xd858f5d00e9bd47a,
                    0x06b03d4d3476ec58,
                ])
            ),
            field_new!(
                Fq,
                BigInteger([
                    0x2b19daf4bcc936d1,
                    0xa1a54e7a56f4299f,
                    0xb533eee05adeaef1,
                    0x170c812b84dda0b2,
                ])
            ),
        ),
        // Fq2(u + 1)**(((2q^4) - 2) / 3)
        field_new!(
            Fq2,
            field_new!(
                Fq,
                BigInteger([
                    0x3350c88e13e80b9c,
                    0x7dce557cdb5e56b9,
                    0x6001b4b8b615564a,
                    0x2682e617020217e0,
                ])
            ),
            field_new!(Fq, BigInteger([0x0, 0x0, 0x0, 0x0])),
        ),
        // Fq2(u + 1)**(((2q^5) - 2) / 3)
        field_new!(
            Fq2,
            field_new!(
                Fq,
                BigInteger([
                    0x843420f1d8dadbd6,
                    0x31f010c9183fcdb2,
                    0x436330b527a76049,
                    0x13d47447f11adfe4,
                ])
            ),
            field_new!(
                Fq,
                BigInteger([
                    0xef494023a857fa74,
                    0x2a925d02d5ab101a,
                    0x83b015829ba62f10,
                    0x2539111d0c13aea3,
                ])
            ),
        ),
    ];

    /// Multiply this element by quadratic nonresidue 9 + u.
    /// Make this generic.
    fn mul_fp2_by_nonresidue(fe: &Fq2) -> Fq2 {
        let mut copy = *fe;

        // (xi+y)(i+9) = (9x+y)i+(9y-x)
        let t0 = copy.c0;
        let t1 = copy.c1;

        // 8*x*i + 8*y
        copy.double_in_place();
        copy.double_in_place();
        copy.double_in_place();

        // 9*y
        copy.c0 += &t0;
        // (9*y - x)
        copy.c0 -= &t1;

        // (9*x)i
        copy.c1 += &t1;
        // (9*x + y)
        copy.c1 += &t0;

        copy
    }
}
