mod keygen;
mod prover;
mod verifier;

#[cfg(test)]
mod test {
    use ark_bls12_381::Fr;
    use ark_ff::{One, UniformRand, Zero};
    use ark_std::test_rng;

    use crate::composer::Composer;
    use crate::Error;

    use super::prover::Prover;
    use super::verifier::Verifier;

    fn run() -> Result<bool, Error> {
        let K1: Fr = Fr::from(7 as u64);
        let K2: Fr = Fr::from(13 as u64);
        let K3: Fr = Fr::from(17 as u64);
        let rng = &mut test_rng();

        // compose
        let mut c = Composer::new();
        let lvalue = Fr::rand(rng);
        let rvalue = Fr::rand(rng);
        let lvar = c.alloc_and_assign(lvalue);
        let rvar = c.alloc_and_assign(rvalue);
        let ovar = c.alloc_and_assign(lvalue + rvalue);
        c.create_add_gate(
            (lvar, Fr::one()),
            (rvar, Fr::one()),
            ovar,
            None,
            Fr::zero(),
            Fr::zero(),
        );

        // init
        let mut p = Prover::init(&c, [Fr::one(), K1, K2, K3])?;
        let mut v = Verifier::init(&c)?;
        // first round
        let first_oracles = p.first_round(&c)?;
        let first_msg = v.first_round(rng)?;
        // second round
        let second_oracles = p.second_round(&first_msg)?;
        let second_msg = v.second_round(rng)?;
        // third round
        let third_oracles = p.third_round(&second_msg)?;
        let query_set = v.create_query_set(rng);

        Ok(true)
    }

    #[test]
    fn test() {
        assert!(run().unwrap());
    }
}
