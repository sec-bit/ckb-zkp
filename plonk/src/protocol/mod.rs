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
        let ks = [
            Fr::one(),
            Fr::from(7_u64),
            Fr::from(13_u64),
            Fr::from(17_u64),
        ];
        let rng = &mut test_rng();

        // compose
        let mut cs = Composer::new();
        let one = Fr::one();
        let two = one + one;
        let three = two + one;
        let four = two + two;
        let var_one = cs.alloc_and_assign(one);
        let var_two = cs.alloc_and_assign(two);
        let var_three = cs.alloc_and_assign(three);
        let var_four = cs.alloc_and_assign(four);
        cs.create_add_gate(
            (var_two, one),
            (var_two, one),
            var_four,
            None,
            Fr::zero(),
            Fr::zero(),
        );

        cs.create_mul_gate(
            var_one,
            var_three,
            var_three,
            None,
            Fr::one(),
            Fr::zero(),
            Fr::zero(),
        );

        println!("size of the circuit: {}", cs.size());

        // init
        print!("initializing prover...");
        let mut p = Prover::init(&cs, ks)?;
        println!("done");

        print!("initializing verifier...");
        let mut v = Verifier::init(&cs)?;
        println!("done");
        // first round
        print!("prover: first round...");
        let first_oracles = p.first_round(&cs)?;
        println!("done");

        print!("verifier: first round...");
        let first_msg = v.first_round(rng)?;
        println!("done");

        // second round
        print!("prover: second round...");
        let second_oracles = p.second_round(&first_msg)?;
        println!("done");

        print!("verifier: second round...");
        let second_msg = v.second_round(rng)?;
        println!("done");
        // third round
        print!("prover: third round...");
        let third_oracles = p.third_round(&second_msg)?;
        println!("done");

        print!("verifier: third round...");
        let third_msg = v.third_round(rng)?;
        println!("done");
        // finalize
        print!("prover: evaluating...");
        let evals = p.evaluate(
            &third_msg,
            &first_oracles,
            &second_oracles,
            &third_oracles,
        );
        println!("done");

        print!("verifier: equality checking...");
        let is_equal = v.check_equality(&evals);
        println!("done");

        is_equal
    }

    #[test]
    fn test() {
        let e = run().unwrap();
        println!("result: {:?}", e);
        assert!(e);
    }
}
