#[cfg(test)]
mod bn_256 {
    use crate::libra::circuit::Circuit;
    use crate::libra::libra_linear_gkr::LinearGKRProof;
    use crate::libra::libra_zk_linear_gkr::ZKLinearGKRProof;
    use crate::libra::params::Parameters;
    use curve::bn_256::Bn_256;
    use math::{Curve, One, Zero};
    use rand::thread_rng;

    fn prepare_constrcut_circuit<G: Curve>(
    ) -> (Vec<G::Fr>, Vec<G::Fr>, Vec<Vec<(u8, usize, usize)>>) {
        let mut inputs = Vec::new();
        let mut witnesses = Vec::new();
        let mut value = G::Fr::zero();
        for _ in 0..8 {
            value += &G::Fr::one();
            inputs.push(value)
        }
        for _ in 0..8 {
            value += &G::Fr::one();
            witnesses.push(value)
        }
        let mut layers = Vec::new();
        let mut layer = Vec::new();
        layer.push((1, 0, 1));
        layer.push((0, 2, 3));
        layer.push((0, 4, 5));
        layer.push((1, 6, 7));
        layer.push((1, 15, 8));
        layer.push((1, 9, 10));
        layer.push((0, 11, 12));
        layer.push((0, 13, 14));
        layers.push(layer);
        let mut layer = Vec::new();
        layer.push((1, 0, 1));
        layer.push((0, 2, 3));
        layer.push((0, 4, 5));
        layer.push((1, 6, 7));
        layers.push(layer);
        let mut layer = Vec::new();
        layer.push((0, 0, 1));
        layer.push((0, 1, 2));
        layer.push((1, 2, 3));
        layer.push((1, 1, 3));
        layers.push(layer);

        (inputs, witnesses, layers)
    }

    #[test]
    fn test_libra_linear_gkr_bn_256() {
        println!("start linear_gkr...");
        let (inputs, witnesses, layers) = prepare_constrcut_circuit::<Bn_256>();
        println!("prepare for constructing circuit...ok");

        let circuit = Circuit::new(inputs.len(), witnesses.len(), &layers);
        println!("construct circuit...ok");

        let (proof, output) = LinearGKRProof::<Bn_256>::prover(&circuit, &inputs, &witnesses);
        println!("generate proof...ok");

        let mut inputs2 = witnesses.clone();
        inputs2.extend(&inputs);
        let result = proof.verify(&circuit, &output, &inputs2);
        println!("verifier...{}", result);
        assert!(result);
    }

    #[test]
    fn test_libra_zk_linear_gkr_bn_256() {
        let rng = &mut thread_rng();
        println!("start zk linear gkr...");

        let (inputs, witnesses, layers) = prepare_constrcut_circuit::<Bn_256>();
        println!("prepare for constructing circuit...ok");

        let params = Parameters::<Bn_256>::new(rng, 8);
        println!("prepare for constructing circuit...ok");

        let circuit = Circuit::new(inputs.len(), witnesses.len(), &layers);
        println!("construct circuit...ok");

        let (proof, output) =
            ZKLinearGKRProof::prover::<_>(&params, &circuit, &inputs, &witnesses, rng);
        println!("generate proof...ok");

        let result = proof.verify(&params, &circuit, &output, &inputs);
        println!("verifier...{}", result);
        assert!(result);
    }
}

#[cfg(test)]
mod bls12_381 {
    use crate::libra::circuit::Circuit;
    use crate::libra::libra_linear_gkr::LinearGKRProof;
    use crate::libra::libra_zk_linear_gkr::ZKLinearGKRProof;
    use crate::libra::params::Parameters;
    use curve::bls12_381::Bls12_381;
    use math::{Curve, One, Zero};
    use rand::thread_rng;

    fn prepare_constrcut_circuit<G: Curve>(
    ) -> (Vec<G::Fr>, Vec<G::Fr>, Vec<Vec<(u8, usize, usize)>>) {
        let mut inputs = Vec::new();
        let mut witnesses = Vec::new();
        let mut value = G::Fr::zero();
        for _ in 0..8 {
            value += &G::Fr::one();
            inputs.push(value)
        }
        for _ in 0..8 {
            value += &G::Fr::one();
            witnesses.push(value)
        }
        let mut layers = Vec::new();
        let mut layer = Vec::new();
        layer.push((1, 0, 1));
        layer.push((0, 2, 3));
        layer.push((0, 4, 5));
        layer.push((1, 6, 7));
        layer.push((1, 15, 8));
        layer.push((1, 9, 10));
        layer.push((0, 11, 12));
        layer.push((0, 13, 14));
        layers.push(layer);
        let mut layer = Vec::new();
        layer.push((1, 0, 1));
        layer.push((0, 2, 3));
        layer.push((0, 4, 5));
        layer.push((1, 6, 7));
        layers.push(layer);
        let mut layer = Vec::new();
        layer.push((0, 0, 1));
        layer.push((0, 1, 2));
        layer.push((1, 2, 3));
        layer.push((1, 1, 3));
        layers.push(layer);

        (inputs, witnesses, layers)
    }

    #[test]
    fn test_libra_linear_gkr_bls12_381() {
        println!("start linear_gkr...");
        let (inputs, witnesses, layers) = prepare_constrcut_circuit::<Bls12_381>();
        println!("prepare for constructing circuit...ok");

        let circuit = Circuit::new(inputs.len(), witnesses.len(), &layers);
        println!("construct circuit...ok");

        let (proof, output) = LinearGKRProof::<Bls12_381>::prover(&circuit, &inputs, &witnesses);
        println!("generate proof...ok");

        let mut inputs2 = witnesses.clone();
        inputs2.extend(&inputs);
        let result = proof.verify(&circuit, &output, &inputs2);
        println!("verifier...{}", result);
        assert!(result);
    }

    #[test]
    fn test_libra_zk_linear_gkr_bls12_381() {
        let rng = &mut thread_rng();
        println!("start zk linear gkr...");

        let (inputs, witnesses, layers) = prepare_constrcut_circuit::<Bls12_381>();
        println!("prepare for constructing circuit...ok");

        let params = Parameters::<Bls12_381>::new(rng, 8);
        println!("prepare for constructing circuit...ok");

        let circuit = Circuit::new(inputs.len(), witnesses.len(), &layers);
        println!("construct circuit...ok");

        let (proof, output) =
            ZKLinearGKRProof::<Bls12_381>::prover::<_>(&params, &circuit, &inputs, &witnesses, rng);
        println!("generate proof...ok");

        let result = proof.verify(&params, &circuit, &output, &inputs);
        println!("verifier...{}", result);
        assert!(result);
    }
}
