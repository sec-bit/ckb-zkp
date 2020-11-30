#[cfg(test)]
mod bn_256 {
    use crate::libra::circuit::Circuit;
    use crate::libra::data_structure::Parameters;
    use crate::libra::libra_linear_gkr::{linear_gkr_prover, linear_gkr_verifier};
    use crate::libra::libra_zk_linear_gkr::{zk_linear_gkr_prover, zk_linear_gkr_verifier};
    use curve::bn_256::Bn_256;
    use math::{Curve, One, Zero};
    use rand::thread_rng;

    fn prepare_constrcut_circuit<G: Curve>() -> (Vec<G::Fr>, Vec<Vec<(u8, usize, usize)>>) {
        let mut inputs = Vec::new();
        let mut value = G::Fr::zero();
        for _ in 0..16 {
            value += &G::Fr::one();
            inputs.push(value)
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

        (inputs, layers)
    }

    #[test]
    fn test_libra_linear_gkr_bn_256() {
        println!("start linear_gkr...");
        let (inputs, layers) = prepare_constrcut_circuit::<Bn_256>();
        println!("prepare for constructing circuit...ok");

        let circuit = Circuit::<Bn_256>::new(&inputs, &layers);
        println!("construct circuit...ok");

        let (proof, output) = linear_gkr_prover::<Bn_256>(&circuit);
        println!("generate proof...ok");
        let result = linear_gkr_verifier::<Bn_256>(&circuit, &output, &inputs, proof);
        println!("verifier...{}", result);
    }

    #[test]
    fn test_libra_zk_linear_gkr_bn_256() {
        let rng = &mut thread_rng();
        println!("start zk linear gkr...");

        let (inputs, layers) = prepare_constrcut_circuit::<Bn_256>();
        println!("prepare for constructing circuit...ok");

        let params = Parameters::<Bn_256>::new(rng, 8);
        println!("prepare for constructing circuit...ok");

        let circuit = Circuit::<Bn_256>::new(&inputs, &layers);
        println!("construct circuit...ok");

        let (proof, output) = zk_linear_gkr_prover::<Bn_256, _>(&params, &circuit, rng);
        println!("generate proof...ok");
        let result = zk_linear_gkr_verifier(&params, &circuit, &output, &inputs, proof);
        println!("verifier...{}", result);
    }
}

#[cfg(test)]
mod bls12_381 {
    use crate::libra::circuit::Circuit;
    use crate::libra::data_structure::Parameters;
    use crate::libra::libra_linear_gkr::{linear_gkr_prover, linear_gkr_verifier};
    use crate::libra::libra_zk_linear_gkr::{zk_linear_gkr_prover, zk_linear_gkr_verifier};
    use curve::bls12_381::Bls12_381;
    use math::{Curve, One, Zero};
    use rand::thread_rng;

    fn prepare_constrcut_circuit<G: Curve>() -> (Vec<G::Fr>, Vec<Vec<(u8, usize, usize)>>) {
        let mut inputs = Vec::new();
        let mut value = G::Fr::zero();
        for _ in 0..16 {
            value += &G::Fr::one();
            inputs.push(value)
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

        (inputs, layers)
    }

    #[test]
    fn test_libra_linear_gkr_bls12_381() {
        println!("start linear_gkr...");
        let (inputs, layers) = prepare_constrcut_circuit::<Bls12_381>();
        println!("prepare for constructing circuit...ok");

        let circuit = Circuit::<Bls12_381>::new(&inputs, &layers);
        println!("construct circuit...ok");

        let (proof, output) = linear_gkr_prover::<Bls12_381>(&circuit);
        println!("generate proof...ok");
        let result = linear_gkr_verifier::<Bls12_381>(&circuit, &output, &inputs, proof);
        println!("verifier...{}", result);
    }

    #[test]
    fn test_libra_zk_linear_gkr_bls12_381() {
        let rng = &mut thread_rng();
        println!("start zk linear gkr...");

        let (inputs, layers) = prepare_constrcut_circuit::<Bls12_381>();
        println!("prepare for constructing circuit...ok");

        let params = Parameters::<Bls12_381>::new(rng, 8);
        println!("prepare for constructing circuit...ok");

        let circuit = Circuit::<Bls12_381>::new(&inputs, &layers);
        println!("construct circuit...ok");

        let (proof, output) = zk_linear_gkr_prover::<Bls12_381, _>(&params, &circuit, rng);
        println!("generate proof...ok");
        let result = zk_linear_gkr_verifier(&params, &circuit, &output, &inputs, proof);
        println!("verifier...{}", result);
    }
}
