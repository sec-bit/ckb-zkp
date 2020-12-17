#[cfg(test)]
mod bn_256 {
    use crate::hyrax::circuit::Circuit;
    use crate::hyrax::hyrax_proof::HyraxProof;
    use crate::hyrax::params::Parameters;
    use curve::bn_256::Bn_256;
    use math::{Curve, UniformRand};
    use rand::thread_rng;
    use rand::Rng;

    #[test]
    fn test_hyrax_gkr() {
        println!("start linear_gkr...");
        let rng = &mut thread_rng();
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
        println!("prepare linear_gkr...ok");
        let circuit = Circuit::new(8, 8, &layers);
        println!("construct circuit...ok");
        let mut witnesses = Vec::new();
        let mut inputs = Vec::new();
        let n = 4;
        for _ in 0..n {
            witnesses.push(
                (0..8)
                    .map(|_| <Bn_256 as Curve>::Fr::rand(rng))
                    .collect::<Vec<_>>(),
            );
            inputs.push(
                (0..8)
                    .map(|_| <Bn_256 as Curve>::Fr::rand(rng))
                    .collect::<Vec<_>>(),
            );
        }
        let params = Parameters::new(rng, 8);
        println!("generate parameters...");
        let result =
            hyrax_zk_parallel_gkr::<Bn_256, _>(&params, &witnesses, &inputs, &circuit, rng);
        assert!(result);
        println!("hyrax linear gkr...ok");
    }

    fn hyrax_zk_parallel_gkr<G: Curve, R: Rng>(
        params: &Parameters<G>,
        witnesses: &Vec<Vec<G::Fr>>,
        inputs: &Vec<Vec<G::Fr>>,
        circuit: &Circuit,
        rng: &mut R,
    ) -> bool {
        assert_eq!(witnesses.len(), inputs.len());
        let (proof, outputs) =
            HyraxProof::prover(params, witnesses, inputs, circuit, witnesses.len(), rng);
        println!("hyrax_zk_parallel_gkr -- generate proof...ok");
        let result = proof.verify(params, &outputs, inputs, circuit);
        println!("hyrax_zk_parallel_gkr -- verify...{}", result);
        result
    }
}
