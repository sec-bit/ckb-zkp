use crate::libra::data_structure::{
    MultiCommitmentSetupParameters,
    PolyCommitmentSetupParameters,
    SetupParameters,
    SumCheckCommitmentSetupParameters, //ZK_SetupParameters,
};
use math::{PairingEngine, ProjectiveCurve, UniformRand};
use rand::Rng;

impl<E: PairingEngine> SetupParameters<E> {
    pub fn new<R: Rng>(rng: &mut R, num: usize) -> Self {
        let pc_params = PolyCommitmentSetupParameters::new(rng, num);
        let sc_params = SumCheckCommitmentSetupParameters::new(rng);

        Self {
            pc_params,
            sc_params,
        }
    }
}

impl<E: PairingEngine> PolyCommitmentSetupParameters<E> {
    pub fn new<R: Rng>(rng: &mut R, num: usize) -> Self {
        let n = (2usize).pow((num - num / 2) as u32);
        let mut generators = Vec::new();
        for _ in 0..n {
            generators.push(E::G1Projective::rand(rng).into_affine());
        }
        let h = E::G1Projective::rand(rng).into_affine();
        let gen_n = MultiCommitmentSetupParameters { n, generators, h };

        let g = E::G1Projective::rand(rng).into_affine();
        let gen_1 = MultiCommitmentSetupParameters {
            n: 1,
            generators: vec![g],
            h,
        };

        Self { n, gen_n, gen_1 }
    }
}

impl<E: PairingEngine> SumCheckCommitmentSetupParameters<E> {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let n = 3;
        let mut generators = Vec::new();
        for _ in 0..n {
            generators.push(E::G1Projective::rand(rng).into_affine());
        }
        let h = E::G1Projective::rand(rng).into_affine();
        let gen_3 = MultiCommitmentSetupParameters { n, generators, h };

        let h = E::G1Projective::rand(rng).into_affine();
        let g = E::G1Projective::rand(rng).into_affine();
        let gen_1 = MultiCommitmentSetupParameters {
            n: 1,
            generators: vec![g],
            h,
        };

        Self { gen_1, gen_3 }
    }
}
