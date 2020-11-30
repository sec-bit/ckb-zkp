// use math::fft::DensePolynomial as Polynomial;
use math::{PairingEngine, ProjectiveCurve, UniformRand};
use rand::Rng;

#[derive(Clone)]
pub struct MultiCommitmentSetupParameters<E: PairingEngine> {
    pub n: usize,
    pub generators: Vec<E::G1Affine>,
    pub h: E::G1Affine,
}

#[derive(Clone)]
pub struct SumCheckCommitmentSetupParameters<E: PairingEngine> {
    pub gen_1: MultiCommitmentSetupParameters<E>,
    pub gen_3: MultiCommitmentSetupParameters<E>,
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

#[derive(Clone)]
pub struct PolyCommitmentSetupParameters<E: PairingEngine> {
    pub n: usize,
    pub gen_n: MultiCommitmentSetupParameters<E>,
    pub gen_1: MultiCommitmentSetupParameters<E>,
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
