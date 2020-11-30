// use math::fft::DensePolynomial as Polynomial;
use math::{Curve, ProjectiveCurve, UniformRand};
use rand::Rng;

#[derive(Clone)]
pub struct MultiCommitmentSetupParameters<G: Curve> {
    pub n: usize,
    pub generators: Vec<G::Affine>,
    pub h: G::Affine,
}

#[derive(Clone)]
pub struct SumCheckCommitmentSetupParameters<G: Curve> {
    pub gen_1: MultiCommitmentSetupParameters<G>,
    pub gen_3: MultiCommitmentSetupParameters<G>,
}

impl<G: Curve> SumCheckCommitmentSetupParameters<G> {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let n = 3;
        let mut generators = Vec::new();
        for _ in 0..n {
            generators.push(G::Projective::rand(rng).into_affine());
        }
        let h = G::Projective::rand(rng).into_affine();
        let gen_3 = MultiCommitmentSetupParameters { n, generators, h };

        let h = G::Projective::rand(rng).into_affine();
        let g = G::Projective::rand(rng).into_affine();
        let gen_1 = MultiCommitmentSetupParameters {
            n: 1,
            generators: vec![g],
            h,
        };

        Self { gen_1, gen_3 }
    }
}

#[derive(Clone)]
pub struct PolyCommitmentSetupParameters<G: Curve> {
    pub n: usize,
    pub gen_n: MultiCommitmentSetupParameters<G>,
    pub gen_1: MultiCommitmentSetupParameters<G>,
}

impl<G: Curve> PolyCommitmentSetupParameters<G> {
    pub fn new<R: Rng>(rng: &mut R, num: usize) -> Self {
        let n = (2usize).pow((num - num / 2) as u32);
        let mut generators = Vec::new();
        for _ in 0..n {
            generators.push(G::Projective::rand(rng).into_affine());
        }
        let h = G::Projective::rand(rng).into_affine();
        let gen_n = MultiCommitmentSetupParameters { n, generators, h };

        let g = G::Projective::rand(rng).into_affine();
        let gen_1 = MultiCommitmentSetupParameters {
            n: 1,
            generators: vec![g],
            h,
        };

        Self { n, gen_n, gen_1 }
    }
}
