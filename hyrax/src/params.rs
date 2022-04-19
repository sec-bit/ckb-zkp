use ark_ff::UniformRand;
use ark_serialize::*;
use rand::Rng;
use zkp_curve::{Curve, ProjectiveCurve};

use crate::Vec;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<G: Curve> {
    pub sc_params: SumCheckCommitmentSetupParameters<G>,
    pub pc_params: PolyCommitmentSetupParameters<G>,
}

impl<G: Curve> Parameters<G> {
    pub fn new<R: Rng>(rng: &mut R, num: usize) -> Self {
        let pc_params = PolyCommitmentSetupParameters::new(rng, num);

        let sc_params = SumCheckCommitmentSetupParameters::new(rng, &pc_params.gen_1);
        Self {
            pc_params,
            sc_params,
        }
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SumCheckCommitmentSetupParameters<G: Curve> {
    pub gen_1: MultiCommitmentSetupParameters<G>,
    pub gen_3: MultiCommitmentSetupParameters<G>,
    pub gen_4: MultiCommitmentSetupParameters<G>,
}

impl<G: Curve> SumCheckCommitmentSetupParameters<G> {
    pub fn new<R: Rng>(rng: &mut R, gen_1_pc: &MultiCommitmentSetupParameters<G>) -> Self {
        let gen_1 = MultiCommitmentSetupParameters {
            n: 1,
            generators: gen_1_pc.generators.clone(),
            h: gen_1_pc.h,
        };
        let gen_3 = MultiCommitmentSetupParameters::new(rng, 3);
        let gen_4 = MultiCommitmentSetupParameters::new(rng, 4);

        Self {
            gen_1,
            gen_3,
            gen_4,
        }
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PolyCommitmentSetupParameters<G: Curve> {
    pub n: usize,
    pub gen_n: MultiCommitmentSetupParameters<G>,
    pub gen_1: MultiCommitmentSetupParameters<G>,
}

impl<G: Curve> PolyCommitmentSetupParameters<G> {
    pub fn new<R: Rng>(rng: &mut R, num: usize) -> Self {
        let n = (2usize).pow((num - num / 2) as u32);
        let gen_n = MultiCommitmentSetupParameters::new(rng, n);
        let g = G::Projective::rand(rng).into_affine();
        let gen_1 = MultiCommitmentSetupParameters {
            n: 1,
            generators: vec![g],
            h: gen_n.h,
        };

        Self { n, gen_n, gen_1 }
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MultiCommitmentSetupParameters<G: Curve> {
    pub n: usize,
    pub generators: Vec<G::Affine>,
    pub h: G::Affine,
}

impl<G: Curve> MultiCommitmentSetupParameters<G> {
    pub fn new<R: Rng>(rng: &mut R, n: usize) -> Self {
        let generators = (0..n)
            .map(|_| G::Projective::rand(rng).into_affine())
            .collect::<Vec<G::Affine>>();
        let h = G::Projective::rand(rng).into_affine();
        Self { n, generators, h }
    }
}
