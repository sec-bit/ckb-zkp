use crate::libra::data_structure::{
    MultiCommitmentSetupParameters,
    Parameters,
    PolyCommitmentSetupParameters,
    SumCheckCommitmentSetupParameters, //ZK_SetupParameters,
};
use math::{Curve, ProjectiveCurve, UniformRand};
use rand::Rng;

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

impl<G: Curve> MultiCommitmentSetupParameters<G> {
    pub fn new<R: Rng>(rng: &mut R, n: usize) -> Self {
        let generators = (0..n)
            .map(|_| G::Projective::rand(rng).into_affine())
            .collect::<Vec<G::Affine>>();
        let h = G::Projective::rand(rng).into_affine();
        Self { n, generators, h }
    }
}
