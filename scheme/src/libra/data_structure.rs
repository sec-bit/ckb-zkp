// use math::fft::DensePolynomial as Polynomial;
use math::Curve;

pub struct Parameters<G: Curve> {
    pub sc_params: SumCheckCommitmentSetupParameters<G>,
    pub pc_params: PolyCommitmentSetupParameters<G>,
}

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
    pub gen_4: MultiCommitmentSetupParameters<G>,
}

#[derive(Clone)]
pub struct PolyCommitmentSetupParameters<G: Curve> {
    pub n: usize,
    pub gen_n: MultiCommitmentSetupParameters<G>,
    pub gen_1: MultiCommitmentSetupParameters<G>,
}
