use math::fft::DensePolynomial as Polynomial;
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

pub struct SumCheckEvalProof<G: Curve> {
    pub d_commit: G::Affine,
    pub dot_cd_commit: G::Affine,
    pub z: Vec<G::Fr>,
    pub z_delta: G::Fr,
    pub z_beta: G::Fr,
}

pub struct SumCheckProof<G: Curve> {
    pub polys: Vec<Polynomial<G::Fr>>,
    pub poly_value_at_r: Vec<G::Fr>,
}

pub struct LayerProof<G: Curve> {
    pub proof_phase_one: SumCheckProof<G>,
    pub proof_phase_two: SumCheckProof<G>,
}

pub struct LinearGKRProof<G: Curve> {
    pub proofs: Vec<LayerProof<G>>,
}

pub struct ZKSumCheckProof<G: Curve> {
    pub comm_polys: Vec<G::Affine>,
    pub comm_evals: Vec<G::Affine>,
    pub proofs: Vec<SumCheckEvalProof<G>>,
    pub poly_value_at_r: Vec<G::Fr>,
    pub blind_eval: G::Fr,
}

pub struct ZKLayerProof<G: Curve> {
    pub proof_phase_one: ZKSumCheckProof<G>,
    pub proof_phase_two: ZKSumCheckProof<G>,
}

pub struct ZKLinearGKRProof<G: Curve> {
    pub proofs: Vec<ZKLayerProof<G>>,
}
