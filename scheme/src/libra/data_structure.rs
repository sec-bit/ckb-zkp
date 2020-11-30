use math::fft::DensePolynomial as Polynomial;
use math::PairingEngine;

pub struct Parameters<E: PairingEngine> {
    pub sc_params: SumCheckCommitmentSetupParameters<E>,
    pub pc_params: PolyCommitmentSetupParameters<E>,
}

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
    pub gen_4: MultiCommitmentSetupParameters<E>,
}

#[derive(Clone)]
pub struct PolyCommitmentSetupParameters<E: PairingEngine> {
    pub n: usize,
    pub gen_n: MultiCommitmentSetupParameters<E>,
    pub gen_1: MultiCommitmentSetupParameters<E>,
}

pub struct SumCheckEvalProof<E: PairingEngine> {
    pub d_commit: E::G1Affine,
    pub dot_cd_commit: E::G1Affine,
    pub z: Vec<E::Fr>,
    pub z_delta: E::Fr,
    pub z_beta: E::Fr,
}

pub struct SumCheckProof<E: PairingEngine> {
    pub polys: Vec<Polynomial<E::Fr>>,
    pub poly_value_at_r: Vec<E::Fr>,
}

pub struct LayerProof<E: PairingEngine> {
    pub proof_phase_one: SumCheckProof<E>,
    pub proof_phase_two: SumCheckProof<E>,
}

pub struct LinearGKRProof<E: PairingEngine> {
    pub proofs: Vec<LayerProof<E>>,
}

pub struct ZKSumCheckProof<E: PairingEngine> {
    pub comm_polys: Vec<E::G1Affine>,
    pub comm_evals: Vec<E::G1Affine>,
    pub proofs: Vec<SumCheckEvalProof<E>>,
    pub poly_value_at_r: Vec<E::Fr>,
    pub blind_eval: E::Fr,
}

pub struct ZKLayerProof<E: PairingEngine> {
    pub proof_phase_one: ZKSumCheckProof<E>,
    pub proof_phase_two: ZKSumCheckProof<E>,
}

pub struct ZKLinearGKRProof<E: PairingEngine> {
    pub proofs: Vec<ZKLayerProof<E>>,
}
