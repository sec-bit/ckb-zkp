use crate::Vec;
use math::fft::DensePolynomial as Polynomial;
use math::{Field, PairingEngine};

#[derive(Clone)]
pub struct PolyCommitmentSetupParameters<E: PairingEngine> {
    pub n: usize,
    pub gen_n: MultiCommitmentSetupParameters<E>,
    pub gen_1: MultiCommitmentSetupParameters<E>,
}

#[derive(Clone)]
pub struct MultiCommitmentSetupParameters<E: PairingEngine> {
    pub n: usize,
    pub generators: Vec<E::G1Affine>,
    pub h: E::G1Affine,
}

pub struct SumCheckCommitmentSetupParameters<E: PairingEngine> {
    pub gen_1: MultiCommitmentSetupParameters<E>,
    pub gen_3: MultiCommitmentSetupParameters<E>,
    pub gen_4: MultiCommitmentSetupParameters<E>,
}

pub struct R1CSSatisfiedSetupParameters<E: PairingEngine> {
    pub pc_params: PolyCommitmentSetupParameters<E>,
    pub sc_params: SumCheckCommitmentSetupParameters<E>,
    pub n: usize,
}

pub struct R1CSEvalsSetupParameters<E: PairingEngine> {
    pub ops_params: PolyCommitmentSetupParameters<E>,
    pub mem_params: PolyCommitmentSetupParameters<E>,
    pub derefs_params: PolyCommitmentSetupParameters<E>,
}

pub struct SetupParametersWithSpark<E: PairingEngine> {
    pub r1cs_eval_params: R1CSEvalsSetupParameters<E>,
    pub r1cs_satisfied_params: R1CSSatisfiedSetupParameters<E>,
}

pub struct AddrTimestamps<E: PairingEngine> {
    pub addr_index: Vec<Vec<usize>>,
    pub addrs: Vec<Vec<E::Fr>>,
    pub read_ts_list: Vec<Vec<E::Fr>>,
    pub audit_ts: Vec<E::Fr>,
}

pub struct EncodeCommit<E: PairingEngine> {
    pub n: usize,
    pub m: usize,
    pub ops_commit: Vec<E::G1Affine>,
    pub mem_commit: Vec<E::G1Affine>,
}

pub struct EncodeMemory<E: PairingEngine> {
    pub row_addr_ts: AddrTimestamps<E>,
    pub col_addr_ts: AddrTimestamps<E>,
    pub val_list: Vec<Vec<E::Fr>>,
    pub ops_list: Vec<E::Fr>,
    pub mem_list: Vec<E::Fr>,
}

pub struct SumCheckEvalProof<E: PairingEngine> {
    pub d_commit: E::G1Affine,
    pub dot_cd_commit: E::G1Affine,
    pub z: Vec<E::Fr>,
    pub z_delta: E::Fr,
    pub z_beta: E::Fr,
}

pub struct NIZKProof<E: PairingEngine> {
    pub r1cs_satisfied_proof: R1CSSatProof<E>,
    pub r: (Vec<E::Fr>, Vec<E::Fr>),
}

pub struct SNARKProof<E: PairingEngine> {
    pub r1cs_satisfied_proof: R1CSSatProof<E>,
    pub matrix_evals: (E::Fr, E::Fr, E::Fr),
    pub r1cs_evals_proof: R1CSEvalsProof<E>,
}

pub struct R1CSSatProof<E: PairingEngine> {
    pub commit_witness: Vec<E::G1Affine>,
    pub proof_one: SumCheckProof<E>,
    pub proof_two: SumCheckProof<E>,
    pub w_ry: E::Fr,
    pub product_proof: DotProductProof<E>,
    pub knowledge_product_commit: KnowledgeProductCommit<E>,
    pub knowledge_product_proof: KnowledgeProductProof<E>,
    pub sc1_eq_proof: EqProof<E>,
    pub sc2_eq_proof: EqProof<E>,
    pub commit_ry: E::G1Affine,
}

pub struct R1CSEvalsProof<E: PairingEngine> {
    pub prod_layer_proof: ProductLayerProof<E>,
    pub hash_layer_proof: HashLayerProof<E>,
    pub derefs_commit: Vec<E::G1Affine>,
}

pub struct PolyCommitments<E: PairingEngine> {
    pub commit: E::G1Affine,
}

pub struct SumCheckProof<E: PairingEngine> {
    pub comm_polys: Vec<E::G1Affine>,
    pub comm_evals: Vec<E::G1Affine>,
    pub proofs: Vec<SumCheckEvalProof<E>>,
    // pub r: Vec<E::Fr>,
    pub polys_value_at_r: Vec<E::Fr>,
    pub blinds_eval: E::Fr,
}

pub struct WitnessProof<E: PairingEngine> {
    pub proof_phase_one_sumcheck: SumCheckProof<E>,
    pub proof_phase_two_sumcheck: SumCheckProof<E>,
}

pub struct KnowledgeProof<E: PairingEngine> {
    pub t_commit: E::G1Affine,
    pub z1: E::Fr,
    pub z2: E::Fr,
}

pub struct ProductProof<E: PairingEngine> {
    pub commit_alpha: E::G1Affine,
    pub commit_beta: E::G1Affine,
    pub commit_delta: E::G1Affine,
    pub z: Vec<E::Fr>,
}

pub struct EqProof<E: PairingEngine> {
    pub alpha: E::G1Affine,
    pub z: E::Fr,
}

pub struct InnerProductProof<E: PairingEngine> {
    pub l_vec: Vec<E::G1Affine>,
    pub r_vec: Vec<E::G1Affine>,
}

pub struct DotProductProof<E: PairingEngine> {
    pub inner_product_proof: InnerProductProof<E>,
    pub delta: E::G1Affine,
    pub beta: E::G1Affine,
    pub z1: E::Fr,
    pub z2: E::Fr,
}

pub struct KnowledgeProductCommit<E: PairingEngine> {
    pub va_commit: E::G1Affine,
    pub vb_commit: E::G1Affine,
    pub vc_commit: E::G1Affine,
    pub prod_commit: E::G1Affine,
}

pub struct KnowledgeProductProof<E: PairingEngine> {
    pub knowledge_proof: KnowledgeProof<E>,
    pub product_proof: ProductProof<E>,
}

pub struct HashForMemoryChecking<E: PairingEngine> {
    pub init_hash: Vec<E::Fr>,
    pub read_ts_hash_list: Vec<Vec<E::Fr>>,
    pub write_ts_hash_list: Vec<Vec<E::Fr>>,
    pub audit_ts_hash: Vec<E::Fr>,
}

pub struct ProdForMemoryChecking<E: PairingEngine> {
    pub init_prod: ProductCircuit<E>,
    pub read_ts_prod_list: Vec<ProductCircuit<E>>,
    pub write_ts_prod_list: Vec<ProductCircuit<E>>,
    pub audit_ts_prod: ProductCircuit<E>,
}

#[derive(Clone)]
pub struct ProductCircuit<E: PairingEngine> {
    pub left_vec: Vec<Vec<E::Fr>>,
    pub right_vec: Vec<Vec<E::Fr>>,
}

pub struct MemoryLayer<E: PairingEngine> {
    pub hash: HashForMemoryChecking<E>,
    pub prod: ProdForMemoryChecking<E>,
}

pub struct ProductLayerProof<E: PairingEngine> {
    pub proof_memory: ProductCircuitEvalProof<E>,
    pub proof_ops: ProductCircuitEvalProof<E>,
    pub eval_dotp: (Vec<E::Fr>, Vec<E::Fr>),
    pub eval_row: (E::Fr, Vec<E::Fr>, Vec<E::Fr>, E::Fr),
    pub eval_col: (E::Fr, Vec<E::Fr>, Vec<E::Fr>, E::Fr),
}

pub struct LayerProductCircuitProof<E: PairingEngine> {
    pub polys: Vec<Polynomial<E::Fr>>,
    pub claim_prod_left: Vec<E::Fr>,
    pub claim_prod_right: Vec<E::Fr>,
}

pub struct ProductCircuitEvalProof<E: PairingEngine> {
    pub layers_proof: Vec<LayerProductCircuitProof<E>>,
    pub claim_dotp: (Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>),
}

pub struct HashLayerProof<E: PairingEngine> {
    pub proof_derefs: DotProductProof<E>,
    pub proof_ops: DotProductProof<E>,
    pub proof_mem: DotProductProof<E>,
    pub evals_derefs: (Vec<E::Fr>, Vec<E::Fr>),
    pub evals_row: (Vec<E::Fr>, Vec<E::Fr>, E::Fr),
    pub evals_col: (Vec<E::Fr>, Vec<E::Fr>, E::Fr),
    pub evals_val: Vec<E::Fr>,
}

pub fn random_bytes_to_fr<E: PairingEngine>(bytes: &[u8]) -> E::Fr {
    let mut r_bytes = [0u8; 31];
    // only use the first 31 bytes, to avoid value over modulus
    // we could mod modulus here too to keep value in range
    r_bytes.copy_from_slice(&bytes[0..31]);
    let r = <E::Fr as Field>::from_random_bytes(&r_bytes);
    r.unwrap()
}
