use math::fft::DensePolynomial as Polynomial;
use math::{Curve, Field};

use crate::Vec;

#[derive(Clone, Serialize, Deserialize)]
pub struct PolyCommitmentParameters<G: Curve> {
    pub n: usize,
    pub gen_n: MultiCommitmentParameters<G>,
    pub gen_1: MultiCommitmentParameters<G>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MultiCommitmentParameters<G: Curve> {
    pub n: usize,
    pub generators: Vec<G::Affine>,
    pub h: G::Affine,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SumCheckCommitmentParameters<G: Curve> {
    pub gen_1: MultiCommitmentParameters<G>,
    pub gen_3: MultiCommitmentParameters<G>,
    pub gen_4: MultiCommitmentParameters<G>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct R1CSSatisfiedParameters<G: Curve> {
    pub pc_params: PolyCommitmentParameters<G>,
    pub sc_params: SumCheckCommitmentParameters<G>,
    pub n: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct R1CSEvalsParameters<G: Curve> {
    pub ops_params: PolyCommitmentParameters<G>,
    pub mem_params: PolyCommitmentParameters<G>,
    pub derefs_params: PolyCommitmentParameters<G>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NizkParameters<G: Curve> {
    pub r1cs_satisfied_params: R1CSSatisfiedParameters<G>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SnarkParameters<G: Curve> {
    pub r1cs_eval_params: R1CSEvalsParameters<G>,
    pub r1cs_satisfied_params: R1CSSatisfiedParameters<G>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AddrTimestamps<G: Curve> {
    pub addr_index: Vec<Vec<usize>>,
    pub addrs: Vec<Vec<G::Fr>>,
    pub read_ts_list: Vec<Vec<G::Fr>>,
    pub audit_ts: Vec<G::Fr>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncodeCommit<G: Curve> {
    pub n: usize,
    pub m: usize,
    pub ops_commit: Vec<G::Affine>,
    pub mem_commit: Vec<G::Affine>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncodeMemory<G: Curve> {
    pub row_addr_ts: AddrTimestamps<G>,
    pub col_addr_ts: AddrTimestamps<G>,
    pub val_list: Vec<Vec<G::Fr>>,
    pub ops_list: Vec<G::Fr>,
    pub mem_list: Vec<G::Fr>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SumCheckEvalProof<G: Curve> {
    pub d_commit: G::Affine,
    pub dot_cd_commit: G::Affine,
    pub z: Vec<G::Fr>,
    pub z_delta: G::Fr,
    pub z_beta: G::Fr,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NIZKProof<G: Curve> {
    pub r1cs_satisfied_proof: R1CSSatProof<G>,
    pub r: (Vec<G::Fr>, Vec<G::Fr>),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SNARKProof<G: Curve> {
    pub r1cs_satisfied_proof: R1CSSatProof<G>,
    pub matrix_evals: (G::Fr, G::Fr, G::Fr),
    pub r1cs_evals_proof: R1CSEvalsProof<G>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct R1CSSatProof<G: Curve> {
    pub commit_witness: Vec<G::Affine>,
    pub proof_one: SumCheckProof<G>,
    pub proof_two: SumCheckProof<G>,
    pub w_ry: G::Fr,
    pub product_proof: DotProductProof<G>,
    pub knowledge_product_commit: KnowledgeProductCommit<G>,
    pub knowledge_product_proof: KnowledgeProductProof<G>,
    pub sc1_eq_proof: EqProof<G>,
    pub sc2_eq_proof: EqProof<G>,
    pub commit_ry: G::Affine,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct R1CSEvalsProof<G: Curve> {
    pub prod_layer_proof: ProductLayerProof<G>,
    pub hash_layer_proof: HashLayerProof<G>,
    pub derefs_commit: Vec<G::Affine>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PolyCommitments<G: Curve> {
    pub commit: G::Affine,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SumCheckProof<G: Curve> {
    pub comm_polys: Vec<G::Affine>,
    pub comm_evals: Vec<G::Affine>,
    pub proofs: Vec<SumCheckEvalProof<G>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WitnessProof<G: Curve> {
    pub proof_phase_one_sumcheck: SumCheckProof<G>,
    pub proof_phase_two_sumcheck: SumCheckProof<G>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KnowledgeProof<G: Curve> {
    pub t_commit: G::Affine,
    pub z1: G::Fr,
    pub z2: G::Fr,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProductProof<G: Curve> {
    pub commit_alpha: G::Affine,
    pub commit_beta: G::Affine,
    pub commit_delta: G::Affine,
    pub z: Vec<G::Fr>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EqProof<G: Curve> {
    pub alpha: G::Affine,
    pub z: G::Fr,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InnerProductProof<G: Curve> {
    pub l_vec: Vec<G::Affine>,
    pub r_vec: Vec<G::Affine>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DotProductProof<G: Curve> {
    pub inner_product_proof: InnerProductProof<G>,
    pub delta: G::Affine,
    pub beta: G::Affine,
    pub z1: G::Fr,
    pub z2: G::Fr,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KnowledgeProductCommit<G: Curve> {
    pub va_commit: G::Affine,
    pub vb_commit: G::Affine,
    pub vc_commit: G::Affine,
    pub prod_commit: G::Affine,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KnowledgeProductProof<G: Curve> {
    pub knowledge_proof: KnowledgeProof<G>,
    pub product_proof: ProductProof<G>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HashForMemoryChecking<G: Curve> {
    pub init_hash: Vec<G::Fr>,
    pub read_ts_hash_list: Vec<Vec<G::Fr>>,
    pub write_ts_hash_list: Vec<Vec<G::Fr>>,
    pub audit_ts_hash: Vec<G::Fr>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProdForMemoryChecking<G: Curve> {
    pub init_prod: ProductCircuit<G>,
    pub read_ts_prod_list: Vec<ProductCircuit<G>>,
    pub write_ts_prod_list: Vec<ProductCircuit<G>>,
    pub audit_ts_prod: ProductCircuit<G>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProductCircuit<G: Curve> {
    pub left_vec: Vec<Vec<G::Fr>>,
    pub right_vec: Vec<Vec<G::Fr>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MemoryLayer<G: Curve> {
    pub hash: HashForMemoryChecking<G>,
    pub prod: ProdForMemoryChecking<G>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProductLayerProof<G: Curve> {
    pub proof_memory: ProductCircuitEvalProof<G>,
    pub proof_ops: ProductCircuitEvalProof<G>,
    pub eval_dotp: (Vec<G::Fr>, Vec<G::Fr>),
    pub eval_row: (G::Fr, Vec<G::Fr>, Vec<G::Fr>, G::Fr),
    pub eval_col: (G::Fr, Vec<G::Fr>, Vec<G::Fr>, G::Fr),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LayerProductCircuitProof<G: Curve> {
    pub polys: Vec<Polynomial<G::Fr>>,
    pub claim_prod_left: Vec<G::Fr>,
    pub claim_prod_right: Vec<G::Fr>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProductCircuitEvalProof<G: Curve> {
    pub layers_proof: Vec<LayerProductCircuitProof<G>>,
    pub claim_dotp: (Vec<G::Fr>, Vec<G::Fr>, Vec<G::Fr>),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HashLayerProof<G: Curve> {
    pub proof_derefs: DotProductProof<G>,
    pub proof_ops: DotProductProof<G>,
    pub proof_mem: DotProductProof<G>,
    pub evals_derefs: (Vec<G::Fr>, Vec<G::Fr>),
    pub evals_row: (Vec<G::Fr>, Vec<G::Fr>, G::Fr),
    pub evals_col: (Vec<G::Fr>, Vec<G::Fr>, G::Fr),
    pub evals_val: Vec<G::Fr>,
}

pub fn random_bytes_to_fr<G: Curve>(bytes: &[u8]) -> G::Fr {
    let mut r_bytes = [0u8; 31];
    // only use the first 31 bytes, to avoid value over modulus
    // we could mod modulus here too to keep value in range
    r_bytes.copy_from_slice(&bytes[0..31]);
    let r = <G::Fr as Field>::from_random_bytes(&r_bytes);
    r.unwrap()
}
