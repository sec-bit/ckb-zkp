use ark_ff::{Field,to_bytes};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_serialize::*;
use zkp_curve::Curve;
use merlin::Transcript;

use crate::Vec;


#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PolyCommitmentParameters<G: Curve> {
    pub n: usize,
    pub gen_n: MultiCommitmentParameters<G>,
    pub gen_1: MultiCommitmentParameters<G>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MultiCommitmentParameters<G: Curve> {
    pub n: usize,
    pub generators: Vec<G::Affine>,
    pub h: G::Affine,
}

impl <G: Curve> MultiCommitmentParameters<G>{
    fn param_to_hash(&self,transcript: &mut Transcript,) {
        transcript.append_u64(b"MultiCommitmentParameters_n", self.n as u64);
        transcript.append_message(b"MultiCommitmentParameters_h", &to_bytes!(self.h).unwrap());
        for i in 0..self.generators.len(){
            transcript.append_message(b"MultiCommitmentParameters_generators", &to_bytes!(self.generators[i]).unwrap());
        }
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SumCheckCommitmentParameters<G: Curve> {
    pub gen_1: MultiCommitmentParameters<G>,
    pub gen_3: MultiCommitmentParameters<G>,
    pub gen_4: MultiCommitmentParameters<G>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSSatisfiedParameters<G: Curve> {
    pub pc_params: PolyCommitmentParameters<G>,
    pub sc_params: SumCheckCommitmentParameters<G>,
    pub n: usize,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSEvalsParameters<G: Curve> {
    pub ops_params: PolyCommitmentParameters<G>,
    pub mem_params: PolyCommitmentParameters<G>,
    pub derefs_params: PolyCommitmentParameters<G>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct NizkParameters<G: Curve> {
    pub r1cs_satisfied_params: R1CSSatisfiedParameters<G>,
}

impl <G: Curve> NizkParameters<G>{
    pub fn param_to_hash(&self)-> G::Fr {
        let mut transcript = Transcript::new(b"Spartan nizk params");
        transcript.append_u64(b"r1cs_satisfied_params_n", self.r1cs_satisfied_params.n as u64);

        transcript.append_u64(b"r1cs_satisfied_params_pc_params_n", self.r1cs_satisfied_params.pc_params.n as u64);
        self.r1cs_satisfied_params.pc_params.gen_n.param_to_hash(&mut transcript);
        self.r1cs_satisfied_params.pc_params.gen_1.param_to_hash(&mut transcript);
        
        self.r1cs_satisfied_params.sc_params.gen_1.param_to_hash(&mut transcript);
        self.r1cs_satisfied_params.sc_params.gen_3.param_to_hash(&mut transcript);
        self.r1cs_satisfied_params.sc_params.gen_4.param_to_hash(&mut transcript);

        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        random_bytes_to_fr::<G>(&buf)
        
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SnarkParameters<G: Curve> {
    pub r1cs_eval_params: R1CSEvalsParameters<G>,
    pub r1cs_satisfied_params: R1CSSatisfiedParameters<G>,
}

impl <G: Curve> SnarkParameters<G>{
    pub fn param_to_hash(&self)-> G::Fr {
        let mut transcript = Transcript::new(b"Spartan snark params");
        transcript.append_u64(b"r1cs_satisfied_params_n", self.r1cs_satisfied_params.n as u64);

        transcript.append_u64(b"r1cs_satisfied_params_pc_params", self.r1cs_satisfied_params.pc_params.n as u64);
        self.r1cs_satisfied_params.pc_params.gen_n.param_to_hash(&mut transcript);
        self.r1cs_satisfied_params.pc_params.gen_1.param_to_hash(&mut transcript);
        
        self.r1cs_satisfied_params.sc_params.gen_1.param_to_hash(&mut transcript);
        self.r1cs_satisfied_params.sc_params.gen_3.param_to_hash(&mut transcript);
        self.r1cs_satisfied_params.sc_params.gen_4.param_to_hash(&mut transcript);

        transcript.append_u64(b"r1cs_eval_params_ops_params_n", self.r1cs_eval_params.ops_params.n as u64);
        self.r1cs_eval_params.ops_params.gen_n.param_to_hash(&mut transcript);
        self.r1cs_eval_params.ops_params.gen_1.param_to_hash(&mut transcript);

        transcript.append_u64(b"r1cs_eval_params_mem_params_n", self.r1cs_eval_params.mem_params.n as u64);
        self.r1cs_eval_params.mem_params.gen_n.param_to_hash(&mut transcript);
        self.r1cs_eval_params.mem_params.gen_1.param_to_hash(&mut transcript);
        
        transcript.append_u64(b"r1cs_eval_params_derefs_params_n", self.r1cs_eval_params.derefs_params.n as u64);
        self.r1cs_eval_params.derefs_params.gen_n.param_to_hash(&mut transcript);
        self.r1cs_eval_params.derefs_params.gen_1.param_to_hash(&mut transcript);
        
        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        random_bytes_to_fr::<G>(&buf)
        
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AddrTimestamps<G: Curve> {
    pub addr_index: Vec<Vec<usize>>,
    pub addrs: Vec<Vec<G::Fr>>,
    pub read_ts_list: Vec<Vec<G::Fr>>,
    pub audit_ts: Vec<G::Fr>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct EncodeCommit<G: Curve> {
    pub n: usize,
    pub m: usize,
    pub ops_commit: Vec<G::Affine>,
    pub mem_commit: Vec<G::Affine>,
}

impl <G: Curve> EncodeCommit<G> {
    pub fn encode_to_hash(&self)->G::Fr{
        let mut transcript = Transcript::new(b"Spartan EncodeCommit");
        
        transcript.append_u64(b"EncodeCommit_n", self.n as u64);
        transcript.append_u64(b"EncodeCommit_m", self.m as u64);

        for commit in self.ops_commit.iter(){ 
            transcript.append_message(b"EncodeCommit_ops_commit", &to_bytes!(commit).unwrap());
        }

        for commit in self.mem_commit.iter(){
            transcript.append_message(b"EncodeCommit_mem_commit", &to_bytes!(commit).unwrap());
        }

 
        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"challenge_nextround", &mut buf);
        random_bytes_to_fr::<G>(&buf)
    }
    
}


#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct EncodeMemory<G: Curve> {
    pub row_addr_ts: AddrTimestamps<G>,
    pub col_addr_ts: AddrTimestamps<G>,
    pub val_list: Vec<Vec<G::Fr>>,
    pub ops_list: Vec<G::Fr>,
    pub mem_list: Vec<G::Fr>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SumCheckEvalProof<G: Curve> {
    pub d_commit: G::Affine,
    pub dot_cd_commit: G::Affine,
    pub z: Vec<G::Fr>,
    pub z_delta: G::Fr,
    pub z_beta: G::Fr,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct NIZKProof<G: Curve> {
    pub r1cs_satisfied_proof: R1CSSatProof<G>,
    pub r: (Vec<G::Fr>, Vec<G::Fr>),
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SNARKProof<G: Curve> {
    pub r1cs_satisfied_proof: R1CSSatProof<G>,
    pub matrix_evals: (G::Fr, G::Fr, G::Fr),
    pub r1cs_evals_proof: R1CSEvalsProof<G>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
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

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSEvalsProof<G: Curve> {
    pub prod_layer_proof: ProductLayerProof<G>,
    pub hash_layer_proof: HashLayerProof<G>,
    pub derefs_commit: Vec<G::Affine>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PolyCommitments<G: Curve> {
    pub commit: G::Affine,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SumCheckProof<G: Curve> {
    pub comm_polys: Vec<G::Affine>,
    pub comm_evals: Vec<G::Affine>,
    pub proofs: Vec<SumCheckEvalProof<G>>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct WitnessProof<G: Curve> {
    pub proof_phase_one_sumcheck: SumCheckProof<G>,
    pub proof_phase_two_sumcheck: SumCheckProof<G>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct KnowledgeProof<G: Curve> {
    pub t_commit: G::Affine,
    pub z1: G::Fr,
    pub z2: G::Fr,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProductProof<G: Curve> {
    pub commit_alpha: G::Affine,
    pub commit_beta: G::Affine,
    pub commit_delta: G::Affine,
    pub z: Vec<G::Fr>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct EqProof<G: Curve> {
    pub alpha: G::Affine,
    pub z: G::Fr,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct InnerProductProof<G: Curve> {
    pub l_vec: Vec<G::Affine>,
    pub r_vec: Vec<G::Affine>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct DotProductProof<G: Curve> {
    pub inner_product_proof: InnerProductProof<G>,
    pub delta: G::Affine,
    pub beta: G::Affine,
    pub z1: G::Fr,
    pub z2: G::Fr,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct KnowledgeProductCommit<G: Curve> {
    pub va_commit: G::Affine,
    pub vb_commit: G::Affine,
    pub vc_commit: G::Affine,
    pub prod_commit: G::Affine,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct KnowledgeProductProof<G: Curve> {
    pub knowledge_proof: KnowledgeProof<G>,
    pub product_proof: ProductProof<G>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct HashForMemoryChecking<G: Curve> {
    pub init_hash: Vec<G::Fr>,
    pub read_ts_hash_list: Vec<Vec<G::Fr>>,
    pub write_ts_hash_list: Vec<Vec<G::Fr>>,
    pub audit_ts_hash: Vec<G::Fr>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProdForMemoryChecking<G: Curve> {
    pub init_prod: ProductCircuit<G>,
    pub read_ts_prod_list: Vec<ProductCircuit<G>>,
    pub write_ts_prod_list: Vec<ProductCircuit<G>>,
    pub audit_ts_prod: ProductCircuit<G>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProductCircuit<G: Curve> {
    pub left_vec: Vec<Vec<G::Fr>>,
    pub right_vec: Vec<Vec<G::Fr>>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MemoryLayer<G: Curve> {
    pub hash: HashForMemoryChecking<G>,
    pub prod: ProdForMemoryChecking<G>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProductLayerProof<G: Curve> {
    pub proof_memory: ProductCircuitEvalProof<G>,
    pub proof_ops: ProductCircuitEvalProof<G>,
    pub eval_dotp: (Vec<G::Fr>, Vec<G::Fr>),
    pub eval_row: (G::Fr, Vec<G::Fr>, Vec<G::Fr>, G::Fr),
    pub eval_col: (G::Fr, Vec<G::Fr>, Vec<G::Fr>, G::Fr),
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct LayerProductCircuitProof<G: Curve> {
    pub polys: Vec<DensePolynomial<G::Fr>>,
    pub claim_prod_left: Vec<G::Fr>,
    pub claim_prod_right: Vec<G::Fr>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProductCircuitEvalProof<G: Curve> {
    pub layers_proof: Vec<LayerProductCircuitProof<G>>,
    pub claim_dotp: (Vec<G::Fr>, Vec<G::Fr>, Vec<G::Fr>),
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
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
