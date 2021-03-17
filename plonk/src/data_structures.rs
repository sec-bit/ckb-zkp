use ark_ff::FftField as Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{BatchLCProof, PolynomialCommitment};

use crate::protocol::{PreprocessorInfo, PreprocessorKeys};

pub type UniversalParams<F, PC> =
    <PC as PolynomialCommitment<F, DensePolynomial<F>>>::UniversalParams;

pub type LabeledPolynomial<F> =
    ark_poly_commit::LabeledPolynomial<F, DensePolynomial<F>>;

pub struct ProverKey<F: Field, PC: PolynomialCommitment<F, DensePolynomial<F>>>
{
    pub vk: VerifierKey<F, PC>,
    pub rands: Vec<PC::Randomness>,

    pub ck: PC::CommitterKey,
    pub keys: PreprocessorKeys<F>,
}

#[derive(Clone)]
pub struct VerifierKey<
    F: Field,
    PC: PolynomialCommitment<F, DensePolynomial<F>>,
> {
    pub comms: Vec<PC::Commitment>,
    pub labels: Vec<String>,
    pub rk: PC::VerifierKey,
    pub info: PreprocessorInfo<F>,
}

impl<F: Field, PC: PolynomialCommitment<F, DensePolynomial<F>>>
    VerifierKey<F, PC>
{
    pub fn clone(&self) -> Self {
        Self {
            comms: self.comms.clone(),
            labels: self.labels.clone(),
            rk: self.rk.clone(),
            info: self.info,
        }
    }
}

pub struct Proof<F: Field, PC: PolynomialCommitment<F, DensePolynomial<F>>> {
    pub commitments: Vec<PC::Commitment>,
    pub evaluations: Vec<F>,
    pub pc_proof: BatchLCProof<F, DensePolynomial<F>, PC>,
}
