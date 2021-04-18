use ark_ff::FftField as Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{BatchLCProof, PolynomialCommitment};
use ark_serialize::*;
use ark_std::{string::String, vec::Vec};

use crate::ahp::{Index, IndexInfo};

pub type UniversalParams<F, PC> =
    <PC as PolynomialCommitment<F, DensePolynomial<F>>>::UniversalParams;

pub type LabeledPolynomial<F> = ark_poly_commit::LabeledPolynomial<F, DensePolynomial<F>>;

pub struct ProverKey<F: Field, PC: PolynomialCommitment<F, DensePolynomial<F>>> {
    pub vk: VerifierKey<F, PC>,
    pub rands: Vec<PC::Randomness>,
    pub index: Index<F>,
    pub ck: PC::CommitterKey,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierKey<F: Field, PC: PolynomialCommitment<F, DensePolynomial<F>>> {
    pub info: IndexInfo<F>,
    pub comms: Vec<PC::Commitment>,
    pub labels: Vec<String>,
    pub rk: PC::VerifierKey,
}

impl<F: Field, PC: PolynomialCommitment<F, DensePolynomial<F>>> VerifierKey<F, PC> {
    pub fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            comms: self.comms.clone(),
            labels: self.labels.clone(),
            rk: self.rk.clone(),
        }
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<F: Field, PC: PolynomialCommitment<F, DensePolynomial<F>>> {
    pub commitments: Vec<Vec<PC::Commitment>>,
    pub evaluations: Vec<F>,
    pub pc_proof: BatchLCProof<F, DensePolynomial<F>, PC>,
}
