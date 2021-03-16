use ark_ff::FftField as Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;

use crate::protocol::{PreprocessorInfo, PreprocessorKeys};

pub type UniversalParams<F, PC> =
    <PC as PolynomialCommitment<F, DensePolynomial<F>>>::UniversalParams;

pub type LabeledPolynomial<F> =
    ark_poly_commit::LabeledPolynomial<F, DensePolynomial<F>>;

pub struct ProverKey<
    F: Field,
    PC: PolynomialCommitment<F, DensePolynomial<F>>,
> {
    pub keys: PreprocessorKeys<F>,
    pub rands: Vec<PC::Randomness>,
    pub ck: PC::CommitterKey,
}

pub struct VerifierKey<
    F: Field,
    PC: PolynomialCommitment<F, DensePolynomial<F>>,
> {
    pub info: PreprocessorInfo<F>,
    pub comms: Vec<PC::Commitment>,
    pub rk: PC::VerifierKey,
}

pub struct Proof<F: Field, PC: PolynomialCommitment<F, DensePolynomial<F>>>
{
    pub commitments: Vec<PC::Commitment>,
    pub evaluations: Vec<F>,
    pub pc_proof: PC::BatchProof,
}
