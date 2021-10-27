use ark_ec::PairingEngine;
use ark_ff::FftField as Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{ PolynomialCommitment};
use ark_poly_commit::kzg10::Commitment;
use ark_std::{vec::Vec};

use crate::ahp::{Index, IndexInfo};

pub type UniversalParams<E: PairingEngine, PC> =
    <PC as PolynomialCommitment<E::Fr, DensePolynomial<E::Fr>>>::UniversalParams;

pub type LabeledPolynomial<F: Field> = ark_poly_commit::LabeledPolynomial<F, DensePolynomial<F>>;

pub struct ProverKey<E: PairingEngine> {
    pub vk: VerifierKey<E>,
    pub index: Index<E::Fr>,
}

pub struct VerifierKey<E: PairingEngine> {
    pub info: IndexInfo<E::Fr>,
    pub comms: Vec<Commitment<E>>,
}

impl<E: PairingEngine> VerifierKey<E> {
    pub fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            comms: self.comms.clone(),
        }
    }
}

pub struct Proof<E: PairingEngine> {
    pub commitments: Vec<Vec<Commitment<E>>>,
    pub evaluations: Vec<E::Fr>,
    pub pi_w: Commitment<E>,
    pub pi_wz: Commitment<E>,
}
