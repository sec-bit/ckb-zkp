use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, Polynomial};
use ark_std::{borrow::Cow, string::String};

pub enum Error {
    TrimmingDegreeTooLarge,
    PolynomialDegreeTooLarge,
    DegreeIsZero,
    Other,
}

#[derive(Clone, Debug)]
pub struct LabeledPolynomial<'a, F: Field> {
    label: String,
    poly: Cow<'a, DensePolynomial<F>>,
}

impl<'a, F: Field> LabeledPolynomial<'a, F> {
    pub fn degree(&self) -> usize {
        self.poly.degree()
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn polynoimal(&self) -> &DensePolynomial<F> {
        &self.poly
    }
}

#[derive(Clone, Debug)]
pub struct Commitment<E: PairingEngine>(pub E::G1Affine);

#[derive(Clone, Debug)]
pub struct LabeledCommitment<E: PairingEngine> {
    pub label: String,
    pub commitment: Commitment<E>,
}

pub struct UniversalParams<E: PairingEngine> {
    pub powers_of_g: Vec<E::G1Affine>,
}

impl<E: PairingEngine> UniversalParams<E> {
    pub fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }
}

#[derive(Clone, Debug)]
pub struct CommitterKey<E: PairingEngine> {
    pub powers_of_g: Vec<E::G1Affine>,
}

impl<E: PairingEngine> CommitterKey<E> {
    pub fn degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }
}
