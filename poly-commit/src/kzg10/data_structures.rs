use ark_ec::PairingEngine;

pub enum Error {
    TrimmingDegreeTooLarge,
    PolynomialDegreeTooLarge,
}

#[derive(Clone, Debug)]
pub struct Commitment<E: PairingEngine>(pub E::G1Affine);

pub struct UniversalParams<E: PairingEngine> {
    pub powers_of_g: Vec<E::G1Affine>,
    pub h: E::G2Affine,
    pub beta_h: E::G2Affine,
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

#[derive(Clone, Debug)]
pub struct VerifierKey<E: PairingEngine> {
    pub g: E::G1Affine,
    pub h: E::G2Affine,
    pub beta_h: E::G2Affine,

    pub degree: usize,
}

#[derive(Clone, Debug)]
pub struct Proof<E: PairingEngine> {
    pub w: E::G1Affine,
}
