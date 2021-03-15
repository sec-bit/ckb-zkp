use zkp_curve::Curve;

#[derive(Debug, Clone)]
pub enum Error {
    TrimmingDegreeTooLarge,
    PolynomialDegreeTooLarge,
    Other,
}

#[derive(Debug, Clone)]
pub struct UniversalParams<C: Curve> {
    pub generators: Vec<C::Affine>,
    pub u: C::Affine,
}

impl<C: Curve> UniversalParams<C> {
    pub fn max_degree(&self) -> usize {
        self.generators.len() - 1
    }
}

#[derive(Debug, Clone)]
pub struct CommitterKey<C: Curve> {
    pub generators: Vec<C::Affine>,
    pub u: C::Affine,
}

impl<C: Curve> CommitterKey<C> {
    pub fn degree(&self) -> usize {
        self.generators.len() - 1
    }
}

pub type VerifierKey<C> = CommitterKey<C>;

#[derive(Clone, Debug)]
pub struct Commitment<C: Curve>(pub C::Affine);

pub struct Proof<C: Curve> {
    pub l: Vec<C::Affine>,
    pub r: Vec<C::Affine>,
}
