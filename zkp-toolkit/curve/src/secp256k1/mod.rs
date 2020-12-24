mod fq;
mod fr;
mod group;

pub use fq::*;
pub use fr::*;
pub use group::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct Secp256k1;

impl math::Curve for Secp256k1 {
    type Fq = Fq;
    type Fr = Fr;
    type Affine = Affine;
    type Projective = Projective;
}

#[cfg(test)]
mod tests;
