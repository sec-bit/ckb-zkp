use math::{
    bytes::{FromBytes, ToBytes},
    io::{self, Result as IoResult},
    serialize::*,
    Field, PairingEngine,
};

use crate::r1cs::{Index, LinearCombination, SynthesisError};
use crate::Vec;

/// Reduce an R1CS instance to a *Quadratic Arithmetic Program* instance.
pub mod r1cs_to_qap;

/// Generate public parameters for the Groth16 zkSNARK construction.
pub mod generator;

/// Create proofs for the Groth16 zkSNARK construction.
pub mod prover;

/// Verify proofs for the Groth16 zkSNARK construction.
pub mod verifier;

#[cfg(test)]
mod test;

pub use self::{generator::*, prover::*, verifier::*};

/// A proof in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: PairingEngine> {
    pub a: E::G1Affine,
    pub b: E::G2Affine,
    pub c: E::G1Affine,
}

impl<E: PairingEngine> ToBytes for Proof<E> {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.a.write(&mut writer)?;
        self.b.write(&mut writer)?;
        self.c.write(&mut writer)
    }
}

impl<E: PairingEngine> FromBytes for Proof<E> {
    #[inline]
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let a = E::G1Affine::read(&mut reader)?;
        let b = E::G2Affine::read(&mut reader)?;
        let c = E::G1Affine::read(reader)?;
        Ok(Self { a, b, c })
    }
}

impl<E: PairingEngine> Default for Proof<E> {
    fn default() -> Self {
        Self {
            a: E::G1Affine::default(),
            b: E::G2Affine::default(),
            c: E::G1Affine::default(),
        }
    }
}

/// A verification key in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<E: PairingEngine> {
    pub alpha_g1: E::G1Affine,
    pub beta_g2: E::G2Affine,
    pub gamma_g2: E::G2Affine,
    pub delta_g2: E::G2Affine,
    pub gamma_abc_g1: Vec<E::G1Affine>,
}

impl<E: PairingEngine> ToBytes for VerifyingKey<E> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.alpha_g1.write(&mut writer)?;
        self.beta_g2.write(&mut writer)?;
        self.gamma_g2.write(&mut writer)?;
        self.delta_g2.write(&mut writer)?;
        (self.gamma_abc_g1.len() as u64).write(&mut writer)?;
        for q in &self.gamma_abc_g1 {
            q.write(&mut writer)?;
        }
        Ok(())
    }
}

impl<E: PairingEngine> FromBytes for VerifyingKey<E> {
    #[inline]
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let alpha_g1 = E::G1Affine::read(&mut reader)?;
        let beta_g2 = E::G2Affine::read(&mut reader)?;
        let gamma_g2 = E::G2Affine::read(&mut reader)?;
        let delta_g2 = E::G2Affine::read(&mut reader)?;
        let g_len = u64::read(&mut reader).unwrap();
        let mut gamma_abc_g1 = vec![];
        for _ in 0..g_len {
            let v = E::G1Affine::read(&mut reader)?;
            gamma_abc_g1.push(v);
        }

        Ok(Self {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        })
    }
}

impl<E: PairingEngine> Default for VerifyingKey<E> {
    fn default() -> Self {
        Self {
            alpha_g1: E::G1Affine::default(),
            beta_g2: E::G2Affine::default(),
            gamma_g2: E::G2Affine::default(),
            delta_g2: E::G2Affine::default(),
            gamma_abc_g1: Vec::new(),
        }
    }
}

/// Full public (prover and verifier) parameters for the Groth16 zkSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<E: PairingEngine> {
    pub vk: VerifyingKey<E>,
    pub beta_g1: E::G1Affine,
    pub delta_g1: E::G1Affine,
    pub a_query: Vec<E::G1Affine>,
    pub b_g1_query: Vec<E::G1Affine>,
    pub b_g2_query: Vec<E::G2Affine>,
    pub h_query: Vec<E::G1Affine>,
    pub l_query: Vec<E::G1Affine>,
}

impl<E: PairingEngine> ToBytes for Parameters<E> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.vk.write(&mut writer)?;
        self.beta_g1.write(&mut writer)?;
        self.delta_g1.write(&mut writer)?;
        (self.a_query.len() as u64).write(&mut writer)?;
        self.a_query.write(&mut writer)?;
        (self.b_g1_query.len() as u64).write(&mut writer)?;
        self.b_g1_query.write(&mut writer)?;
        (self.b_g2_query.len() as u64).write(&mut writer)?;
        self.b_g2_query.write(&mut writer)?;
        (self.h_query.len() as u64).write(&mut writer)?;
        self.h_query.write(&mut writer)?;
        (self.l_query.len() as u64).write(&mut writer)?;
        self.l_query.write(&mut writer)?;

        Ok(())
    }
}
impl<E: PairingEngine> FromBytes for Parameters<E> {
    #[inline]
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let vk = VerifyingKey::<E>::read(&mut reader)?;
        let beta_g1 = E::G1Affine::read(&mut reader)?;
        let delta_g1 = E::G1Affine::read(&mut reader)?;

        let a_query_len = u64::read(&mut reader).unwrap();
        let mut a_query = vec![];
        for _ in 0..a_query_len {
            a_query.push(E::G1Affine::read(&mut reader)?);
        }

        let b_g1_query_len = u64::read(&mut reader).unwrap();
        let mut b_g1_query = vec![];
        for _ in 0..b_g1_query_len {
            b_g1_query.push(E::G1Affine::read(&mut reader)?);
        }

        let b_g2_query_len = u64::read(&mut reader).unwrap();
        let mut b_g2_query = vec![];
        for _ in 0..b_g2_query_len {
            b_g2_query.push(E::G2Affine::read(&mut reader)?);
        }

        let h_query_len = u64::read(&mut reader).unwrap();
        let mut h_query = vec![];
        for _ in 0..h_query_len {
            h_query.push(E::G1Affine::read(&mut reader)?);
        }

        let l_query_len = u64::read(&mut reader).unwrap();
        let mut l_query = vec![];
        for _ in 0..l_query_len {
            l_query.push(E::G1Affine::read(&mut reader)?);
        }

        Ok(Self {
            vk,
            beta_g1,
            delta_g1,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        })
    }
}

/// Preprocessed verification key parameters that enable faster verification
/// at the expense of larger size in memory.
#[derive(Clone, Debug, PartialEq)]
pub struct PreparedVerifyingKey<E: PairingEngine> {
    pub vk: VerifyingKey<E>,
    pub alpha_g1_beta_g2: E::Fqk,
    pub gamma_g2_neg_pc: E::G2Prepared,
    pub delta_g2_neg_pc: E::G2Prepared,
    pub gamma_abc_g1: Vec<E::G1Affine>,
}

impl<E: PairingEngine> From<PreparedVerifyingKey<E>> for VerifyingKey<E> {
    fn from(other: PreparedVerifyingKey<E>) -> Self {
        other.vk
    }
}

impl<E: PairingEngine> From<VerifyingKey<E>> for PreparedVerifyingKey<E> {
    fn from(other: VerifyingKey<E>) -> Self {
        prepare_verifying_key(&other)
    }
}

impl<E: PairingEngine> Default for PreparedVerifyingKey<E> {
    fn default() -> Self {
        Self {
            vk: VerifyingKey::default(),
            alpha_g1_beta_g2: E::Fqk::default(),
            gamma_g2_neg_pc: E::G2Prepared::default(),
            delta_g2_neg_pc: E::G2Prepared::default(),
            gamma_abc_g1: Vec::new(),
        }
    }
}

impl<E: PairingEngine> ToBytes for PreparedVerifyingKey<E> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.vk.write(&mut writer)?;
        self.alpha_g1_beta_g2.write(&mut writer)?;
        self.gamma_g2_neg_pc.write(&mut writer)?;
        self.delta_g2_neg_pc.write(&mut writer)?;
        for q in &self.gamma_abc_g1 {
            q.write(&mut writer)?;
        }
        Ok(())
    }
}

impl<E: PairingEngine> FromBytes for PreparedVerifyingKey<E> {
    #[inline]
    fn read<R: Read>(mut _reader: R) -> IoResult<Self> {
        unimplemented!()
    }
}

fn push_constraints<F: Field>(
    l: LinearCombination<F>,
    constraints: &mut [Vec<(F, Index)>],
    this_constraint: usize,
) {
    for (var, coeff) in l.as_ref() {
        match var.get_unchecked() {
            Index::Input(i) => constraints[this_constraint].push((*coeff, Index::Input(i))),
            Index::Aux(i) => constraints[this_constraint].push((*coeff, Index::Aux(i))),
        }
    }
}

impl<E: PairingEngine> Parameters<E> {
    pub fn get_vk(&self, _: usize) -> Result<VerifyingKey<E>, SynthesisError> {
        Ok(self.vk.clone())
    }

    pub fn get_a_query(
        &self,
        num_inputs: usize,
    ) -> Result<(&[E::G1Affine], &[E::G1Affine]), SynthesisError> {
        Ok((&self.a_query[1..num_inputs], &self.a_query[num_inputs..]))
    }

    pub fn get_b_g1_query(
        &self,
        num_inputs: usize,
    ) -> Result<(&[E::G1Affine], &[E::G1Affine]), SynthesisError> {
        Ok((
            &self.b_g1_query[1..num_inputs],
            &self.b_g1_query[num_inputs..],
        ))
    }

    pub fn get_b_g2_query(
        &self,
        num_inputs: usize,
    ) -> Result<(&[E::G2Affine], &[E::G2Affine]), SynthesisError> {
        Ok((
            &self.b_g2_query[1..num_inputs],
            &self.b_g2_query[num_inputs..],
        ))
    }

    pub fn get_h_query(
        &self,
        num_inputs: usize,
    ) -> Result<(&[E::G1Affine], &[E::G1Affine]), SynthesisError> {
        Ok((&self.h_query[0..num_inputs], &self.h_query[num_inputs..]))
    }

    pub fn get_a_query_full(&self) -> Result<&[E::G1Affine], SynthesisError> {
        Ok(&self.a_query)
    }

    pub fn get_b_g1_query_full(&self) -> Result<&[E::G1Affine], SynthesisError> {
        Ok(&self.b_g1_query)
    }

    pub fn get_b_g2_query_full(&self) -> Result<&[E::G2Affine], SynthesisError> {
        Ok(&self.b_g2_query)
    }

    pub fn get_h_query_full(&self) -> Result<&[E::G1Affine], SynthesisError> {
        Ok(&self.h_query)
    }

    pub fn get_l_query_full(&self) -> Result<&[E::G1Affine], SynthesisError> {
        Ok(&self.l_query)
    }
}
