use math::PairingEngine;

use crate::Vec;

use crate::marlin::ahp::indexer::{Index, IndexInfo};
use crate::marlin::pc::{Commitment, CommitterKey, Proof as PCProof, Randomness, VerifierKey};

#[derive(Clone, Debug)]
pub struct IndexVerifierKey<E: PairingEngine> {
    pub index_info: IndexInfo,
    pub index_comms: Vec<Commitment<E>>,
    pub verifier_key: VerifierKey<E>,
}

impl<E: PairingEngine> IndexVerifierKey<E> {
    pub fn iter(&self) -> impl Iterator<Item = &Commitment<E>> {
        self.index_comms.iter()
    }
}

impl<E: PairingEngine> math::ToBytes for IndexVerifierKey<E> {
    #[inline]
    fn write<W: math::io::Write>(&self, mut w: W) -> math::io::Result<()> {
        self.index_info.write(&mut w)?;
        (self.index_comms.len() as u32).write(&mut w)?;
        for i in &self.index_comms {
            i.write(&mut w)?;
        }
        self.verifier_key.write(&mut w)
    }
}

impl<E: PairingEngine> math::FromBytes for IndexVerifierKey<E> {
    #[inline]
    fn read<R: math::io::Read>(mut r: R) -> math::io::Result<Self> {
        let index_info = IndexInfo::read(&mut r)?;
        let mut index_comms = Vec::new();
        let len = u32::read(&mut r)?;
        for _ in 0..len {
            index_comms.push(Commitment::read(&mut r)?);
        }
        let verifier_key = VerifierKey::read(&mut r)?;

        Ok(Self {
            index_info,
            index_comms,
            verifier_key,
        })
    }
}

#[derive(Clone, Debug)]
pub struct IndexProverKey<'a, E: PairingEngine> {
    pub index: Index<'a, E::Fr>,
    pub index_rands: Vec<Randomness<E::Fr>>,
    pub index_verifier_key: IndexVerifierKey<E>,
    pub committer_key: CommitterKey<E>,
}

impl<'a, E: PairingEngine> math::ToBytes for IndexProverKey<'a, E> {
    #[inline]
    fn write<W: math::io::Write>(&self, mut w: W) -> math::io::Result<()> {
        self.index.write(&mut w)?;
        (self.index_rands.len() as u32).write(&mut w)?;
        for i in &self.index_rands {
            i.write(&mut w)?;
        }
        self.index_verifier_key.write(&mut w)?;
        self.committer_key.write(&mut w)
    }
}

impl<'a, E: PairingEngine> math::FromBytes for IndexProverKey<'a, E> {
    #[inline]
    fn read<R: math::io::Read>(mut r: R) -> math::io::Result<Self> {
        let index = Index::read(&mut r)?;

        let mut index_rands = Vec::new();
        let len = u32::read(&mut r)?;
        for _ in 0..len {
            index_rands.push(Randomness::read(&mut r)?);
        }
        let index_verifier_key = IndexVerifierKey::read(&mut r)?;
        let committer_key = CommitterKey::read(&mut r)?;

        Ok(Self {
            index,
            index_rands,
            index_verifier_key,
            committer_key,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Proof<E: PairingEngine> {
    pub commitments: Vec<Vec<Commitment<E>>>,
    pub evaluations: Vec<E::Fr>,
    pub opening_proofs: Vec<PCProof<E>>,
}

impl<E: PairingEngine> math::ToBytes for Proof<E> {
    #[inline]
    fn write<W: math::io::Write>(&self, mut w: W) -> math::io::Result<()> {
        (self.commitments.len() as u32).write(&mut w)?;
        for i in &self.commitments {
            (i.len() as u32).write(&mut w)?;
            for ii in i {
                ii.write(&mut w)?;
            }
        }
        (self.evaluations.len() as u32).write(&mut w)?;
        for i in &self.evaluations {
            i.write(&mut w)?;
        }
        (self.opening_proofs.len() as u32).write(&mut w)?;
        for i in &self.opening_proofs {
            i.write(&mut w)?;
        }
        Ok(())
    }
}

impl<E: PairingEngine> math::FromBytes for Proof<E> {
    #[inline]
    fn read<R: math::io::Read>(mut r: R) -> math::io::Result<Self> {
        let mut commitments = Vec::new();
        let len = u32::read(&mut r)?;
        for _ in 0..len {
            let f_len = u32::read(&mut r)?;
            let mut f_commits = Vec::new();
            for _ in 0..f_len {
                f_commits.push(Commitment::read(&mut r)?);
            }
            commitments.push(f_commits);
        }

        let mut evaluations = Vec::new();
        let e_len = u32::read(&mut r)?;
        for _ in 0..e_len {
            evaluations.push(E::Fr::read(&mut r)?);
        }

        let mut opening_proofs = Vec::new();
        let o_len = u32::read(&mut r)?;
        for _ in 0..o_len {
            opening_proofs.push(PCProof::read(&mut r)?);
        }

        Ok(Self {
            commitments,
            evaluations,
            opening_proofs,
        })
    }
}
