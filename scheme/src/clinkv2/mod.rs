use math::{Field, PairingEngine};

pub mod kzg10;
pub mod prover;
pub mod r1cs;

use crate::Vec;
use r1cs::{Index, LinearCombination};

use self::prover::{KZG10_Comm, KZG10_Proof};

/// The proof in Clinkv2.
#[derive(Clone, Debug)]
pub struct Proof<E: PairingEngine> {
    pub r_mid_comms: Vec<KZG10_Comm<E>>,
    pub q_comm: KZG10_Comm<E>,
    pub r_mid_q_values: Vec<E::Fr>,
    pub r_mid_q_proof: KZG10_Proof<E>,
    opening_challenge: E::Fr,
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
