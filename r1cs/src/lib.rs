//! A library for rank-one constraint systems.
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused, future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(clippy::op_ref, clippy::suspicious_op_assign_impl)]
#![cfg_attr(not(use_asm), forbid(unsafe_code))]
#![cfg_attr(use_asm, feature(llvm_asm))]
#![cfg_attr(use_asm, deny(unsafe_code))]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use alloc::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "std")]
#[allow(unused_imports)]
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};

use ark_ff::Field;
use ark_serialize::*;
use ark_std::io;
use core::cmp::Ordering;
use smallvec::SmallVec as StackVec;

mod constraint_system;
mod error;
mod impl_constraint_var;
mod impl_lc;

pub use constraint_system::{ConstraintSynthesizer, ConstraintSystem, Namespace};
pub use error::SynthesisError;

type SmallVec<F> = StackVec<[(Variable, F); 16]>;

/// Represents a variable in a constraint system.
#[derive(PartialOrd, Ord, PartialEq, Eq, Copy, Clone, Debug)]
pub struct Variable(Index);

impl Variable {
    /// This constructs a variable with an arbitrary index.
    /// Circuit implementations are not recommended to use this.
    pub fn new_unchecked(idx: Index) -> Variable {
        Variable(idx)
    }

    /// This returns the index underlying the variable.
    /// Circuit implementations are not recommended to use this.
    pub fn get_unchecked(&self) -> Index {
        self.0
    }
}

/// Represents the index of either an input variable or auxiliary variable.
#[derive(Copy, Clone, PartialEq, Debug, Eq)]
pub enum Index {
    /// Index of an input variable.
    Input(usize),
    /// Index of an auxiliary (or private) variable.
    Aux(usize),
}

impl CanonicalSerialize for Index {
    #[inline]
    fn serialize<W: io::Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            Index::Input(u) => {
                0u8.serialize(&mut writer)?;
                u.serialize(&mut writer)?;
            }
            Index::Aux(u) => {
                1u8.serialize(&mut writer)?;
                u.serialize(&mut writer)?;
            }
        }
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        1 + 0usize.serialized_size()
    }

    #[inline]
    fn serialize_uncompressed<W: io::Write>(
        &self,
        mut writer: W,
    ) -> Result<(), SerializationError> {
        match self {
            Index::Input(u) => {
                0u8.serialize(&mut writer)?;
                u.serialize(&mut writer)?;
            }
            Index::Aux(u) => {
                1u8.serialize(&mut writer)?;
                u.serialize(&mut writer)?;
            }
        }
        Ok(())
    }

    #[inline]
    fn serialize_unchecked<W: io::Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            Index::Input(u) => {
                0u8.serialize(&mut writer)?;
                u.serialize(&mut writer)?;
            }
            Index::Aux(u) => {
                1u8.serialize(&mut writer)?;
                u.serialize(&mut writer)?;
            }
        }
        Ok(())
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        1 + 0usize.serialized_size()
    }
}

impl CanonicalDeserialize for Index {
    #[inline]
    fn deserialize<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let t = u8::deserialize(&mut reader)?;
        let u = usize::deserialize(&mut reader)?;
        match t {
            0u8 => Ok(Index::Input(u)),
            _ => Ok(Index::Aux(u)),
        }
    }

    #[inline]
    fn deserialize_uncompressed<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let t = u8::deserialize(&mut reader)?;
        let u = usize::deserialize(&mut reader)?;
        match t {
            0u8 => Ok(Index::Input(u)),
            _ => Ok(Index::Aux(u)),
        }
    }

    #[inline]
    fn deserialize_unchecked<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let t = u8::deserialize(&mut reader)?;
        let u = usize::deserialize(&mut reader)?;
        match t {
            0u8 => Ok(Index::Input(u)),
            _ => Ok(Index::Aux(u)),
        }
    }
}

impl PartialOrd for Index {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Index {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Index::Input(ref idx1), Index::Input(ref idx2))
            | (Index::Aux(ref idx1), Index::Aux(ref idx2)) => idx1.cmp(idx2),
            (Index::Input(_), Index::Aux(_)) => Ordering::Less,
            (Index::Aux(_), Index::Input(_)) => Ordering::Greater,
        }
    }
}

/// This represents a linear combination of some variables, with coefficients
/// in the field `F`.
/// The `(coeff, var)` pairs in a `LinearCombination` are kept sorted according
/// to the index of the variable in its constraint system.
#[derive(Debug, Clone)]
pub struct LinearCombination<F: Field>(pub SmallVec<F>);

/// Either a `Variable` or a `LinearCombination`.
#[derive(Clone, Debug)]
pub enum ConstraintVar<F: Field> {
    /// A wrapper around a `LinearCombination`.
    LC(LinearCombination<F>),
    /// A wrapper around a `Variable`.
    Var(Variable),
}
