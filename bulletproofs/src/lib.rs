//! An implementation of the [`Bulletproofs`].
//!
//! [`Bulletproofs`]: https://eprint.iacr.org/2017/1066.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused, future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(clippy::op_ref, clippy::suspicious_op_assign_impl)]
#![cfg_attr(not(use_asm), forbid(unsafe_code))]
#![cfg_attr(use_asm, feature(llvm_asm))]
#![cfg_attr(use_asm, deny(unsafe_code))]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{collections::BTreeMap, string::String, vec::Vec};

use ark_ff::Field;
use zkp_curve::Curve;
use zkp_r1cs::{Index, LinearCombination};

pub mod arithmetic_circuit;
pub mod inner_product_proof;

/// standard interface for create proof.
pub use arithmetic_circuit::create_random_proof;

/// standard interface for verify proof.
pub use arithmetic_circuit::verify_proof;

pub use arithmetic_circuit::{Generators, Proof, R1csCircuit};

// Q (vector, zQ) * Qxn (matrix, WL, WR, WO) = n (vector, zQW)
pub fn vector_matrix_product<F: Field>(v: &Vec<F>, m: &Vec<Vec<F>>) -> Vec<F> {
    let n = m[0].len();
    let mut out = vec![F::zero(); n];
    assert_eq!(v.len(), m.len(), "len of v and m must be equal");

    for row in 0..m.len() {
        if m[row].len() != n {
            panic!("matrix_vector_product(v,m): lengths of vectors do not match");
        }
    }
    for col in 0..n {
        for row in 0..v.len() {
            out[col] += &(v[row] * &(m[row][col])); // z_i * w_ij
        }
    }
    out
}

// Q (vector, zQ) * Qxn (matrix, WL, WR, WO) = n (vector, zQW)
pub fn vector_map_product<F: Field>(v: &Vec<F>, ms: &BTreeMap<(u32, u32), F>, n: usize) -> Vec<F> {
    let zero = F::zero();
    let mut out = vec![zero; n];

    for col in 0..n {
        for row in 0..v.len() {
            out[col] += &(v[row] * ms.get(&(row as u32, col as u32)).unwrap_or(&zero));
            // z_i * w_ij
        }
    }
    out
}

// Q (vector, zQ) * Qxn (matrix, WL, WR, WO) = n (vector, zQW)
pub fn vector_product<F: Field>(v: &Vec<F>, ms: &Vec<F>, m: usize, n: usize) -> Vec<F> {
    let zero = F::zero();
    let mut out = vec![zero; m];
    assert_eq!(v.len(), n, "len of v and m must be equal");

    for col in 0..m {
        for row in 0..v.len() {
            out[col] += &(v[row] * (if row == col { &ms[row] } else { &zero }));
            // z_i * w_ij
        }
    }
    out
}

// n (vector, aL/aR/aO) * Qxn (matrix, WL, WR, WO) = Q (vector, wLaL)
pub fn vector_matrix_product_t<F: Field>(v: &Vec<F>, m: &Vec<Vec<F>>) -> Vec<F> {
    let q = m.len();
    let mut out = vec![F::zero(); q];

    for row in 0..q {
        if m[row].len() != v.len() {
            panic!("matrix_vector_product_T(v,m): lengths of vectors do not match");
        }
        for col in 0..v.len() {
            out[row] += &(m[row][col] * &(v[col])); // w_ij * a_j
        }
    }
    out
}

pub fn hadamard_product<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    if a.len() != b.len() {
        panic!("hadamard_product(a,b): lengths of vectors do not match");
    }
    let mut out = vec![F::zero(); a.len()];
    for i in 0..a.len() {
        out[i] = a[i] * &(b[i]);
    }
    out
}

/// Computes an inner product of two vectors
/// \\[
///    {\langle {\mathbf{a}}, {\mathbf{b}} \rangle} = \sum\_{i=0}^{n-1} a\_i \cdot b\_i.
/// \\]
/// Panics if the lengths of \\(\mathbf{a}\\) and \\(\mathbf{b}\\) are not equal.
pub fn inner_product<F: Field>(a: &[F], b: &[F]) -> F {
    let mut out = F::zero();
    if a.len() != b.len() {
        panic!("inner_product(a,b): lengths of vectors do not match");
    }
    for i in 0..a.len() {
        out += &(a[i] * &(b[i]));
    }
    out
}

/// Represents a degree-3 vector polynomial
/// \\(\mathbf{a} + \mathbf{b} \cdot x + \mathbf{c} \cdot x^2 + \mathbf{d} \cdot x^3 \\).
pub struct VecPoly3<F: Field>(pub Vec<F>, pub Vec<F>, pub Vec<F>, pub Vec<F>);

impl<F: Field> VecPoly3<F> {
    pub fn zero(n: usize) -> Self {
        VecPoly3(
            vec![F::zero(); n], // degree-0
            vec![F::zero(); n], // degree-1
            vec![F::zero(); n], // degree-2
            vec![F::zero(); n], // degree-3
        )
    }

    pub fn eval(&self, x: F) -> Vec<F> {
        let n = self.0.len();
        let mut out = vec![F::zero(); n];
        for i in 0..n {
            out[i] = self.0[i] + &(x * &(self.1[i] + &(x * &(self.2[i] + &(x * &(self.3[i]))))));
        }
        out
    }

    pub fn special_inner_product(lhs: &Self, rhs: &Self) -> Poly6<F> {
        let t1 = inner_product::<F>(&lhs.1, &rhs.0);
        let t2 = inner_product::<F>(&lhs.1, &rhs.1) + &(inner_product::<F>(&lhs.2, &rhs.0));
        let t3 = inner_product::<F>(&lhs.2, &rhs.1) + &(inner_product::<F>(&lhs.3, &rhs.0));
        let t4 = inner_product::<F>(&lhs.1, &rhs.3) + &(inner_product::<F>(&lhs.3, &rhs.1));
        let t5 = inner_product::<F>(&lhs.2, &rhs.3);
        let t6 = inner_product::<F>(&lhs.3, &rhs.3);

        Poly6 {
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
        }
    }
}

/// Represents a degree-3 scalar polynomial, without the zeroth degree
/// \\(a \cdot x + b \cdot x^2 + c \cdot x^3 + d \cdot x^4 + e \cdot x^5 + f \cdot x^6 \\)
pub struct Poly6<F: Field> {
    pub t1: F,
    pub t2: F,
    pub t3: F,
    pub t4: F,
    pub t5: F,
    pub t6: F,
}

impl<F: Field> Poly6<F> {
    pub fn eval(&self, x: F) -> F {
        x * &(self.t1
            + &(x * &(self.t2
                + &(x * &(self.t3 + &(x * &(self.t4 + &(x * &(self.t5 + &(x * &self.t6))))))))))
    }
}

/// Represents a degree-5 vector polynomial
/// \\(\mathbf{a} + \mathbf{b} \cdot x + \mathbf{c} \cdot x^2 + \mathbf{d} \cdot x^3 + \mathbf{e} \cdot x^4 + \mathbf{f} \cdot x^5 \\).
pub struct VecPoly5<F: Field>(
    pub Vec<F>,
    pub Vec<F>,
    pub Vec<F>,
    pub Vec<F>,
    pub Vec<F>,
    pub Vec<F>,
);

impl<F: Field> VecPoly5<F> {
    pub fn zero(n: usize) -> Self {
        VecPoly5(
            vec![F::zero(); n], // degree-0
            vec![F::zero(); n], // degree-1
            vec![F::zero(); n], // degree-2
            vec![F::zero(); n], // degree-3
            vec![F::zero(); n], // degree-4
            vec![F::zero(); n], // degree-5
        )
    }

    pub fn eval(&self, x: F) -> Vec<F> {
        let n = self.0.len();
        let mut out = vec![F::zero(); n];
        for i in 0..n {
            out[i] = self.0[i]
                + &(x * &(self.1[i]
                    + &(x * &(self.2[i]
                        + &(x * &(self.3[i] + &(x * &(self.4[i] + &(x * &(self.5[i]))))))))));
        }
        out
    }

    pub fn special_inner_product(lhs: &Self, rhs: &Self) -> Poly10<F> {
        // lhs: 2, 3, 4, 5 || rhs: 2, 1, 0, 5
        let t2 = inner_product::<F>(&lhs.2, &rhs.0);
        let t3 = inner_product::<F>(&lhs.2, &rhs.1) + &inner_product::<F>(&lhs.3, &rhs.0);
        let t4 = inner_product::<F>(&lhs.2, &rhs.2)
            + &inner_product::<F>(&lhs.3, &rhs.1)
            + &inner_product::<F>(&lhs.4, &rhs.0);
        let t5 = inner_product::<F>(&lhs.3, &rhs.2)
            + &inner_product::<F>(&lhs.4, &rhs.1)
            + &inner_product::<F>(&lhs.5, &rhs.0);
        let t6 = inner_product::<F>(&lhs.4, &rhs.2) + &inner_product::<F>(&lhs.5, &rhs.1);
        let t7 = inner_product::<F>(&lhs.2, &rhs.5) + &inner_product::<F>(&lhs.5, &rhs.2);
        let t8 = inner_product::<F>(&lhs.3, &rhs.5);
        let t9 = inner_product::<F>(&lhs.4, &rhs.5);
        let t10 = inner_product::<F>(&lhs.5, &rhs.5);

        Poly10 {
            t2,
            t3,
            t4,
            t5,
            t6,
            t7,
            t8,
            t9,
            t10,
        }
    }
}

/// Represents a degree-10 scalar polynomial, without the zeroth and 1st degree
/// \\(a \cdot x^2 + b \cdot x^3 + c \cdot x^4 + d \cdot x^5 + e \cdot x^6 + f \cdot x^7 + g \cdot x^8 + h \cdot x^9 + i \cdot x^10 \\)
pub struct Poly10<F: Field> {
    pub t2: F,
    pub t3: F,
    pub t4: F,
    pub t5: F,
    pub t6: F,
    pub t7: F,
    pub t8: F,
    pub t9: F,
    pub t10: F,
}

impl<F: Field> Poly10<F> {
    pub fn eval(&self, x: F) -> F {
        // x * (self.t1 + x * (self.t2
        x * &(x * &(self.t2
            + &(x * &(self.t3
                + &(x * &(self.t4
                    + &(x * &(self.t5
                        + &(x * &(self.t6
                            + &(x * &(self.t7
                                + &(x * &(self.t8
                                    + &(x * &(self.t9 + &(x * &(self.t10))))))))))))))))))
    }
}

// fn naive_multiexp<G>(exponents: Vec<F>, bases: Vec<E::G1Affine>) -> G::Projective
// where
//     G: Curve,
// {
//     let t1 = Instant::now();
//     assert_eq!(bases.len(), exponents.len());

//     let mut acc = G::Projective::zero();

//     for (base, exp) in bases.iter().zip(exponents.iter()) {
//         acc += &base.mul(*exp);
//     }

//     let duration = t1.elapsed();
//     println!(
//         "len = {}, Time elapsed in naive_multiexp is: {:?}",
//         exponents.len(),
//         duration
//     );
//     acc
// }

fn quick_multiexp<G>(exponents: &Vec<G::Fr>, bases: &Vec<G::Affine>) -> G::Projective
where
    G: Curve,
{
    G::vartime_multiscalar_mul(exponents, bases)
}

fn random_bytes_to_fr<F: Field>(bytes: &[u8]) -> F {
    let mut r_bytes = [0u8; 31];
    // only use the first 31 bytes, to avoid value over modulus
    // we could mod modulus here too to keep value in range
    r_bytes.copy_from_slice(&bytes[0..31]);
    let r = <F as Field>::from_random_bytes(&r_bytes);
    r.unwrap()
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
