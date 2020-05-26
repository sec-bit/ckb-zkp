pub mod arithmetic_circuit;
pub mod inner_product_proof;

// use digest::{ExtendableOutput, Input, XofReader};
// use sha3::{Sha3XofReader, Shake256};
use math::{msm::VariableBaseMSM, Field, PairingEngine, PrimeField, Zero};
use std::time::Instant;

// Q (vector, zQ) * Qxn (matrix, WL, WR, WO) = n (vector, zQW)
pub fn vector_matrix_product<E: PairingEngine>(v: &Vec<E::Fr>, m: &Vec<Vec<E::Fr>>) -> Vec<E::Fr> {
    let n = m[0].len();
    let mut out = vec![E::Fr::zero(); n];
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

// n (vector, aL/aR/aO) * Qxn (matrix, WL, WR, WO) = Q (vector, wLaL)
pub fn vector_matrix_product_T<E: PairingEngine>(
    v: &Vec<E::Fr>,
    m: &Vec<Vec<E::Fr>>,
) -> Vec<E::Fr> {
    let Q = m.len();
    let mut out = vec![E::Fr::zero(); Q];

    for row in 0..Q {
        if m[row].len() != v.len() {
            panic!("matrix_vector_product_T(v,m): lengths of vectors do not match");
        }
        for col in 0..v.len() {
            out[row] += &(m[row][col] * &(v[col])); // w_ij * a_j
        }
    }
    out
}

pub fn hadamard_product<E: PairingEngine>(a: &[E::Fr], b: &[E::Fr]) -> Vec<E::Fr> {
    if a.len() != b.len() {
        panic!("hadamard_product(a,b): lengths of vectors do not match");
    }
    let mut out = vec![E::Fr::zero(); a.len()];
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
pub fn inner_product<E: PairingEngine>(a: &[E::Fr], b: &[E::Fr]) -> E::Fr {
    let mut out = E::Fr::zero();
    if a.len() != b.len() {
        panic!("inner_product(a,b): lengths of vectors do not match");
    }
    for i in 0..a.len() {
        out += &(a[i] * &(b[i]));
    }
    out
}

// // copied from bulletproofs' internal code, so that we don't need to modify the original code
// pub struct GeneratorsChain<E: PairingEngine> {
//     reader: Sha3XofReader,
//     dummy: E::Fr,
// }

// impl<E: PairingEngine> GeneratorsChain<E> {
//     /// Creates a chain of generators, determined by the hash of `label`.
//     pub fn new(label: &[u8]) -> Self {
//         let mut shake = Shake256::default();
//         shake.input(b"GeneratorsChain");
//         shake.input(label);
//         println!("label= {:?}", label);

//         GeneratorsChain {
//             reader: shake.xof_result(),
//             dummy: E::Fr::zero(),
//         }
//     }
// }

// impl<E: PairingEngine> Default for GeneratorsChain<E> {
//     fn default() -> Self {
//         Self::new(&[])
//     }
// }

// impl<E: PairingEngine> Iterator for GeneratorsChain<E> {
//     // type Item = E::Fr;
//     type Item = E::G1Affine;

//     fn next(&mut self) -> Option<Self::Item> {
//         let mut bytes = [0u8; 32];
//         self.reader.read(&mut bytes);
//         // E::Fr::from_random_bytes(&bytes)

//         let mut r_bytes = [0u8; 31];
//         // only use the first 31 bytes, to avoid value over modulus
//         // we could mod modulus here too to keep value in range
//         r_bytes.copy_from_slice(&bytes[0..31]);

//         let point = <E::G1Affine as AffineCurve>::from_random_bytes(&r_bytes);
//         println!("next>bytes={:?}, point={:?}", r_bytes, point);
//         point
//     }

//     fn size_hint(&self) -> (usize, Option<usize>) {
//         (usize::max_value(), None)
//     }
// }

/// Represents a degree-3 vector polynomial
/// \\(\mathbf{a} + \mathbf{b} \cdot x + \mathbf{c} \cdot x^2 + \mathbf{d} \cdot x^3 \\).
pub struct VecPoly3<E: PairingEngine>(
    pub Vec<E::Fr>,
    pub Vec<E::Fr>,
    pub Vec<E::Fr>,
    pub Vec<E::Fr>,
);

impl<E: PairingEngine> VecPoly3<E> {
    pub fn zero(n: usize) -> Self {
        VecPoly3(
            vec![E::Fr::zero(); n], // degree-0
            vec![E::Fr::zero(); n], // degree-1
            vec![E::Fr::zero(); n], // degree-2
            vec![E::Fr::zero(); n], // degree-3
        )
    }

    pub fn eval(&self, x: E::Fr) -> Vec<E::Fr> {
        let n = self.0.len();
        let mut out = vec![E::Fr::zero(); n];
        for i in 0..n {
            out[i] = self.0[i] + &(x * &(self.1[i] + &(x * &(self.2[i] + &(x * &(self.3[i]))))));
        }
        out
    }

    pub fn special_inner_product(lhs: &Self, rhs: &Self) -> Poly6<E> {
        let t1 = inner_product::<E>(&lhs.1, &rhs.0);
        let t2 = inner_product::<E>(&lhs.1, &rhs.1) + &(inner_product::<E>(&lhs.2, &rhs.0));
        let t3 = inner_product::<E>(&lhs.2, &rhs.1) + &(inner_product::<E>(&lhs.3, &rhs.0));
        let t4 = inner_product::<E>(&lhs.1, &rhs.3) + &(inner_product::<E>(&lhs.3, &rhs.1));
        let t5 = inner_product::<E>(&lhs.2, &rhs.3);
        let t6 = inner_product::<E>(&lhs.3, &rhs.3);

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
pub struct Poly6<E: PairingEngine> {
    pub t1: E::Fr,
    pub t2: E::Fr,
    pub t3: E::Fr,
    pub t4: E::Fr,
    pub t5: E::Fr,
    pub t6: E::Fr,
}

impl<E: PairingEngine> Poly6<E> {
    pub fn eval(&self, x: E::Fr) -> E::Fr {
        x * &(self.t1
            + &(x * &(self.t2
                + &(x * &(self.t3 + &(x * &(self.t4 + &(x * &(self.t5 + &(x * &self.t6))))))))))
    }
}

/// Represents a degree-5 vector polynomial
/// \\(\mathbf{a} + \mathbf{b} \cdot x + \mathbf{c} \cdot x^2 + \mathbf{d} \cdot x^3 + \mathbf{e} \cdot x^4 + \mathbf{f} \cdot x^5 \\).
pub struct VecPoly5<E: PairingEngine>(
    pub Vec<E::Fr>,
    pub Vec<E::Fr>,
    pub Vec<E::Fr>,
    pub Vec<E::Fr>,
    pub Vec<E::Fr>,
    pub Vec<E::Fr>,
);

impl<E: PairingEngine> VecPoly5<E> {
    pub fn zero(n: usize) -> Self {
        VecPoly5(
            vec![E::Fr::zero(); n], // degree-0
            vec![E::Fr::zero(); n], // degree-1
            vec![E::Fr::zero(); n], // degree-2
            vec![E::Fr::zero(); n], // degree-3
            vec![E::Fr::zero(); n], // degree-4
            vec![E::Fr::zero(); n], // degree-5
        )
    }

    pub fn eval(&self, x: E::Fr) -> Vec<E::Fr> {
        let n = self.0.len();
        let mut out = vec![E::Fr::zero(); n];
        for i in 0..n {
            out[i] = self.0[i]
                + &(x * &(self.1[i]
                    + &(x * &(self.2[i]
                        + &(x * &(self.3[i] + &(x * &(self.4[i] + &(x * &(self.5[i]))))))))));
        }
        out
    }

    pub fn special_inner_product(lhs: &Self, rhs: &Self) -> Poly10<E> {
        // lhs: 2, 3, 4, 5 || rhs: 2, 1, 0, 5
        let t2 = inner_product::<E>(&lhs.2, &rhs.0);
        let t3 = inner_product::<E>(&lhs.2, &rhs.1) + &inner_product::<E>(&lhs.3, &rhs.0);
        let t4 = inner_product::<E>(&lhs.2, &rhs.2)
            + &inner_product::<E>(&lhs.3, &rhs.1)
            + &inner_product::<E>(&lhs.4, &rhs.0);
        let t5 = inner_product::<E>(&lhs.3, &rhs.2)
            + &inner_product::<E>(&lhs.4, &rhs.1)
            + &inner_product::<E>(&lhs.5, &rhs.0);
        let t6 = inner_product::<E>(&lhs.4, &rhs.2) + &inner_product::<E>(&lhs.5, &rhs.1);
        let t7 = inner_product::<E>(&lhs.2, &rhs.5) + &inner_product::<E>(&lhs.5, &rhs.2);
        let t8 = inner_product::<E>(&lhs.3, &rhs.5);
        let t9 = inner_product::<E>(&lhs.4, &rhs.5);
        let t10 = inner_product::<E>(&lhs.5, &rhs.5);

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
pub struct Poly10<E: PairingEngine> {
    pub t2: E::Fr,
    pub t3: E::Fr,
    pub t4: E::Fr,
    pub t5: E::Fr,
    pub t6: E::Fr,
    pub t7: E::Fr,
    pub t8: E::Fr,
    pub t9: E::Fr,
    pub t10: E::Fr,
}

impl<E: PairingEngine> Poly10<E> {
    pub fn eval(&self, x: E::Fr) -> E::Fr {
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

// fn naive_multiexp<E>(exponents: Vec<E::Fr>, bases: Vec<E::G1Affine>) -> E::G1Projective
// where
//     E: PairingEngine,
// {
//     let t1 = Instant::now();
//     assert_eq!(bases.len(), exponents.len());

//     let mut acc = E::G1Projective::zero();

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

fn quick_multiexp<E>(exponents: &Vec<E::Fr>, bases: &Vec<E::G1Affine>) -> E::G1Projective
where
    E: PairingEngine,
{
    let t1 = Instant::now();
    let scalars = exponents[..]
        .into_iter()
        .map(|s| s.into_repr())
        .collect::<Vec<_>>();

    let result = VariableBaseMSM::multi_scalar_mul(bases, &scalars);
    let duration = t1.elapsed();
    println!(
        "len = {}, Time elapsed in quick_multiexp is: {:?}",
        exponents.len(),
        duration
    );
    result
}

fn random_bytes_to_fr<E: PairingEngine>(bytes: &[u8]) -> E::Fr {
    let mut r_bytes = [0u8; 31];
    // only use the first 31 bytes, to avoid value over modulus
    // we could mod modulus here too to keep value in range
    r_bytes.copy_from_slice(&bytes[0..31]);
    let r = <E::Fr as Field>::from_random_bytes(&r_bytes);
    r.unwrap()
}
