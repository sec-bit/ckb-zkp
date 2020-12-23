use math::{curves::AffineCurve, fields::Field, test_rng};

use crate::tests::fields::{field_test, primefield_test};
use crate::tests::{curves::*, groups::*};

use super::*;

use core::str::FromStr;
use rand::Rng;

#[test]
fn test_fr() {
    let mut rng = test_rng();
    let a: Fr = rng.gen();
    let b: Fr = rng.gen();
    field_test(a, b);
    primefield_test::<Fr>();
}

#[test]
fn test_fq() {
    let mut rng = test_rng();
    let a: Fq = rng.gen();
    let b: Fq = rng.gen();
    field_test(a, b);
    primefield_test::<Fq>();
}

#[test]
fn precompute() {
    let b = Fq::from(2u64);
    println!("coeff_b: {:?}", b);

    let g_x = Fq::from_str(
        "55066263022277343669578718895168534326250603453777594175500187360389116729240",
    )
    .unwrap();
    println!("g_x: {:?}", g_x);

    let g_y = Fq::from_str(
        "32670510020758816978083085130507043184471273380659243275938904335757337482424",
    )
    .unwrap();
    println!("g_y: {:?}", g_y);

    let inv = Fq::from(1u64);
    println!("{:?}", inv.inverse());
}

#[test]
fn test_projective_curve() {
    curve_tests::<Projective>();
}

#[test]
fn test_projective_group() {
    let mut rng = test_rng();
    let a = rng.gen();
    let b = rng.gen();
    for _i in 0..100 {
        group_test::<Projective>(a, b);
    }
}

#[test]
fn test_generator() {
    let generator = Affine::prime_subgroup_generator();
    assert!(generator.is_on_curve());
    assert!(generator.is_in_correct_subgroup_assuming_on_curve());
}
