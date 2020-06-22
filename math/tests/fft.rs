use curve::bls12_381::{Fr, G1Projective};
use math::fft::domain::*;
use math::fft::polynomial::*;
use math::fft::{DensePolynomial, EvaluationDomain, SparsePolynomial};
use math::{test_rng, Field, One, PrimeField, UniformRand, Zero};
use rand::Rng;

#[test]
fn vanishing_polynomial_evaluation() {
    let rng = &mut test_rng();
    for coeffs in 0..10 {
        let domain = EvaluationDomain::<Fr>::new(coeffs).unwrap();
        let z = domain.vanishing_polynomial();
        for _ in 0..100 {
            let point = rng.gen();
            assert_eq!(
                z.evaluate(point),
                domain.evaluate_vanishing_polynomial(point)
            )
        }
    }
}

#[test]
fn vanishing_polynomial_vanishes_on_domain() {
    for coeffs in 0..1000 {
        let domain = EvaluationDomain::<Fr>::new(coeffs).unwrap();
        let z = domain.vanishing_polynomial();
        for point in domain.elements() {
            assert!(z.evaluate(point).is_zero())
        }
    }
}

#[test]
fn size_of_elements() {
    for coeffs in 1..10 {
        let size = 1 << coeffs;
        let domain = EvaluationDomain::<Fr>::new(size).unwrap();
        let domain_size = domain.size();
        assert_eq!(domain_size, domain.elements().count());
    }
}

#[test]
fn elements_contents() {
    for coeffs in 1..10 {
        let size = 1 << coeffs;
        let domain = EvaluationDomain::<Fr>::new(size).unwrap();
        for (i, element) in domain.elements().enumerate() {
            assert_eq!(element, domain.group_gen.pow([i as u64]));
        }
    }
}

#[test]
fn double_polynomials_random() {
    let rng = &mut test_rng();
    for degree in 0..70 {
        let p = DensePolynomial::<Fr>::rand(degree, rng);
        let p_double = &p + &p;
        let p_quad = &p_double + &p_double;
        assert_eq!(&(&(&p + &p) + &p) + &p, p_quad);
    }
}

#[test]
fn add_polynomials() {
    let rng = &mut test_rng();
    for a_degree in 0..70 {
        for b_degree in 0..70 {
            let p1 = DensePolynomial::<Fr>::rand(a_degree, rng);
            let p2 = DensePolynomial::<Fr>::rand(b_degree, rng);
            let res1 = &p1 + &p2;
            let res2 = &p2 + &p1;
            assert_eq!(res1, res2);
        }
    }
}

#[test]
fn add_polynomials_with_mul() {
    let rng = &mut test_rng();
    for a_degree in 0..70 {
        for b_degree in 0..70 {
            let mut p1 = DensePolynomial::rand(a_degree, rng);
            let p2 = DensePolynomial::rand(b_degree, rng);
            let f = Fr::rand(rng);
            let f_p2 =
                DensePolynomial::from_coefficients_vec(p2.coeffs.iter().map(|c| f * c).collect());
            let res2 = &f_p2 + &p1;
            p1 += (f, &p2);
            let res1 = p1;
            assert_eq!(res1, res2);
        }
    }
}

#[test]
fn sub_polynomials() {
    let rng = &mut test_rng();
    let p1 = DensePolynomial::<Fr>::rand(5, rng);
    let p2 = DensePolynomial::<Fr>::rand(3, rng);
    let res1 = &p1 - &p2;
    let res2 = &p2 - &p1;
    assert_eq!(
        &res1 + &p2,
        p1,
        "Subtraction should be inverse of addition!"
    );
    assert_eq!(res1, -res2, "p2 - p1 = -(p1 - p2)");
}

#[test]
fn divide_polynomials_fixed() {
    let dividend = DensePolynomial::from_coefficients_slice(&[
        "4".parse().unwrap(),
        "8".parse().unwrap(),
        "5".parse().unwrap(),
        "1".parse().unwrap(),
    ]);
    let divisor = DensePolynomial::from_coefficients_slice(&[Fr::one(), Fr::one()]); // Construct a monic linear polynomial.
    let result = &dividend / &divisor;
    let expected_result = DensePolynomial::from_coefficients_slice(&[
        "4".parse().unwrap(),
        "4".parse().unwrap(),
        "1".parse().unwrap(),
    ]);
    assert_eq!(expected_result, result);
}

#[test]
fn divide_polynomials_random() {
    let rng = &mut test_rng();

    for a_degree in 0..70 {
        for b_degree in 0..70 {
            let dividend = DensePolynomial::<Fr>::rand(a_degree, rng);
            let divisor = DensePolynomial::<Fr>::rand(b_degree, rng);
            if let Some((quotient, remainder)) = DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&dividend).into(),
                &(&divisor).into(),
            ) {
                assert_eq!(dividend, &(&divisor * &quotient) + &remainder)
            }
        }
    }
}

#[test]
fn evaluate_polynomials() {
    let rng = &mut test_rng();
    for a_degree in 0..70 {
        let p = DensePolynomial::rand(a_degree, rng);
        let point: Fr = Fr::from(10u64);
        let mut total = Fr::zero();
        for (i, coeff) in p.coeffs.iter().enumerate() {
            total += &(point.pow(&[i as u64]) * coeff);
        }
        assert_eq!(p.evaluate(point), total);
    }
}

#[test]
fn mul_polynomials_random() {
    let rng = &mut test_rng();
    for a_degree in 0..70 {
        for b_degree in 0..70 {
            let a = DensePolynomial::<Fr>::rand(a_degree, rng);
            let b = DensePolynomial::<Fr>::rand(b_degree, rng);
            assert_eq!(&a * &b, a.naive_mul(&b))
        }
    }
}

#[test]
fn mul_by_vanishing_poly() {
    let rng = &mut test_rng();
    for size in 1..10 {
        let domain = EvaluationDomain::new(1 << size).unwrap();
        for degree in 0..70 {
            let p = DensePolynomial::<Fr>::rand(degree, rng);
            let ans1 = p.mul_by_vanishing_poly(domain);
            let ans2 = &p * &domain.vanishing_polynomial().into();
            assert_eq!(ans1, ans2);
        }
    }
}

#[test]
fn test_leading_zero() {
    let n = 10;
    let rand_poly = DensePolynomial::rand(n, &mut test_rng());
    let coefficients = rand_poly.coeffs.clone();
    let leading_coefficient: Fr = coefficients[n];

    let negative_leading_coefficient = -leading_coefficient;
    let inverse_leading_coefficient = leading_coefficient.inverse().unwrap();

    let mut inverse_coefficients = coefficients.clone();
    inverse_coefficients[n] = inverse_leading_coefficient;

    let mut negative_coefficients = coefficients;
    negative_coefficients[n] = negative_leading_coefficient;

    let negative_poly = DensePolynomial::from_coefficients_vec(negative_coefficients);
    let inverse_poly = DensePolynomial::from_coefficients_vec(inverse_coefficients);

    let x = &inverse_poly * &rand_poly;
    assert_eq!(x.degree(), 2 * n);
    assert!(!x.coeffs.last().unwrap().is_zero());

    let y = &negative_poly + &rand_poly;
    assert_eq!(y.degree(), n - 1);
    assert!(!y.coeffs.last().unwrap().is_zero());
}

#[test]
fn evaluate_over_domain() {
    for size in 2..10 {
        let domain_size = 1 << size;
        let domain = EvaluationDomain::new(domain_size).unwrap();
        let two = Fr::one() + &Fr::one();
        let sparse_poly = SparsePolynomial::from_coefficients_vec(vec![(0, two), (1, two)]);
        let evals1 = sparse_poly.evaluate_over_domain_by_ref(domain);

        let dense_poly: DensePolynomial<Fr> = sparse_poly.into();
        let evals2 = dense_poly.clone().evaluate_over_domain(domain);
        assert_eq!(evals1.clone().interpolate(), evals2.clone().interpolate());
        assert_eq!(evals1.interpolate(), dense_poly);
        assert_eq!(evals2.interpolate(), dense_poly);
    }
}

// Test multiplying various (low degree) polynomials together and
// comparing with naive evaluations.
#[test]
fn fft_composition() {
    fn test_fft_composition<
        F: PrimeField,
        T: DomainCoeff<F> + UniformRand + core::fmt::Debug + Eq,
        R: rand::Rng,
    >(
        rng: &mut R,
    ) {
        for coeffs in 0..10 {
            let coeffs = 1 << coeffs;

            let mut v = vec![];
            for _ in 0..coeffs {
                v.push(T::rand(rng));
            }
            let mut v2 = v.clone();

            let domain = EvaluationDomain::<F>::new(coeffs).unwrap();
            domain.ifft_in_place(&mut v2);
            domain.fft_in_place(&mut v2);
            assert_eq!(v, v2, "ifft(fft(.)) != iden");

            domain.fft_in_place(&mut v2);
            domain.ifft_in_place(&mut v2);
            assert_eq!(v, v2, "fft(ifft(.)) != iden");

            domain.coset_ifft_in_place(&mut v2);
            domain.coset_fft_in_place(&mut v2);
            assert_eq!(v, v2, "coset_fft(coset_ifft(.)) != iden");

            domain.coset_fft_in_place(&mut v2);
            domain.coset_ifft_in_place(&mut v2);
            assert_eq!(v, v2, "coset_ifft(coset_fft(.)) != iden");
        }
    }

    let rng = &mut test_rng();

    test_fft_composition::<Fr, Fr, _>(rng);
    test_fft_composition::<Fr, G1Projective, _>(rng);
}

#[test]
#[cfg(feature = "parallel")]
fn parallel_fft_consistency() {
    use core::cmp::min;
    use curve::bls12_381::Bls12_381;
    use math::fft::domain::*;
    use math::{test_rng, PairingEngine, UniformRand, Vec};

    fn test_consistency<E: PairingEngine, R: rand::Rng>(rng: &mut R) {
        for _ in 0..5 {
            for log_d in 0..10 {
                let d = 1 << log_d;

                let mut v1 = (0..d).map(|_| E::Fr::rand(rng)).collect::<Vec<_>>();
                let mut v2 = v1.clone();

                let domain = EvaluationDomain::new(v1.len()).unwrap();

                for log_cpus in log_d..min(log_d + 1, 3) {
                    parallel_fft::<E::Fr, E::Fr>(&mut v1, domain.group_gen, log_d, log_cpus);
                    serial_fft::<E::Fr, E::Fr>(&mut v2, domain.group_gen, log_d);

                    assert_eq!(v1, v2);
                }
            }
        }
    }

    let rng = &mut test_rng();

    test_consistency::<Bls12_381, _>(rng);
}
