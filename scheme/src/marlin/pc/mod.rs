use core::marker::PhantomData;

pub use math::fft::DensePolynomial as Polynomial;
use math::{AffineCurve, Field, One, PairingEngine, ProjectiveCurve, Zero};
use rand::RngCore;

use crate::{BTreeMap, BTreeSet};

mod data_structures;
pub use data_structures::*;

mod kzg10;
use kzg10::KZG10;

mod optional_rng;
use optional_rng::OptionalRng;

pub struct PC<E: PairingEngine> {
    _engine: PhantomData<E>,
}

impl<E: PairingEngine> PC<E> {
    pub fn setup<R: RngCore>(max_degree: usize, rng: &mut R) -> Result<UniversalParams<E>, Error> {
        KZG10::setup(max_degree, rng)
    }

    pub fn trim(
        pp: &UniversalParams<E>,
        supported_degree: usize,
    ) -> Result<(CommitterKey<E>, VerifierKey<E>), Error> {
        KZG10::trim(pp, supported_degree)
    }

    pub fn commit<'a>(
        ck: &CommitterKey<E>,
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<'a, E::Fr>>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<(Vec<LabeledCommitment<E>>, Vec<Randomness<E::Fr>>), Error> {
        let rng = &mut OptionalRng(rng);
        let mut commitments = Vec::new();
        let mut randomnesses = Vec::new();
        for p in polynomials {
            let label = p.label();
            let polynomial = p.polynomial();
            let hiding_bound = p.hiding_bound();
            let degree_bound = p.degree_bound();

            let (comm, rand) = KZG10::commit(&ck.powers(), polynomial, hiding_bound, Some(rng))?;

            let (shifted_comm, shifted_rand) = if let Some(degree_bound) = degree_bound {
                let shifted_powers = ck
                    .shifted_powers(degree_bound)
                    .ok_or(Error::DegreeOutOfBound)?;
                let (shifted_comm, shifted_rand) =
                    KZG10::commit(&shifted_powers, polynomial, hiding_bound, Some(rng))?;
                (Some(shifted_comm), Some(shifted_rand))
            } else {
                (None, None)
            };

            let commitment = Commitment { comm, shifted_comm };
            let randomness = Randomness { rand, shifted_rand };
            commitments.push(LabeledCommitment::new(
                label.to_string(),
                commitment,
                degree_bound,
            ));
            randomnesses.push(randomness);
        }
        Ok((commitments, randomnesses))
    }

    pub fn open<'a>(
        ck: &CommitterKey<E>,
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<'a, E::Fr>>,
        point: E::Fr,
        opening_challenge: E::Fr,
        randomnesses: impl IntoIterator<Item = &'a Randomness<E::Fr>>,
    ) -> Result<Proof<E>, Error> {
        let supported_degree = ck.supported_degree();
        let mut p = Polynomial::zero();
        let mut r = Rand::empty();
        let mut challenge = E::Fr::one();

        for (poly, rand) in polynomials.into_iter().zip(randomnesses) {
            p += (challenge, poly.polynomial());
            r += (challenge, &rand.rand);
            if let Some(degree_bound) = poly.degree_bound() {
                let shifted_challenge = challenge * &opening_challenge;
                let shifted_rand = rand.shifted_rand.as_ref().unwrap();
                p += (
                    shifted_challenge,
                    &Self::shift_polynomial(poly.polynomial(), supported_degree - degree_bound),
                );
                r += (shifted_challenge, shifted_rand);
            }
            challenge *= &opening_challenge.square();
        }
        KZG10::open(&ck.powers(), &p, point, &r)
    }

    pub fn check<'a>(
        vk: &VerifierKey<E>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<E>>,
        point: E::Fr,
        values: impl IntoIterator<Item = E::Fr>,
        proof: &Proof<E>,
        opening_challenge: E::Fr,
    ) -> Result<bool, Error> {
        let (acc_comm, acc_value) = Self::accumulate_commitments_and_values(
            vk,
            commitments,
            point,
            values,
            opening_challenge,
        )?;
        let acc_comm = Comm(acc_comm.into());
        KZG10::check(vk, &acc_comm, point, acc_value, proof)
    }

    /// multiple query points
    pub fn batch_open<'a>(
        ck: &CommitterKey<E>,
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<'a, E::Fr>>,
        query_set: &QuerySet<E::Fr>,
        opening_challenge: E::Fr,
        randomnesses: impl IntoIterator<Item = &'a Randomness<E::Fr>>,
    ) -> Result<Vec<Proof<E>>, Error> {
        let label_to_poly_rand_map: BTreeMap<_, _> = polynomials
            .into_iter()
            .zip(randomnesses)
            .map(|(p, r)| (p.label(), (p, r)))
            .collect();

        let mut point_to_labels_map = BTreeMap::new();
        for (label, point) in query_set {
            let labels = point_to_labels_map.entry(point).or_insert(BTreeSet::new());
            labels.insert(label);
        }

        let mut proofs = Vec::new();

        for (point, labels) in point_to_labels_map {
            let mut polys: Vec<&'a LabeledPolynomial<'a, _>> = Vec::new();
            let mut rands: Vec<&'a Randomness<_>> = Vec::new();
            for label in labels {
                let (poly, rand) =
                    label_to_poly_rand_map
                        .get(label)
                        .ok_or(Error::MissingPolynomial {
                            label: label.to_string(),
                        })?;
                polys.push(poly);
                rands.push(rand);
            }
            let proof = Self::open(ck, polys, *point, opening_challenge, rands)?;
            proofs.push(proof);
        }
        Ok(proofs)
    }

    /// multiple query points
    pub fn batch_check<'a>(
        vk: &VerifierKey<E>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<E>>,
        query_set: &QuerySet<E::Fr>,
        values: &Evaluations<E::Fr>,
        proofs: &Vec<Proof<E>>,
        opening_challenge: E::Fr,
    ) -> Result<bool, Error> {
        let mut result = true;
        let mut point_to_labels_map = BTreeMap::new();
        for (label, point) in query_set {
            let labels = point_to_labels_map.entry(point).or_insert(BTreeSet::new());
            labels.insert(label);
        }
        assert_eq!(point_to_labels_map.len(), proofs.len());

        let commitments: BTreeMap<_, _> = commitments.into_iter().map(|c| (c.label(), c)).collect();

        for ((point, labels), proof) in point_to_labels_map.into_iter().zip(proofs) {
            let mut cs: Vec<&'_ LabeledCommitment<E>> = Vec::new();
            let mut vs = Vec::new();
            for label in labels {
                let c = commitments.get(label).ok_or(Error::MissingPolynomial {
                    label: label.to_string(),
                })?;

                let v = values
                    .get(&(label.clone(), *point))
                    .ok_or(Error::MissingEvaluation {
                        label: label.to_string(),
                    })?;

                cs.push(c);
                vs.push(*v);
            }
            result &= Self::check(vk, cs, *point, vs, &proof, opening_challenge)?;
        }

        Ok(result)
    }

    fn accumulate_commitments_and_values<'a>(
        vk: &VerifierKey<E>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<E>>,
        point: E::Fr,
        values: impl IntoIterator<Item = E::Fr>,
        opening_challenge: E::Fr,
    ) -> Result<(E::G1Projective, E::Fr), Error> {
        let mut combined_comm = E::G1Projective::zero();
        let mut combined_value = E::Fr::zero();
        let mut challenge = E::Fr::one();

        for (labeled_commitment, value) in commitments.into_iter().zip(values) {
            let degree_bound = labeled_commitment.degree_bound();
            let commitment = labeled_commitment.commitment();
            assert_eq!(degree_bound.is_some(), commitment.shifted_comm.is_some());
            combined_comm += &commitment.comm.0.mul(challenge);
            combined_value += &(value * &challenge);

            if let Some(degree_bound) = degree_bound {
                let shifted_challenge = challenge * &opening_challenge;
                let shifted_comm = commitment
                    .shifted_comm
                    .as_ref()
                    .unwrap()
                    .0
                    .into_projective();
                let shifted_degree = vk.supported_degree - degree_bound;

                let shift_value = point.pow([shifted_degree as u64]) * &value;
                combined_comm += &shifted_comm.mul(shifted_challenge);
                combined_value += &(shift_value * &shifted_challenge);
            }

            challenge *= &opening_challenge.square();
        }
        Ok((combined_comm, combined_value))
    }

    fn shift_polynomial(p: &Polynomial<E::Fr>, shift: usize) -> Polynomial<E::Fr> {
        if p.is_zero() {
            Polynomial::zero()
        } else {
            let mut shifted_coeffs = vec![E::Fr::zero(); shift];
            shifted_coeffs.extend(&p.coeffs);
            Polynomial::from_coefficients_vec(shifted_coeffs)
        }
    }
}

mod tests {
    use super::*;
    use crate::math::UniformRand;

    use curve::test_rng;
    use rand::distributions::Distribution;

    #[derive(Clone)]
    struct TestInfo {
        num_iterations: usize,
        max_degree: usize,
        supported_degree: usize,
        num_polynomials: usize,
        enforcing_degree_bounds: bool,
        num_points: usize,
    }

    fn single_point_template<E: PairingEngine>(info: TestInfo) -> Result<(), Error> {
        let TestInfo {
            num_iterations,
            max_degree,
            supported_degree,
            num_polynomials,
            enforcing_degree_bounds,
            ..
        } = info;
        assert!(max_degree >= supported_degree);

        let rng = &mut test_rng();
        for _ in 0..num_iterations {
            let point = E::Fr::rand(rng);
            let opening_challenge = E::Fr::rand(rng);

            let mut polynomials = Vec::new();
            let mut values = Vec::new();
            for i in 0..num_polynomials {
                let degree = rand::distributions::Uniform::from(1..=supported_degree).sample(rng);
                let polynomial = Polynomial::rand(degree, rng);
                let label = format!("{}", i);
                let degree_bound = if enforcing_degree_bounds {
                    Some(degree)
                } else {
                    None
                };
                let hiding_bound = Some(1);
                let value = polynomial.evaluate(point);

                polynomials.push(LabeledPolynomial::new_owned(
                    label,
                    polynomial,
                    degree_bound,
                    hiding_bound,
                ));
                values.push(value);
            }
            let pp = PC::<E>::setup(max_degree, rng)?;
            let (ck, vk) = PC::<E>::trim(&pp, supported_degree)?;
            let (comms, rands) = PC::<E>::commit(&ck, &polynomials, Some(rng))?;
            let proof = PC::<E>::open(&ck, &polynomials, point, opening_challenge, &rands)?;
            assert!(PC::<E>::check(
                &vk,
                &comms,
                point,
                values,
                &proof,
                opening_challenge
            )?);
        }
        Ok(())
    }

    fn batch_template<E: PairingEngine>(info: TestInfo) -> Result<(), Error> {
        let TestInfo {
            num_iterations,
            max_degree,
            supported_degree,
            num_polynomials,
            enforcing_degree_bounds,
            num_points,
        } = info;
        assert!(max_degree >= supported_degree);

        let rng = &mut test_rng();
        for _ in 0..num_iterations {
            let opening_challenge = E::Fr::rand(rng);

            let mut polynomials = Vec::new();
            for i in 0..num_polynomials {
                let degree = rand::distributions::Uniform::from(1..=supported_degree).sample(rng);
                let polynomial = Polynomial::rand(degree, rng);
                let label = format!("{}", i);
                let degree_bound = if enforcing_degree_bounds {
                    Some(degree)
                } else {
                    None
                };
                let hiding_bound = Some(1);

                polynomials.push(LabeledPolynomial::new_owned(
                    label,
                    polynomial,
                    degree_bound,
                    hiding_bound,
                ));
            }

            let mut evals = Evaluations::new();
            let mut query_set = QuerySet::new();
            for _ in 0..num_points {
                for p in polynomials.iter() {
                    let point = E::Fr::rand(rng);
                    let label = p.label();
                    let eval = p.evaluate(point);
                    query_set.insert((label.clone(), point));
                    evals.insert((label.clone(), point), eval);
                }
            }

            let pp = PC::<E>::setup(max_degree, rng)?;
            let (ck, vk) = PC::<E>::trim(&pp, supported_degree)?;
            let (comms, rands) = PC::<E>::commit(&ck, &polynomials, Some(rng))?;
            let proofs =
                PC::<E>::batch_open(&ck, &polynomials, &query_set, opening_challenge, &rands)?;
            assert!(PC::<E>::batch_check(
                &vk,
                &comms,
                &query_set,
                &evals,
                &proofs,
                opening_challenge
            )?);
        }
        Ok(())
    }

    #[test]
    fn single_point_test() {
        let info = TestInfo {
            num_iterations: 10,
            max_degree: 10,
            supported_degree: 8,
            num_polynomials: 4,
            enforcing_degree_bounds: true,
            num_points: 3,
        };

        use curve::bls12_381::Bls12_381;
        single_point_template::<Bls12_381>(info).expect("est failed for Bls12_381");
    }

    #[test]
    fn batch_test() {
        let info = TestInfo {
            num_iterations: 1,
            max_degree: 10,
            supported_degree: 8,
            num_polynomials: 4,
            enforcing_degree_bounds: true,
            num_points: 3,
        };
        use curve::bls12_381::Bls12_381;
        batch_template::<Bls12_381>(info).expect("est failed for Bls12_381");
    }
}
