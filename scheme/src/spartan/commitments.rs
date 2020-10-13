use crate::r1cs::SynthesisError;
use crate::spartan::data_structure::PolyCommitments;
use crate::Vec;
use core::ops::AddAssign;
use curve::ProjectiveCurve;
use math::{log2, msm::VariableBaseMSM, AffineCurve, PairingEngine, PrimeField, UniformRand, Zero};
use rand::Rng;

pub fn packing_poly_commit<E: PairingEngine, R: Rng>(
    generators: &Vec<E::G1Affine>,
    values: &Vec<E::Fr>,
    h: &E::G1Affine,
    rng: &mut R,
    is_blind: bool,
) -> Result<(Vec<E::G1Affine>, Vec<E::Fr>), SynthesisError> {
    let mut commits = Vec::new();
    let mut blinds = Vec::new();

    let n = values.len();
    let size = log2(n) as usize;
    let l_size = (2usize).pow((size / 2) as u32);
    let r_size = (2usize).pow((size - size / 2) as u32);
    assert_eq!(n, l_size * r_size);

    for i in 0..l_size {
        let mut blind = E::Fr::zero();
        if is_blind {
            blind = E::Fr::rand(rng);
        }
        blinds.push(blind);

        let commit = poly_commit_vec::<E>(
            generators,
            &values[i * r_size..(i + 1) * r_size].to_vec(),
            h,
            blind,
        )
        .unwrap()
        .commit;
        commits.push(commit);
    }
    Ok((commits, blinds))
}

pub fn poly_commit_vec<E: PairingEngine>(
    generators: &Vec<E::G1Affine>,
    values: &Vec<E::Fr>,
    h: &E::G1Affine,
    blind_value: E::Fr,
) -> Result<PolyCommitments<E>, SynthesisError> {
    // let scalars = values.clone();
    let mut commit = VariableBaseMSM::multi_scalar_mul(
        &generators.clone(),
        &values
            .into_iter()
            .map(|e| e.into_repr())
            .collect::<Vec<_>>(),
    );

    commit.add_assign(&(h.mul(blind_value)));

    let commit = PolyCommitments::<E> {
        commit: commit.into_affine(),
    };
    Ok(commit)
}
