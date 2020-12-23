use crate::r1cs::SynthesisError;
use crate::spartan::data_structure::PolyCommitments;
use crate::Vec;
use core::ops::AddAssign;
use curve::ProjectiveCurve;
use math::{log2, AffineCurve, Curve, UniformRand, Zero};
use rand::Rng;

pub fn packing_poly_commit<G: Curve, R: Rng>(
    generators: &Vec<G::Affine>,
    values: &Vec<G::Fr>,
    h: &G::Affine,
    rng: &mut R,
    is_blind: bool,
) -> Result<(Vec<G::Affine>, Vec<G::Fr>), SynthesisError> {
    let mut commits = Vec::new();
    let mut blinds = Vec::new();

    let n = values.len();
    let size = log2(n) as usize;
    let l_size = (2usize).pow((size / 2) as u32);
    let r_size = (2usize).pow((size - size / 2) as u32);
    assert_eq!(n, l_size * r_size);

    for i in 0..l_size {
        let mut blind = G::Fr::zero();
        if is_blind {
            blind = G::Fr::rand(rng);
        }
        blinds.push(blind);

        let commit =
            poly_commit_vec::<G>(&generators, &values[i * r_size..(i + 1) * r_size], h, blind)
                .unwrap()
                .commit;
        commits.push(commit);
    }
    Ok((commits, blinds))
}

pub fn poly_commit_vec<G: Curve>(
    generators: &[G::Affine],
    values: &[G::Fr],
    h: &G::Affine,
    blind_value: G::Fr,
) -> Result<PolyCommitments<G>, SynthesisError> {
    let mut commit = G::vartime_multiscalar_mul(values, generators);

    commit.add_assign(&(h.mul(blind_value)));

    let commit = PolyCommitments::<G> {
        commit: commit.into_affine(),
    };
    Ok(commit)
}
