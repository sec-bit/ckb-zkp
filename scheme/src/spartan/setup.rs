use crate::r1cs::SynthesisError;
use crate::spartan::data_structure::{
    MultiCommitmentParameters, NizkParameters, PolyCommitmentParameters, R1CSEvalsParameters,
    R1CSSatisfiedParameters, SnarkParameters, SumCheckCommitmentParameters,
};
use crate::Vec;
use core::cmp;
use math::{log2, PairingEngine, ProjectiveCurve, UniformRand};
use rand::Rng;

pub fn generate_setup_nizk_parameters<E, R>(
    rng: &mut R,
    num_aux: usize,
    num_inputs: usize,
) -> Result<NizkParameters<E>, SynthesisError>
where
    E: PairingEngine,
    R: Rng,
{
    let r1cs_satisfied_params =
        R1CSSatisfiedParameters::new::<R>(rng, num_aux, num_inputs).unwrap();

    Ok(NizkParameters {
        r1cs_satisfied_params,
    })
}

pub fn generate_setup_snark_parameters<E, R>(
    rng: &mut R,
    num_aux: usize,
    num_inputs: usize,
    num_constraints: usize,
) -> Result<SnarkParameters<E>, SynthesisError>
where
    E: PairingEngine,
    R: Rng,
{
    let r1cs_satisfied_params =
        R1CSSatisfiedParameters::new::<R>(rng, num_aux, num_inputs).unwrap();

    let t = cmp::max(num_aux, num_inputs).next_power_of_two();
    let n = cmp::max(t * 2, num_constraints).next_power_of_two();
    let r1cs_eval_params =
        R1CSEvalsParameters::new::<R>(rng, num_constraints * (t * 2), n).unwrap();
    Ok(SnarkParameters {
        r1cs_satisfied_params,
        r1cs_eval_params,
    })
}

impl<E: PairingEngine> R1CSSatisfiedParameters<E> {
    pub fn new<R>(
        rng: &mut R,
        num_aux: usize,
        num_inputs: usize,
    ) -> Result<R1CSSatisfiedParameters<E>, SynthesisError>
    where
        E: PairingEngine,
        R: Rng,
    {
        let n = log2(cmp::max(num_aux, num_inputs).next_power_of_two()) as usize;
        let pc_params = PolyCommitmentParameters::new::<R>(rng, n).unwrap();
        let sc_params =
            SumCheckCommitmentParameters::new::<R>(rng, pc_params.gen_1.clone()).unwrap();
        Ok(R1CSSatisfiedParameters {
            pc_params,
            sc_params,
            n,
        })
    }
}

impl<E: PairingEngine> PolyCommitmentParameters<E> {
    pub fn new<R: Rng>(
        rng: &mut R,
        num: usize,
    ) -> Result<PolyCommitmentParameters<E>, SynthesisError> {
        let n = (2usize).pow((num - num / 2) as u32);
        let mut generators = Vec::new();
        for _ in 0..n {
            generators.push(E::G1Projective::rand(rng).into_affine());
        }
        let h = E::G1Projective::rand(rng).into_affine();
        let gen_n = MultiCommitmentParameters { n, generators, h };

        let g = E::G1Projective::rand(rng).into_affine();
        let gen_1 = MultiCommitmentParameters {
            n: 1,
            generators: vec![g],
            h,
        };

        let pc_params = PolyCommitmentParameters { n, gen_n, gen_1 };

        Ok(pc_params)
    }
}

impl<E: PairingEngine> SumCheckCommitmentParameters<E> {
    pub fn new<R: Rng>(
        rng: &mut R,
        gen_1: MultiCommitmentParameters<E>,
    ) -> Result<SumCheckCommitmentParameters<E>, SynthesisError> {
        let mut n = 3;
        let mut generators = Vec::new();
        for _ in 0..n {
            generators.push(E::G1Projective::rand(rng).into_affine());
        }
        let h = E::G1Projective::rand(rng).into_affine();
        let gen_3 = MultiCommitmentParameters { n, generators, h };

        n = 4;
        generators = Vec::new();
        for _ in 0..n {
            generators.push(E::G1Projective::rand(rng).into_affine());
        }
        let h = E::G1Projective::rand(rng).into_affine();
        let gen_4 = MultiCommitmentParameters { n, generators, h };

        let sc_params = SumCheckCommitmentParameters {
            gen_1,
            gen_3,
            gen_4,
        };

        Ok(sc_params)
    }
}

impl<E: PairingEngine> R1CSEvalsParameters<E> {
    pub fn new<R: Rng>(
        rng: &mut R,
        n: usize,
        m: usize,
    ) -> Result<R1CSEvalsParameters<E>, SynthesisError> {
        let num_ops_params = log2(n) as usize + 4; //  (3 * 5).next_power_of_two().log2();
        let ops_params = PolyCommitmentParameters::new::<R>(rng, num_ops_params).unwrap();

        let num_mem_params = log2(m * 2) as usize + 1;
        let mem_params = PolyCommitmentParameters::new::<R>(rng, num_mem_params).unwrap();

        let num_derefs_params = log2(n) as usize + 3; //  (3 * 2).next_power_of_two().log2();
        let derefs_params = PolyCommitmentParameters::new::<R>(rng, num_derefs_params).unwrap();

        let params = R1CSEvalsParameters::<E> {
            ops_params,
            mem_params,
            derefs_params,
        };

        Ok(params)
    }
}
