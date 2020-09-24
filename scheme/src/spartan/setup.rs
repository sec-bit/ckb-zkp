use crate::r1cs::SynthesisError;
use crate::spartan::data_structure::{
    MultiCommitmentSetupParameters, PolyCommitmentSetupParameters, R1CSEvalsSetupParameters,
    R1CSSatisfiedSetupParameters, SetupParametersWithSpark, SumCheckCommitmentSetupParameters,
};
use math::{log2, PairingEngine, ProjectiveCurve, UniformRand};
use rand::Rng;
use std::cmp;

pub fn generate_setup_parameters<E, R>(
    rng: &mut R,
    num_aux: usize,
    num_inputs: usize,
) -> Result<R1CSSatisfiedSetupParameters<E>, SynthesisError>
where
    E: PairingEngine,
    R: Rng,
{
    let n = log2(cmp::max(num_aux, num_inputs).next_power_of_two()) as usize;
    let pc_params = PolyCommitmentSetupParameters::new::<R>(rng, n).unwrap();
    let sc_params = R1CSSatisfiedSetupParameters::new::<R>(rng, pc_params.gen_1.clone()).unwrap();
    Ok(R1CSSatisfiedSetupParameters {
        pc_params,
        sc_params,
        n,
    })
}

pub fn generate_setup_parameters_with_spark<E, R>(
    rng: &mut R,
    num_aux: usize,
    num_inputs: usize,
    num_constraints: usize,
) -> Result<SetupParametersWithSpark<E>, SynthesisError>
where
    E: PairingEngine,
    R: Rng,
{
    let r1cs_satisfied_params =
        generate_setup_parameters::<E, R>(rng, num_aux, num_inputs).unwrap();

    let t = cmp::max(num_aux, num_inputs).next_power_of_two();
    let n = cmp::max(t * 2, num_constraints).next_power_of_two();
    let r1cs_eval_params =
        R1CSEvalsSetupParameters::new::<R>(rng, num_constraints * (t * 2), n).unwrap();
    Ok(SetupParametersWithSpark {
        r1cs_satisfied_params,
        r1cs_eval_params,
    })
}

impl<E: PairingEngine> PolyCommitmentSetupParameters<E> {
    pub fn new<R: Rng>(
        rng: &mut R,
        num: usize,
    ) -> Result<PolyCommitmentSetupParameters<E>, SynthesisError> {
        let n = (2usize).pow((num - num / 2) as u32);
        let mut generators = Vec::new();
        for _ in 0..n {
            generators.push(E::G1Projective::rand(rng).into_affine());
        }
        let h = E::G1Projective::rand(rng).into_affine();
        let gen_n = MultiCommitmentSetupParameters { n, generators, h };

        let g = E::G1Projective::rand(rng).into_affine();
        let gen_1 = MultiCommitmentSetupParameters {
            n: 1,
            generators: vec![g],
            h,
        };

        let pc_params = PolyCommitmentSetupParameters { n, gen_n, gen_1 };

        Ok(pc_params)
    }
}

impl<E: PairingEngine> R1CSSatisfiedSetupParameters<E> {
    pub fn new<R: Rng>(
        rng: &mut R,
        gen_1: MultiCommitmentSetupParameters<E>,
    ) -> Result<SumCheckCommitmentSetupParameters<E>, SynthesisError> {
        let mut n = 3;
        let mut generators = Vec::new();
        for _ in 0..n {
            generators.push(E::G1Projective::rand(rng).into_affine());
        }
        let h = E::G1Projective::rand(rng).into_affine();
        let gen_3 = MultiCommitmentSetupParameters { n, generators, h };

        n = 4;
        generators = Vec::new();
        for _ in 0..n {
            generators.push(E::G1Projective::rand(rng).into_affine());
        }
        let h = E::G1Projective::rand(rng).into_affine();
        let gen_4 = MultiCommitmentSetupParameters { n, generators, h };

        let sc_params = SumCheckCommitmentSetupParameters {
            gen_1,
            gen_3,
            gen_4,
        };

        Ok(sc_params)
    }
}

impl<E: PairingEngine> R1CSEvalsSetupParameters<E> {
    pub fn new<R: Rng>(
        rng: &mut R,
        n: usize,
        m: usize,
    ) -> Result<R1CSEvalsSetupParameters<E>, SynthesisError> {
        let num_ops_params = log2(n) as usize + 4; //  (3 * 5).next_power_of_two().log2();
        let ops_params = PolyCommitmentSetupParameters::new::<R>(rng, num_ops_params).unwrap();

        let num_mem_params = log2(m * 2) as usize + 1;
        let mem_params = PolyCommitmentSetupParameters::new::<R>(rng, num_mem_params).unwrap();

        let num_derefs_params = log2(n) as usize + 3; //  (3 * 2).next_power_of_two().log2();
        let derefs_params =
            PolyCommitmentSetupParameters::new::<R>(rng, num_derefs_params).unwrap();

        let params = R1CSEvalsSetupParameters::<E> {
            ops_params,
            mem_params,
            derefs_params,
        };

        Ok(params)
    }
}
