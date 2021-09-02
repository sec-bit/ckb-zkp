use ark_ff::FftField as Field;

use ark_poly_commit::LinearCombination;
use ark_std::{marker::PhantomData, string::String, vec, vec::Vec};

use crate::composer::Error as CSError;
use crate::utils::generator;

mod evaluations;
pub use evaluations::EvaluationsProvider;

mod indexer;
pub use indexer::{ArithmeticKey, Index, IndexInfo, PermutationKey, MimcKey};

mod prover;
pub use prover::ProverState;

mod verifier;
pub use verifier::{FirstMsg, SecondMsg, ThirdMsg, VerifierState};

pub struct AHPForPLONK<F: Field> {
    _field: PhantomData<F>,
}

impl<F: Field> AHPForPLONK<F> {
    pub const LABELS: [&'static str; 9] =
        ["w_0", "w_1", "w_2", "w_3", "z", "t_0", "t_1", "t_2", "t_3"];

    pub fn construct_linear_combinations(
        info: &IndexInfo<F>,
        first_msg: &FirstMsg<F>,
        second_msg: &SecondMsg<F>,
        third_msg: &ThirdMsg<F>,
        evals: &impl EvaluationsProvider<F>,
    ) -> Result<Vec<LinearCombination<F>>, Error> {
        let FirstMsg { beta, gamma } = *first_msg;
        let SecondMsg { alpha } = *second_msg;
        let ThirdMsg { zeta } = *third_msg;

        let w_0 = LinearCombination::new("w_0", vec![(F::one(), "w_0")]);
        let w_1 = LinearCombination::new("w_1", vec![(F::one(), "w_1")]);
        let w_2 = LinearCombination::new("w_2", vec![(F::one(), "w_2")]);
        let w_3 = LinearCombination::new("w_3", vec![(F::one(), "w_3")]);

        let z = LinearCombination::new("z", vec![(F::one(), "z")]);

        let t = {
            let zeta_n = zeta.pow(&[info.n as u64]);
            let zeta_2n = zeta_n.square();

            LinearCombination::new(
                "t",
                vec![
                    (F::one(), "t_0"),
                    (zeta_n, "t_1"),
                    (zeta_2n, "t_2"),
                    (zeta_n * zeta_2n, "t_3"),
                ],
            )
        };

        let sigma_0 = LinearCombination::new("sigma_0", vec![(F::one(), "sigma_0")]);
        let sigma_1 = LinearCombination::new("sigma_1", vec![(F::one(), "sigma_1")]);
        let sigma_2 = LinearCombination::new("sigma_2", vec![(F::one(), "sigma_2")]);

        let q_arith = LinearCombination::new("q_arith", vec![(F::one(), "q_arith")]);

        //let q_mimc_c = LinearCombination::new("q_mimc_c", vec![(F::one(), "q_mimc_c")]);

        let r = {
            //按标签找到多项式，并得到点zeta（w zeta）处的值
            let w_0_zeta = evals.get_lc_eval(&w_0, zeta)?;
            let w_1_zeta = evals.get_lc_eval(&w_1, zeta)?;
            let w_2_zeta = evals.get_lc_eval(&w_2, zeta)?;
            let w_3_zeta = evals.get_lc_eval(&w_3, zeta)?;

            let shifted_zeta = zeta * generator(info.domain_n);
            let z_shifted_zeta = evals.get_lc_eval(&z, shifted_zeta)?;

            let w_0_shifted_zeta = evals.get_lc_eval(&w_0, shifted_zeta)?;

            let sigma_0_zeta = evals.get_lc_eval(&sigma_0, zeta)?;
            let sigma_1_zeta = evals.get_lc_eval(&sigma_1, zeta)?;
            let sigma_2_zeta = evals.get_lc_eval(&sigma_2, zeta)?;
            let q_arith_zeta = evals.get_lc_eval(&q_arith, zeta)?;

            //let q_mimc_c_zeta = evals.get_lc_eval(&q_mimc_c, zeta)?;

            let arith_lc = ArithmeticKey::construct_linear_combination(
                (w_0_zeta, w_1_zeta, w_2_zeta, w_3_zeta),
                q_arith_zeta,
            );

            let perm_lc = PermutationKey::construct_linear_combination(
                info.domain_n,
                &info.ks,
                (w_0_zeta, w_1_zeta, w_2_zeta, w_3_zeta),
                z_shifted_zeta,
                sigma_0_zeta,
                sigma_1_zeta,
                sigma_2_zeta,
                beta,
                gamma,
                alpha,
                zeta,
            );

            let range_lc = Index::construct_linear_combination_q_range(
                (w_0_zeta, w_1_zeta, w_2_zeta, w_3_zeta),
                w_0_shifted_zeta,
                alpha,
            );

            // let mimc_lc = MimcKey::construct_linear_combination (
            //     (w_0_zeta, w_1_zeta, w_2_zeta, w_3_zeta),
            //     w_0_shifted_zeta,
            //     alpha,
            // );
            let mimc_lc = MimcKey::construct_linear_combination_nosponge (
                (w_0_zeta, w_1_zeta, w_2_zeta, w_3_zeta),
                w_0_shifted_zeta,
                alpha,
            );

            //todo 这里不用排序
            let mut r = LinearCombination::<F>::empty("r");
            r += &arith_lc;
            r += &perm_lc;
            r += &range_lc;
            r += &mimc_lc;
            r
        };

        let mut lcs = vec![
            w_0, w_1, w_2, w_3, z, sigma_0, sigma_1, sigma_2, q_arith, t, r,
        ];
        lcs.sort_by(|a, b| a.label.cmp(&b.label));

        Ok(lcs)
    }
}

#[derive(Debug)]
pub enum Error {
    SynthesisError(CSError),
    MissingEvaluation(String),
    Other,
}

impl From<CSError> for Error {
    fn from(err: CSError) -> Error {
        Error::SynthesisError(err)
    }
}

#[cfg(test)]
mod test {
    use ark_poly_commit::Evaluations;
    use ark_std::test_rng;

    use super::*;

    #[test]
    fn ahp() -> Result<(), Error> {
        //let cs = crate::tests::circuit();
        let cs = crate::tests::circuit();
        let ks = crate::tests::ks();
        let rng = &mut test_rng();
        println!("circuit size: {}", cs.size());

        let index = AHPForPLONK::index(&cs, ks)?;
        println!("index size: {}", index.size());
        let ps = AHPForPLONK::prover_init(&cs, &index)?;
        let vs = AHPForPLONK::verifier_init(&index.info)?;

        let (ps, first_oracles) = AHPForPLONK::prover_first_round(ps, &cs)?;
        let (vs, first_msg) = AHPForPLONK::verifier_first_round(vs, rng)?;

        let (ps, second_oracles) = AHPForPLONK::prover_second_round(ps, &first_msg, &ks)?;
        let (vs, second_msg) = AHPForPLONK::verifier_second_round(vs, rng)?;

        let third_oracles = AHPForPLONK::prover_third_round(ps, &second_msg, &ks)?;
        let (vs, third_msg) = AHPForPLONK::verifier_third_round(vs, rng)?;

        let polynomials: Vec<_> = index
            .iter()
            .chain(first_oracles.iter())
            .chain(second_oracles.iter())
            .chain(third_oracles.iter())
            .collect();

        let lcs = AHPForPLONK::construct_linear_combinations(
            &index.info,
            &first_msg,
            &second_msg,
            &third_msg,
            &polynomials,
        )?;

        let evaluations = {
            let query_set = AHPForPLONK::verifier_query_set(&vs);

            let evals: Vec<_> = {
                let mut evals = Vec::new();
                for (label, (_, point)) in &query_set {
                    let lc = lcs
                        .iter()
                        .find(|lc| &lc.label == label)
                        .ok_or_else(|| Error::MissingEvaluation(label.to_string()))?;
                    let eval = polynomials.get_lc_eval(&lc, *point)?;
                    evals.push((label.to_string(), eval));
                }
                evals.sort_by(|a, b| a.0.cmp(&b.0));
                evals.into_iter().map(|x| x.1).collect()
            };

            let mut evaluation_labels: Vec<_> = query_set
                .iter()
                .cloned()
                .map(|(l, (_, p))| (l, p))
                .collect();
            evaluation_labels.sort_by(|a, b| a.0.cmp(&b.0));

            let mut evaluations = Evaluations::new();
            for (q, eval) in evaluation_labels.into_iter().zip(&evals) {
                evaluations.insert(q, *eval);
            }
            evaluations
        };

        let is_equal = AHPForPLONK::verifier_equality_check(&vs, &evaluations, cs.public_inputs())?;

        assert!(is_equal);
        Ok(())
    }
}
