use ark_ff::{FftField as Field};

// use ark_poly_commit::LinearCombination;
use ark_std::{marker::PhantomData};

use crate::composer::Error as CSError;
// use crate::utils::generator;

// mod evaluations;
// pub use evaluations::EvaluationsProvider;

mod indexer;
pub use indexer::{ArithmeticKey, Index, IndexInfo, PermutationKey};

mod prover;
pub use prover::ProverState;

mod verifier;
pub use verifier::{FirstMsg, SecondMsg, ThirdMsg, VerifierState};

pub struct AHPForPLONK<F: Field> {
    _field: PhantomData<F>,
}

// impl<F: Field> AHPForPLONK<F> {
//     pub const LABELS: [&'static str; 9] =
//         ["w_0", "w_1", "w_2", "w_3", "z", "t_0", "t_1", "t_2", "t_3"];
//
//     pub fn construct_linear_combinations(
//         info: &IndexInfo<F>,
//         first_msg: &FirstMsg<F>,
//         second_msg: &SecondMsg<F>,
//         third_msg: &ThirdMsg<F>,
//         evals: &impl EvaluationsProvider<F>,
//     ) -> Result<Vec<LinearCombination<F>>, Error> {
//         let FirstMsg { beta, gamma } = *first_msg;
//         let SecondMsg { alpha } = *second_msg;
//         let ThirdMsg { zeta } = *third_msg;
//
//         let w_0 = LinearCombination::new("w_0", vec![(F::one(), "w_0")]);
//         let w_1 = LinearCombination::new("w_1", vec![(F::one(), "w_1")]);
//         let w_2 = LinearCombination::new("w_2", vec![(F::one(), "w_2")]);
//         let w_3 = LinearCombination::new("w_3", vec![(F::one(), "w_3")]);
//
//         let z = LinearCombination::new("z", vec![(F::one(), "z")]);
//
//         let t = {
//             let zeta_n = zeta.pow(&[info.n as u64]);
//             let zeta_2n = zeta_n.square();
//
//             LinearCombination::new(
//                 "t",
//                 vec![
//                     (F::one(), "t_0"),
//                     (zeta_n, "t_1"),
//                     (zeta_2n, "t_2"),
//                     (zeta_n * zeta_2n, "t_3"),
//                 ],
//             )
//         };
//
//         //let sigma_0 = LinearCombination::new("sigma_0", vec![(F::one(), "sigma_0")]);
//         let sigma_1 = LinearCombination::new("sigma_1", vec![(F::one(), "sigma_1")]);
//         let sigma_2 = LinearCombination::new("sigma_2", vec![(F::one(), "sigma_2")]);
//         let sigma_3 = LinearCombination::new("sigma_3", vec![(F::one(), "sigma_3")]);
//
//         //let q_arith = LinearCombination::new("q_arith", vec![(F::one(), "q_arith")]);
//
//         let r = {
//             let w_0_zeta = evals.get_lc_eval(&w_0, zeta)?;
//             let w_1_zeta = evals.get_lc_eval(&w_1, zeta)?;
//             let w_2_zeta = evals.get_lc_eval(&w_2, zeta)?;
//             let w_3_zeta = evals.get_lc_eval(&w_3, zeta)?;
//
//             let shifted_zeta = zeta * generator(info.domain_n);
//             let z_shifted_zeta = evals.get_lc_eval(&z, shifted_zeta)?;
//
//             // let sigma_0_zeta = evals.get_lc_eval(&sigma_0, zeta)?;
//             // let sigma_1_zeta = evals.get_lc_eval(&sigma_1, zeta)?;
//             // let sigma_2_zeta = evals.get_lc_eval(&sigma_2, zeta)?;
//             //let q_arith_zeta = evals.get_lc_eval(&q_arith, zeta)?;
//
//             let sigma_1_zeta = evals.get_lc_eval(&sigma_1, zeta)?;
//             let sigma_2_zeta = evals.get_lc_eval(&sigma_2, zeta)?;
//             let sigma_3_zeta = evals.get_lc_eval(&sigma_3, zeta)?;
//
//             let arith_lc = ArithmeticKey::construct_linear_combination(
//                 (w_0_zeta, w_1_zeta, w_2_zeta, w_3_zeta),
//             );
//
//             let perm_lc = PermutationKey::construct_linear_combination(
//                 info.domain_n,
//                 &info.ks,
//                 (w_0_zeta, w_1_zeta, w_2_zeta, w_3_zeta),
//                 z_shifted_zeta,
//                 sigma_3_zeta,
//                 sigma_1_zeta,
//                 sigma_2_zeta,
//                 beta,
//                 gamma,
//                 alpha,
//                 zeta,
//             );
//
//             let mut r = LinearCombination::<F>::empty("r");
//             r += &arith_lc;
//             r += &perm_lc;
//             r
//         };
//
//         let mut lcs = vec![
//             w_0, w_1, w_2, w_3, z, sigma_3, sigma_1, sigma_2, t, r,
//         ];
//         lcs.sort_by(|a, b| a.label.cmp(&b.label));
//
//         Ok(lcs)
//     }
// }

#[derive(Debug)]
pub enum Error {
    SynthesisError(CSError),
    // MissingEvaluation(String),
    Other,
}

impl From<CSError> for Error {
    fn from(err: CSError) -> Error {
        Error::SynthesisError(err)
    }
}
