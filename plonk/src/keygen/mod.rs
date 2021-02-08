use ark_ff::FftField as Field;

use crate::composer::Composer;
use crate::Error;

mod arithmetic;
mod permutation;

pub struct ProverKey<F: Field> {
    n: usize,
    arithmetic: arithmetic::ProverKey<F>,
    permutation: permutation::ProverKey<F>,
}

pub fn generate_prover_key<F: Field>(
    cs: Composer<F>,
) -> Result<ProverKey<F>, Error> {
    let (n, selectors) = cs.compute_selectors()?;
    Ok(ProverKey {
        n: n,
        arithmetic: arithmetic::ProverKey {
            q_0: selectors.q_0,
            q_1: selectors.q_1,
            q_2: selectors.q_2,
            q_3: selectors.q_3,

            q_m: selectors.q_m,
            q_c: selectors.q_c,
            pi: selectors.pi,

            q_arith: selectors.q_arith,
        },
        permutation: permutation::ProverKey {
            sigma_0: selectors.sigma_0,
            sigma_1: selectors.sigma_1,
            sigma_2: selectors.sigma_2,
            sigma_3: selectors.sigma_3,
        },
    })
}
