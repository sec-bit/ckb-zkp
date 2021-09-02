//! An implementation of the [`PlonK`].
//!
//! [`PlonK`]: https://eprint.iacr.org/2019/953.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(clippy::op_ref, clippy::suspicious_op_assign_impl)]
#![cfg_attr(not(use_asm), forbid(unsafe_code))]
#![cfg_attr(use_asm, feature(llvm_asm))]
#![cfg_attr(use_asm, deny(unsafe_code))]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as Map;

#[cfg(feature = "std")]
use std::collections::HashMap as Map;

use ark_ff::{to_bytes, FftField as Field};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{Evaluations, LabeledCommitment, PCUniversalParams, PolynomialCommitment};

use ark_std::{marker::PhantomData, string::ToString, vec, vec::Vec};
use digest::Digest;
use rand_core::RngCore;

mod error;
use error::Error;

mod data_structures;
pub use crate::data_structures::*;

mod composer;
pub use crate::composer::Composer;

mod ahp;
use ahp::{AHPForPLONK, EvaluationsProvider};

mod rng;
use crate::rng::FiatShamirRng;

mod utils;

pub struct Plonk<F: Field, D: Digest, PC: PolynomialCommitment<F, DensePolynomial<F>>> {
    _field: PhantomData<F>,
    _digest: PhantomData<D>,
    _pc: PhantomData<PC>,
}

impl<F: Field, D: Digest, PC: PolynomialCommitment<F, DensePolynomial<F>>> Plonk<F, D, PC> {
    pub const PROTOCOL_NAME: &'static [u8] = b"PLONK";

    //多项式承诺的setup
    pub fn setup<R: RngCore>(
        max_degree: usize,
        rng: &mut R,
    ) -> Result<UniversalParams<F, PC>, Error<PC::Error>> {
        PC::setup(max_degree, None, rng).map_err(Error::from_pc_err)
    }

    #[allow(clippy::type_complexity)]
    pub fn keygen(
        srs: &UniversalParams<F, PC>,
        cs: &Composer<F>,
        ks: [F; 4],
    ) -> Result<(ProverKey<F, PC>, VerifierKey<F, PC>), Error<PC::Error>> {
        let index = AHPForPLONK::index(cs, ks)?;
        if srs.max_degree() < index.size() {
            return Err(Error::CircuitTooLarge);
        }

        let (ck, vk) = PC::trim(srs, index.size(), 0, None).map_err(Error::from_pc_err)?;
        //index.iter就是arithmetic.iter连接上permutation.iter，实质是 LabeledPolynomial表示的q0 q1 ...(arithmetickey里) 和 sigma0123（PermutationKey里）
        //pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        //         self.arithmetic.iter().chain(self.permutation.iter())
        //     }
        //依次为[q0], [q1], [q2], [q3], [qm], [qc], [qarith], [sigma_0], [sigma_1], [sigma_2], [sigma_3], [qrange], [q_mimc]
        let (comms, rands) = PC::commit(&ck, index.iter(), None).map_err(Error::from_pc_err)?;
        let labels = comms.iter().map(|c| c.label().clone()).collect();
        let comms = comms.iter().map(|c| c.commitment().clone()).collect();

        // for label in &labels {
        //     println!("{}", label);
        // }

        let vk = VerifierKey {
            comms,
            labels,
            rk: vk,
            info: index.info.clone(),
        };
        let pk = ProverKey {
            vk: vk.clone(),
            index,
            rands, //KZG10的PC里，每个comm都要带一个随机数用于遮蔽
            ck,
        };

        Ok((pk, vk))
    }

    pub fn prove(
        pk: &ProverKey<F, PC>,
        cs: &Composer<F>,
        zk_rng: &mut dyn RngCore,
    ) -> Result<Proof<F, PC>, Error<PC::Error>> {
        let public_inputs = cs.public_inputs();

        let mut fs_rng =
            FiatShamirRng::<D>::from_seed(&to_bytes![&Self::PROTOCOL_NAME, public_inputs].unwrap());

        let ps = AHPForPLONK::prover_init(cs, &pk.index)?;
        let vs = AHPForPLONK::verifier_init(&pk.vk.info)?;

        let (ps, first_oracles) = AHPForPLONK::prover_first_round(ps, &cs)?;
        let (first_comms, first_rands) =
            PC::commit(&pk.ck, first_oracles.iter(), Some(zk_rng)).map_err(Error::from_pc_err)?;
        fs_rng.absorb(&to_bytes![first_comms].unwrap());
        let (vs, first_msg) = AHPForPLONK::verifier_first_round(vs, &mut fs_rng)?;

        let (ps, second_oracles) =
            AHPForPLONK::prover_second_round(ps, &first_msg, &pk.vk.info.ks)?;
        let (second_comms, second_rands) =
            PC::commit(&pk.ck, second_oracles.iter(), Some(zk_rng)).map_err(Error::from_pc_err)?;
        fs_rng.absorb(&to_bytes![second_comms].unwrap());
        let (vs, second_msg) = AHPForPLONK::verifier_second_round(vs, &mut fs_rng)?;

        let third_oracles = AHPForPLONK::prover_third_round(ps, &second_msg, &pk.vk.info.ks)?;
        let (third_comms, third_rands) =
            PC::commit(&pk.ck, third_oracles.iter(), Some(zk_rng)).map_err(Error::from_pc_err)?;
        fs_rng.absorb(&to_bytes![third_comms].unwrap());
        let (vs, third_msg) = AHPForPLONK::verifier_third_round(vs, &mut fs_rng)?;

        let polynomials: Vec<_> = pk
            //q。。一堆
            .index.iter()
            //w0123
            .chain(first_oracles.iter())
            //z
            .chain(second_oracles.iter())
            //t0123
            .chain(third_oracles.iter())
            .collect();

        //取labeledcommi的commi（二维向量）
        let commitments = vec![
            first_comms.iter().map(|c| c.commitment().clone()).collect(),
            second_comms.iter().map(|c| c.commitment().clone()).collect(),
            third_comms.iter().map(|c| c.commitment().clone()).collect(),
        ];

        //vk里的commitment（q0123..），然后是三个round的labeledcomms
        let labeled_commitments: Vec<_> = pk
            .vk
            .comms.iter().cloned()
            .zip(pk.vk.labels.iter())
            .map(|(c, l)| LabeledCommitment::new(l.to_string(), c, None))
            .chain(first_comms.iter().cloned())
            .chain(second_comms.iter().cloned())
            .chain(third_comms.iter().cloned())
            .collect();

        let randomnesses: Vec<_> = pk
            .rands.iter()
            .chain(first_rands.iter())
            .chain(second_rands.iter())
            .chain(third_rands.iter())
            .collect();

        //合并一些多项式为r后，需要commit和open的多项式们
        //只是标记了’哪些多项式‘会在哪个点open
        let qs = AHPForPLONK::verifier_query_set(&vs);
        //优化2：把多项式们 线性组合(r在里面现场构造)，lcs已排序
        let lcs = AHPForPLONK::construct_linear_combinations(
            &pk.vk.info,
            &first_msg,
            &second_msg,
            &third_msg,
            &polynomials,
        )?;

        //qs中的多项式进行open，并排序
        let evaluations: Vec<_> = {
            let mut evals = Vec::new();
            for (label, (_, point)) in &qs {
                //对于qs中的每一个标签，从lcs中找到对应的多项式并open
                let lc = lcs.iter()
                    .find(|lc| &lc.label == label)
                    .ok_or_else(|| Error::MissingEvaluation(label.to_string()))?;
                //open的值
                let eval = polynomials.get_lc_eval(&lc, *point)?;
                evals.push((label.to_string(), eval));
            }
            evals.sort_by(|a, b| a.0.cmp(&b.0));
            evals.into_iter().map(|x| x.1).collect()
        };
        //evaluation生成epsilon
        fs_rng.absorb(&evaluations);
        let epsilon = F::rand(&mut fs_rng);

        //优化2：一堆多项式的线性组合只需要一个proof就可以验证commitment是否与open相符
        //epsilon是pdf里W的v吗（可以只用一个随机数
        let pc_proof = PC::open_combinations(
            &pk.ck,
            &lcs,
            polynomials,
            &labeled_commitments,
            &qs,
            epsilon,
            randomnesses,
            Some(zk_rng),
        )
        .map_err(Error::from_pc_err)?;
        let proof = Proof {
            commitments,
            evaluations, //无label的
            pc_proof,
        };
        Ok(proof)
    }

    pub fn verify(
        vk: &VerifierKey<F, PC>,
        public_inputs: &[F],
        proof: Proof<F, PC>,
    ) -> Result<bool, Error<PC::Error>> {
        //alpha beta gamma 这些要通过协议交互过程自己计算出来
        let vs = AHPForPLONK::verifier_init(&vk.info)?;
        let mut fs_rng =
            FiatShamirRng::<D>::from_seed(&to_bytes![&Self::PROTOCOL_NAME, public_inputs].unwrap());

        let first_comms = &proof.commitments[0];
        fs_rng.absorb(&to_bytes![first_comms].unwrap());
        let (vs, first_msg) = AHPForPLONK::verifier_first_round(vs, &mut fs_rng)?;

        let second_comms = &proof.commitments[1];
        fs_rng.absorb(&to_bytes![second_comms].unwrap());
        let (vs, second_msg) = AHPForPLONK::verifier_second_round(vs, &mut fs_rng)?;

        let third_comms = &proof.commitments[2];
        fs_rng.absorb(&to_bytes![third_comms].unwrap());
        let (vs, third_msg) = AHPForPLONK::verifier_third_round(vs, &mut fs_rng)?;

        //只是标记了’哪些多项式‘会在哪个点open
        let query_set = AHPForPLONK::verifier_query_set(&vs);
        fs_rng.absorb(&proof.evaluations);
        let epsilon = F::rand(&mut fs_rng);

        //接口？
        //qs中的多项式的label排序，然后和proof里对应的值 组合在一起
        let evaluations = {
            let mut evaluation_labels: Vec<_> = query_set
                .iter().cloned()
                .map(|(l, (_, p))| (l, p))
                .collect();
            evaluation_labels.sort_by(|a, b| a.0.cmp(&b.0));

            let mut evaluations = Evaluations::new();
            for (q, eval) in evaluation_labels.into_iter().zip(&proof.evaluations) {
                evaluations.insert(q, *eval);
            }
            evaluations
        };

        //验证’最终大等式‘是否相等
        // if !AHPForPLONK::verifier_equality_check(&vs, &evaluations, public_inputs)? {
        //     return Ok(false);
        // };
        let tmp = AHPForPLONK::verifier_equality_check(&vs, &evaluations, public_inputs)?;
        assert_eq!(tmp, true);

        let pc_check = {
            let labels: Vec<_> = vk
                .labels.iter().cloned()
                .chain(AHPForPLONK::<F>::LABELS.iter().map(|l| l.to_string()))
                .collect();

            //和labels一一对应，组合成LabeledCommitment
            let labeled_commitments: Vec<_> = vk
                .comms.iter().cloned()
                //w0 w1 w2 w3
                .chain(first_comms.iter().cloned())
                //z
                .chain(second_comms.iter().cloned())
                //t0 t1 t2 t3
                .chain(third_comms.iter().cloned())
                .zip(labels.iter())
                .map(|(c, l)| LabeledCommitment::new(l.to_string(), c, None))
                .collect();

            //evals既可以像这里 直接接收evaluations，也可以像prover那里接收Vec<Borrow<LabeledPolynomial<F>>>。（因为evaluations.rs里给它实现了
            let lcs = AHPForPLONK::construct_linear_combinations(
                &vk.info,
                &first_msg,
                &second_msg,
                &third_msg,
                &evaluations,
            )?;

            PC::check_combinations(
                &vk.rk,
                &lcs,
                &labeled_commitments,
                &query_set,
                &evaluations,
                &proof.pc_proof,
                epsilon,
                &mut ark_std::test_rng(), // we now impl default rng (not use)
            )
            .map_err(Error::from_pc_err)?
        };
        Ok(pc_check)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::{One, Zero, Field};
    use ark_poly_commit::{marlin_pc::MarlinKZG10, Error as PCError};
    use ark_std::test_rng;

    use blake2::Blake2s;

    use crate::composer::Composer;

    use super::*;
    use crate::composer::range::RangeType;

    type PC = MarlinKZG10<Bls12_381, DensePolynomial<Fr>>;
    type PlonkInst = Plonk<Fr, Blake2s, PC>;

    pub fn ks() -> [Fr; 4] {
        [
            Fr::one(),
            Fr::from(7_u64),
            Fr::from(13_u64),
            Fr::from(17_u64),
        ]
    }

    pub fn circuit() -> Composer<Fr> {
        let mut cs = Composer::new();
        let mimc_c = vec![Fr::zero(), Fr::one(), Fr::one(), Fr::one(), Fr::zero()];
        //cs.init_mimc(mimc_c);
        let one = Fr::one();
        let two = one + one;
        let three = two + one;
        let four = two + two;
        let six = two + four;
        let var_one = cs.alloc_and_assign(one);
        let var_two = cs.alloc_and_assign(two);
        let var_three = cs.alloc_and_assign(three);
        let var_four = cs.alloc_and_assign(four);
        let var_six = cs.alloc_and_assign(six);
        cs.create_add_gate(
            (var_one, one),
            (var_two, one),
            var_three,
            None,
            Fr::zero(),
            Fr::zero(),
        );
        cs.create_add_gate(
            (var_one, one),
            (var_three, one),
            var_four,
            None,
            Fr::zero(),
            Fr::zero(),
        );
        cs.create_mul_gate(
            var_two,
            var_two,
            var_four,
            None,
            Fr::one(),
            Fr::zero(),
            Fr::zero(),
        );
        cs.create_mul_gate(var_one, var_two, var_six, None, two, two, Fr::zero());
        cs.constrain_to_constant(var_six, six, Fr::zero());

        cs
    }

    pub fn my_circuit() -> Composer<Fr> { //v神文章里的电路x**3+x+5，设x=1，输出7
        let mut cs = Composer::new();
        let mimc_c = vec![Fr::zero(), Fr::zero(), Fr::one(), Fr::one(), Fr::zero()];
        let mimc_c = vec![Fr::one()];
        cs.init_mimc(2,mimc_c);
        let one = Fr::one();
        let two = one.double();
        let three = one + two;
        let four = two.double();
        let eight = four.double();
        let five = one + four;
        let seven = five + two;
        let nine = three.square();

        let fv11 = nine + two;
        let fv1332 = fv11.square() * fv11 + one;
        let fv1330 = fv1332 - two;
        //var是变量，变量本身就代表了copy constraint的信息，在add gate的时候会处理
        //这里变量里存的值代表这个变量的唯一编号
        let var_1 = cs.alloc_and_assign(one); //x
        let var_2 = cs.alloc_and_assign(one); //乘法门1的out
        let var_3 = cs.alloc_and_assign(one); //乘法门2的out
        //let var_4 = cs.alloc_and_assign(ten); //加法门1的out
        //let var_5 = cs.alloc_and_assign(five); //加法门2的另一个in 5
        let var_6 = cs.alloc_and_assign(fv1332);

        cs.create_add_gate( //v1 + v3 + 5 = v6
            (var_1, one),
            (var_3, one),
            var_6,
            None,
            fv1330, //加法门2的另一个in 5
            Fr::zero(),
        );
        cs.create_mul_gate(
            var_1,
            var_1,
            var_2,
            None,
            Fr::one(),
            Fr::zero(),
            Fr::zero(),
        );
        cs.create_mul_gate(
            var_2,
            var_1,
            var_3,
            None,
            Fr::one(),
            Fr::zero(),
            Fr::zero(),
        );
        cs.constrain_to_constant(var_6, fv1332, Fr::zero());

        cs.create_range_gate(
            var_6,
            RangeType::U16,
        );

        let FV8 = four.double();
        //println!("{}", FV128);
        // let test_c = vec![Fr::zero(),Fr::one()];
        // let mimc_hash = cs.create_mimc_hash(
        //     var_6,
        //     test_c,
        // );
        let mimc_hash = cs.create_mimc_hash_no_sponge(
            var_6,
            one,
            two,
        );

        println!("{}", mimc_hash);

        cs
    }

    #[test]
    fn test_plonk() -> Result<(), Error<PCError>> {
        let rng = &mut test_rng();

        // compose
        let cs = my_circuit();
        //let cs = circuit(); //过了
        let ks = ks();
        println!("size of the circuit: {}", cs.size());

        let srs = PlonkInst::setup(16, rng)?;
        let (pk, vk) = PlonkInst::keygen(&srs, &cs, ks)?;
        let proof = PlonkInst::prove(&pk, &cs, rng)?;
        let result = PlonkInst::verify(&vk, cs.public_inputs(), proof)?;
        assert_eq!(result, true);
        //assert!(result);
        Ok(())
    }
}
