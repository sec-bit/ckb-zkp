use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_poly::polynomial::univariate::DensePolynomial;

use ark_poly_commit::kzg10::Commitment;

use std::ops::AddAssign;
use std::ops::SubAssign;
use std::ops::Div;
use ark_ec::msm::FixedBaseMSM;
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, UVPolynomial};
use rand_core::RngCore;
use crate::ahp::VerifierState;
use crate::{Proof, VerifierKey};
use crate::utils::{evaluate_first_lagrange_poly, evaluate_vanishing_poly, generator, pad_to_size};

pub type LabeledPolynomial<F> = ark_poly_commit::LabeledPolynomial<F, DensePolynomial<F>>;

pub struct PCKey<E: PairingEngine> {
    /// The key used to commit to polynomials.
    pub powers: Vec<E::G1Affine>,
    /// The maximum degree supported by the `UniversalParams` `self` was derived from.
    pub max_degree: usize,

    pub vk: VKey<E>,
}

#[derive(Clone, Copy)]
pub struct VKey<E: PairingEngine> {
    /// The generator of G1.
    pub g: E::G1Affine,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
}

impl<E: PairingEngine> PCKey<E> {

    pub fn setup<R>(max_degree :usize, rng: &mut R) -> Self
        where
            R: RngCore,
    {
        println!("[setup] start to setup...");
        let beta = E::Fr::rand(rng);
        let g = E::G1Projective::rand(rng);
        // let g = E::AFFINE_GENERATOR_COEFFS;
        let h = E::G2Projective::rand(rng);
        println!("[setup] generate...ok.");

        let mut powers_of_beta = vec![E::Fr::one()];

        let mut cur = beta;
        for _ in 0..max_degree {
            powers_of_beta.push(cur);
            cur *= &beta;
        }

        let window_size = FixedBaseMSM::get_mul_window_size(max_degree + 1);

        let scalar_bits = E::Fr::size_in_bits();
        let g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, g);
        let powers_of_g = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(
            scalar_bits,
            window_size,
            &g_table,
            &powers_of_beta,
        );
        let powers_of_g = E::G1Projective::batch_normalization_into_affine(&powers_of_g);

        println!("[setup] generate powers_of_g1...ok. max_degree = {}", max_degree);


        let vk = VKey::<E>{
            g: g.into_affine(),
            h: h.into_affine(),
            beta_h: h.into_affine().mul(beta).into_affine(),
        };
        let pckey = PCKey::<E>{
            powers: powers_of_g,
            max_degree,
            vk: vk.clone(),
        };
        println!("[setup]finish.");
        pckey

    }

    pub fn commit_vec<'a>(
        &mut self,
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<E::Fr>>,
    ) -> Vec<Commitment<E>>
    {
        let mut comms = Vec::new();
        for polynomial in polynomials {
            let comm = self.commit_one(polynomial);
            comms.push(comm);
        }
        comms
    }

    pub fn commit_one(
        &mut self,
        polynomial: &LabeledPolynomial<E::Fr>
    )-> Commitment<E>
    {
        // assert!(num_coefficient > 1);
        // assert!(num_coefficient <= num_powers);

        let coe = polynomial.coeffs.clone();

        let mut commit = E::G1Projective::zero();
        for (e, b) in coe.iter().zip(self.powers.iter()) {
            let b = b.into_projective();
            commit.add_assign(&b.mul(e.into_repr()));
        }

        let c =  Commitment::<E>{
            0: commit.into_affine(),
        };
        c
    }

    pub fn open_one(
        &mut self,
        polynomial: &LabeledPolynomial<E::Fr>,
        point: E::Fr,
    )-> (Commitment<E>, E::Fr)
    {
        //assert!(num_coefficient > 1);
        // assert!(num_coefficient <= num_powers);

        let coe = polynomial.coeffs.clone();
        let value = polynomial.evaluate(&point);

        let mut neg_point = E::Fr::zero();
        neg_point.sub_assign(&point);
        let divisor = DensePolynomial::from_coefficients_vec(vec![neg_point, E::Fr::one()]);
        //no need to -value, the result is the same
        let p = DensePolynomial::from_coefficients_vec(coe);
        let witness_polynomial = p.div(&divisor);

        let mut witness = E::G1Projective::zero();
        for (e, b) in witness_polynomial.coeffs.iter().zip(self.powers.iter()) {
            let b = b.into_projective();
            witness.add_assign(&b.mul(e.into_repr()));
        }

        let c =  Commitment::<E>{
            0: witness.into_affine(),
        };

        (c, value)
    }

    pub fn compute_opening_evaluations<'a>(
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<E::Fr>>,
        point: E::Fr,
    ) -> Vec<E::Fr>{
        let mut evals = Vec::new();
        for polynomial in polynomials {
            let value = polynomial.evaluate(&point);
            evals.push(value);
        }
        evals
    }

    pub fn compute_full_t<'a>(
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<E::Fr>>,
    ) -> LabeledPolynomial<E::Fr>{

        let mut coes = Vec::new();
        for polynomial in polynomials {
            let mut tmp = polynomial.coeffs.clone();
            coes.append(&mut tmp);
        }

        let p = DensePolynomial::from_coefficients_vec(coes);
        LabeledPolynomial::<E::Fr>::new("t".into(), p, None, None)
    }

    pub fn compute_full_r<'a>(
        domain_size: usize,
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<E::Fr>>,
        evals: Vec<E::Fr>,
        beta: E::Fr,
        gamma: E::Fr,
        alpha: E::Fr,
        zeta: E::Fr,
        ks: &[E::Fr; 4],
        l1_zeta: E::Fr,
    ) -> LabeledPolynomial<E::Fr>{
        //poly: q0 q1 q2 q3 qm qc sigma_0 1 2 3, z
        //evals: q0 q1 q2 q3 qm qc sigma_0 1 2 3, w0123, z, t1234, full_t, z^
        let alpha_2 = alpha.square();

        let mut polycoes = Vec::new();
        for polynomial in polynomials {
            //When a polynomial has all 0 coefficients, 'tmp' is an empty vec
            let mut tmp = polynomial.coeffs.clone();
            if tmp.is_empty() {
                tmp = vec![E::Fr::zero(); domain_size];
            }
            polycoes.push(tmp);
        }

        let mut coe_r = Vec::new();
        for i in 0..domain_size {
            let tmp: E::Fr =
                polycoes[0][i].clone()*evals[10] + polycoes[1][i].clone()*evals[11] + polycoes[2][i].clone()*evals[12] + polycoes[3][i].clone()*evals[13]
                + polycoes[4][i].clone()*evals[11]*evals[12] + polycoes[5][i].clone()

                + alpha * polycoes[10][i].clone()
                * (evals[10] + beta*ks[0]*zeta + gamma)
                * (evals[11] + beta*ks[1]*zeta + gamma)
                * (evals[12] + beta*ks[2]*zeta + gamma)
                * (evals[13] + beta*ks[3]*zeta + gamma)

                - alpha * beta * evals[20] * polycoes[6][i].clone()
                * (evals[11] + beta*evals[7] + gamma)
                * (evals[12] + beta*evals[8] + gamma)
                * (evals[13] + beta*evals[9] + gamma)

                + l1_zeta * alpha_2 * polycoes[10][i].clone();
            coe_r.push(tmp);
        }

        let r = DensePolynomial::from_coefficients_vec(coe_r);
        LabeledPolynomial::<E::Fr>::new("r".into(), r, None, None)
    }

    pub fn compute_comm_eval_of_r(
        comms: Vec<Commitment::<E>>,
        evals: Vec<E::Fr>,
        beta: E::Fr,
        gamma: E::Fr,
        alpha: E::Fr,
        zeta: E::Fr,
        ks: &[E::Fr; 4],
        l1_zeta: E::Fr,
    ) -> (Commitment<E>, E::Fr){
        //comms: q0 q1 q2 q3 qm qc sigma_0 1 2 3, w0123, z, t1234
        //evals: q0 q1 q2 q3 qm qc sigma_0 1 2 3, w0123, z, t1234, full_t, z^

        let alpha_2 = alpha.square();

        let comm_r = comms[0].0.into_projective().mul(evals[10].into_repr())
            + comms[1].0.into_projective().mul(evals[11].into_repr())
            + comms[2].0.into_projective().mul(evals[12].into_repr())
            + comms[3].0.into_projective().mul(evals[13].into_repr())
            + comms[4].0.into_projective().mul((evals[11] * evals[12]).into_repr())
            + comms[5].0.into_projective()

            + comms[14].0.into_projective()
                .mul((alpha * (evals[10] + beta*ks[0]*zeta + gamma)
                        * (evals[11] + beta*ks[1]*zeta + gamma)
                        * (evals[12] + beta*ks[2]*zeta + gamma)
                        * (evals[13] + beta*ks[3]*zeta + gamma)).into_repr())

            - comms[6].0.into_projective()
                .mul((alpha * beta * evals[20]
                    * (evals[11] + beta*evals[7] + gamma)
                    * (evals[12] + beta*evals[8] + gamma)
                    * (evals[13] + beta*evals[9] + gamma)).into_repr())

            + comms[14].0.into_projective()
                .mul((l1_zeta * alpha_2).into_repr());

        let eval_r =
            evals[0]*evals[10] + evals[1]*evals[11] + evals[2]*evals[12] + evals[3]*evals[13]
            + evals[4]*evals[11]*evals[12] + evals[5]

            + alpha * evals[14]
                * (evals[10] + beta*ks[0]*zeta + gamma)
                * (evals[11] + beta*ks[1]*zeta + gamma)
                * (evals[12] + beta*ks[2]*zeta + gamma)
                * (evals[13] + beta*ks[3]*zeta + gamma)

            - alpha * beta * evals[20] * evals[6]
                * (evals[11] + beta*evals[7] + gamma)
                * (evals[12] + beta*evals[8] + gamma)
                * (evals[13] + beta*evals[9] + gamma)

            + l1_zeta * alpha_2 * evals[14];


        let comm_r =  Commitment::<E>{
            0: comm_r.into_affine(),
        };

        (comm_r, eval_r)

    }

    pub fn compute_opening_proof_comm_w<'a>(
        &mut self,
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<E::Fr>>,
        zeta: E::Fr,
        v: E::Fr,
        domain_size: usize,
    ) -> Commitment<E> {
        //poly: q0 q1 q2 q3 qm qc sigma_0 1 2 3, w0123, z, t1234, r
        let polys: Vec<LabeledPolynomial<E::Fr>> = polynomials.into_iter().cloned().collect();

        let zeta_n = zeta.pow(E::Fr::from(domain_size as u128).into_repr());
        let zeta_2n = zeta_n.square();
        let zeta_3n: E::Fr = zeta_n * zeta_2n;

        let mut tmp_t_coes = Vec::new();
        let t1_coe = polys[15].coeffs.clone();
        let t2_coe = polys[16].coeffs.clone();
        let t3_coe = polys[17].coeffs.clone();
        let mut t4_coe = polys[18].coeffs.clone();
        for _ in 0..domain_size {
            t4_coe.push(E::Fr::zero());
        }
        for i in 0..domain_size {
            let tmp = t1_coe[i] + t2_coe[i]*zeta_n + t3_coe[i]*zeta_2n + t4_coe[i]*zeta_3n;
            tmp_t_coes.push(tmp);
        }

        let mut neg_point = E::Fr::zero();
        neg_point.sub_assign(&zeta);
        let divisor = DensePolynomial::from_coefficients_vec(vec![neg_point, E::Fr::one()]);
        let p = DensePolynomial::from_coefficients_vec(tmp_t_coes);
        let witness_polynomial = p.div(&divisor);

        let mut t_part_open = E::G1Projective::zero();
        for (e, b) in witness_polynomial.coeffs.iter().zip(self.powers.iter()) {
            let b = b.into_projective();
            t_part_open.add_assign(&b.mul(e.into_repr()));
        }

        let (r,_) = self.open_one(&polys[19], zeta);
        let (w1,_) = self.open_one(&polys[11], zeta);
        let (w2,_) = self.open_one(&polys[12], zeta);
        let (w3,_) = self.open_one(&polys[13], zeta);
        let (w0,_) = self.open_one(&polys[10], zeta);
        let (sigma_1,_) = self.open_one(&polys[7], zeta);
        let (sigma_2,_) = self.open_one(&polys[8], zeta);
        let (sigma_3,_) = self.open_one(&polys[9], zeta);

        let v_2 = v.square();
        let v_3 = v*v_2;
        let v_4 = v_2.square();
        let v_5 = v*v_4;
        let v_6 = v*v_5;
        let v_7 = v*v_6;
        let v_8 = v*v_7;

        let w = t_part_open + r.0.into_projective().mul(v.into_repr())
            + w1.0.into_projective().mul(v_2.into_repr())
            + w2.0.into_projective().mul(v_3.into_repr())
            + w3.0.into_projective().mul(v_4.into_repr())
            + w0.0.into_projective().mul(v_5.into_repr())
            + sigma_1.0.into_projective().mul(v_6.into_repr())
            + sigma_2.0.into_projective().mul(v_7.into_repr())
            + sigma_3.0.into_projective().mul(v_8.into_repr());

        Commitment::<E>{
            0: w.into_affine(),
        }
    }

    pub fn verify_pc(
        &mut self,
        vs: &VerifierState<'_, E::Fr>,
        vk: &VerifierKey<E>,
        proof: &Proof<E>,
        v: E::Fr,
        u: E::Fr,
    ) -> bool {
        //q0 q1 q2 q3 qm qc sigma_0 1 2 3
        let comms1 = vk.comms.clone();
        // [w0123] [z] [t1234]
        let comms2 = proof.commitments.clone();
        //w123 0, sigma_1 2 3, z^, t,  r
        let evals = proof.evaluations.clone();

        let ks = vk.info.ks;
        let alpha = vs.alpha.unwrap();
        let beta = vs.beta.unwrap();
        let gamma = vs.gamma.unwrap();
        let zeta = vs.zeta.unwrap();

        let l1_zeta = evaluate_first_lagrange_poly(vs.info.domain_n, zeta);
        let alpha_2 = alpha.square();

        let domain_size = vs.info.domain_n.size();

        let zeta_n = zeta.pow(E::Fr::from(domain_size as u128).into_repr());
        let zeta_2n = zeta_n.square();
        let zeta_3n: E::Fr = zeta_n * zeta_2n;

        let v_2 = v.square();
        let v_3 = v*v_2;
        let v_4 = v_2.square();
        let v_5 = v*v_4;
        let v_6 = v*v_5;
        let v_7 = v*v_6;
        let v_8 = v*v_7;

        let comm_r = comms1[0].0.into_projective().mul(evals[3].into_repr())
            + comms1[1].0.into_projective().mul(evals[0].into_repr())
            + comms1[2].0.into_projective().mul(evals[1].into_repr())
            + comms1[3].0.into_projective().mul(evals[2].into_repr())
            + comms1[4].0.into_projective().mul((evals[0] * evals[1]).into_repr())
            + comms1[5].0.into_projective()

            + comms2[1][0].0.into_projective()
            .mul((alpha * (evals[3] + beta*ks[0]*zeta + gamma)
                * (evals[0] + beta*ks[1]*zeta + gamma)
                * (evals[1] + beta*ks[2]*zeta + gamma)
                * (evals[2] + beta*ks[3]*zeta + gamma)).into_repr())

            - comms1[6].0.into_projective()
            .mul((alpha * beta * evals[7]
                * (evals[0] + beta*evals[4] + gamma)
                * (evals[1] + beta*evals[5] + gamma)
                * (evals[2] + beta*evals[6] + gamma)).into_repr())

            + comms2[1][0].0.into_projective()
            .mul((l1_zeta * alpha_2).into_repr());

        let full_batched_polynomial_commitment = comms2[2][0].0.into_projective()
            + comms2[2][1].0.into_projective().mul(zeta_n.into_repr())
            + comms2[2][2].0.into_projective().mul(zeta_2n.into_repr())
            + comms2[2][3].0.into_projective().mul(zeta_3n.into_repr())

            + comm_r.mul(v.into_repr())
            + comms2[0][1].0.into_projective().mul(v_2.into_repr())
            + comms2[0][2].0.into_projective().mul(v_3.into_repr())
            + comms2[0][3].0.into_projective().mul(v_4.into_repr())
            + comms2[0][0].0.into_projective().mul(v_5.into_repr())
            + comms1[7].0.into_projective().mul(v_6.into_repr())
            + comms1[8].0.into_projective().mul(v_7.into_repr())
            + comms1[9].0.into_projective().mul(v_8.into_repr())

            + comms2[1][0].0.into_projective().mul(u.into_repr());

        let group_encoded_batch_evaluation = self.vk.g.into_projective()
            .mul(
            (evals[8]
                + v*evals[9]
                + v_2*evals[0]
                + v_3*evals[1]
                + v_4*evals[2]
                + v_5*evals[3]
                + v_6*evals[4]
                + v_7*evals[5]
                + v_8*evals[6]
                + u*evals[7]).into_repr()
            );

        let inner = proof.pi_w.0.into_projective() + proof.pi_wz.0.into_projective().mul(u.into_repr());
        let lhs = E::pairing(inner, self.vk.beta_h);

        let omega: E::Fr = generator(vs.info.domain_n.clone());
        let inner = proof.pi_w.0.into_projective().mul(zeta.into_repr())
            + proof.pi_wz.0.into_projective().mul((u * zeta * omega).into_repr())
            + full_batched_polynomial_commitment
            - group_encoded_batch_evaluation;

        let rhs = E::pairing(inner, self.vk.h);

        lhs == rhs

    }

    pub fn verifier_equality_check(
        vs: &VerifierState<'_, E::Fr>,
        evals: Vec<E::Fr>,
        public_inputs: &[E::Fr],
    ) -> bool {
        //w123 0, sigma_1 2 3, z^, t,  r

        let alpha = vs.alpha.unwrap();
        let beta = vs.beta.unwrap();
        let gamma = vs.gamma.unwrap();
        let zeta = vs.zeta.unwrap();

        let domain_n = vs.info.domain_n.clone();

        let v_zeta = evaluate_vanishing_poly(domain_n.clone(), zeta);
        let pi_zeta = {
            let pi_n = pad_to_size(public_inputs, domain_n.size());
            let pi_poly = DensePolynomial::from_coefficients_vec(pi_n);
            let pi_poly = LabeledPolynomial::<E::Fr>::new("pi".into(), pi_poly, None, None);
            pi_poly.evaluate(&zeta)
        };

        let l1_zeta = evaluate_first_lagrange_poly(vs.info.domain_n, zeta);
        let alpha_2 = alpha.square();

        let lhs: E::Fr = v_zeta * evals[8];
        let rhs = evals[9] + pi_zeta
            - evals[7]
            * (evals[0] + beta * evals[4] + gamma)
            * (evals[1] + beta * evals[5] + gamma)
            * (evals[2] + beta * evals[6] + gamma)
            * (evals[3] + gamma)
            * alpha
            - l1_zeta * alpha_2;

        lhs == rhs
    }
}
