use crate::libra::data_structure::{MultiCommitmentSetupParameters, PolyCommitmentSetupParameters};
use crate::libra::evaluate::{eval_eq, poly_commit_vec, random_bytes_to_fr};
use math::{
    bytes::ToBytes, log2, msm::VariableBaseMSM, AffineCurve, Curve, Field, One, PrimeField,
    ProjectiveCurve, UniformRand, Zero,
};
use merlin::Transcript;
use rand::Rng;

pub struct EqProof<G: Curve> {
    pub alpha: G::Affine,
    pub z: G::Fr,
}

impl<G: Curve> EqProof<G> {
    pub fn prover<R: Rng>(
        params: &MultiCommitmentSetupParameters<G>,
        claim1: G::Fr,
        blind1: G::Fr,
        claim2: G::Fr,
        blind2: G::Fr,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> Self {
        let r = G::Fr::rand(rng);
        let comm1 = poly_commit_vec::<G>(&params.generators, &vec![claim1], &params.h, blind1);
        transcript.append_message(b"C1", &math::to_bytes!(comm1).unwrap());
        let comm2 = poly_commit_vec::<G>(&params.generators, &vec![claim2], &params.h, blind2);
        transcript.append_message(b"C2", &math::to_bytes!(comm2).unwrap());
        let alpha = params.h.mul(r).into_affine();
        transcript.append_message(b"alpha", &math::to_bytes!(alpha).unwrap());
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"c", &mut buf);
        let c = random_bytes_to_fr::<G>(&buf);
        let z = c * &(blind1 - &blind2) + &r;
        Self { alpha, z }
    }

    pub fn verify(
        &self,
        params: &MultiCommitmentSetupParameters<G>,
        comm1: G::Affine,
        comm2: G::Affine,
        transcript: &mut Transcript,
    ) -> bool {
        transcript.append_message(b"C1", &math::to_bytes!(comm1).unwrap());
        transcript.append_message(b"C2", &math::to_bytes!(comm2).unwrap());
        transcript.append_message(b"alpha", &math::to_bytes!(self.alpha).unwrap());
        let mut buf = [0u8; 32];
        transcript.challenge_bytes(b"c", &mut buf);
        let c = random_bytes_to_fr::<G>(&buf);
        let comm = (comm1.into_projective() - &comm2.into_projective()).into_affine();
        let lhs = params.h.mul(self.z);
        let rhs = comm.mul(c) + &self.alpha.into_projective();
        lhs == rhs
    }
}

pub struct KnowledgeProof<G: Curve> {
    pub t_comm: G::Affine,
    pub z1: G::Fr,
    pub z2: G::Fr,
}

impl<G: Curve> KnowledgeProof<G> {
    pub fn prover<R: Rng>(
        params: &MultiCommitmentSetupParameters<G>,
        claim: G::Fr,
        blind: G::Fr,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> (Self, G::Affine) {
        let t1 = G::Fr::rand(rng);
        let t2 = G::Fr::rand(rng);
        let claim_comm = poly_commit_vec::<G>(&params.generators, &vec![claim], &params.h, blind);
        transcript.append_message(b"C", &math::to_bytes!(claim_comm).unwrap());
        let t_comm = poly_commit_vec::<G>(&params.generators, &vec![t1], &params.h, t2);
        transcript.append_message(b"alpha", &math::to_bytes!(t_comm).unwrap());
        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"c", &mut buf);
        let c = random_bytes_to_fr::<G>(&buf);
        let z1 = claim * &c + &t1;
        let z2 = blind * &c + &t2;
        let proof = Self {
            t_comm: t_comm,
            z1: z1,
            z2: z2,
        };
        (proof, claim_comm)
    }

    pub fn verify(
        &self,
        params: &MultiCommitmentSetupParameters<G>,
        claim_comm: G::Affine,
        transcript: &mut Transcript,
    ) -> bool {
        transcript.append_message(b"C", &math::to_bytes!(claim_comm).unwrap());
        transcript.append_message(b"alpha", &math::to_bytes!(self.t_comm).unwrap());
        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"c", &mut buf);
        let c = random_bytes_to_fr::<G>(&buf);
        let lhs = poly_commit_vec::<G>(&params.generators, &vec![self.z1], &params.h, self.z2);
        let rhs = claim_comm.mul(c) + &self.t_comm.into_projective();
        lhs == rhs.into_affine()
    }
}

pub struct ProductProof<G: Curve> {
    pub comm_alpha: G::Affine,
    pub comm_beta: G::Affine,
    pub comm_delta: G::Affine,
    pub z: Vec<G::Fr>,
}

impl<G: Curve> ProductProof<G> {
    pub fn prover<R: Rng>(
        params: &MultiCommitmentSetupParameters<G>,
        claim_x: G::Fr,
        blind_x: G::Fr,
        claim_y: G::Fr,
        blind_y: G::Fr,
        prod: G::Fr,
        blind_prod: G::Fr,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> (Self, G::Affine, G::Affine, G::Affine) {
        let comm_x = poly_commit_vec::<G>(&params.generators, &vec![claim_x], &params.h, blind_x);
        transcript.append_message(b"X", &math::to_bytes!(comm_x).unwrap());
        let comm_y = poly_commit_vec::<G>(&params.generators, &vec![claim_y], &params.h, blind_y);
        transcript.append_message(b"Y", &math::to_bytes!(comm_y).unwrap());
        let comm_prod =
            poly_commit_vec::<G>(&params.generators, &vec![prod], &params.h, blind_prod);
        transcript.append_message(b"Z", &math::to_bytes!(comm_prod).unwrap());

        let b1 = G::Fr::rand(rng);
        let b2 = G::Fr::rand(rng);
        let b3 = G::Fr::rand(rng);
        let b4 = G::Fr::rand(rng);
        let b5 = G::Fr::rand(rng);
        let comm_alpha = poly_commit_vec::<G>(&params.generators, &vec![b1], &params.h, b2);
        transcript.append_message(b"alpha", &math::to_bytes!(comm_alpha).unwrap());
        let comm_beta = poly_commit_vec::<G>(&params.generators, &vec![b3], &params.h, b4);
        transcript.append_message(b"beta", &math::to_bytes!(comm_beta).unwrap());
        let comm_delta = poly_commit_vec::<G>(&vec![comm_x], &vec![b3], &params.h, b5);
        transcript.append_message(b"delta", &math::to_bytes!(comm_delta).unwrap());

        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"c", &mut buf);
        let c = random_bytes_to_fr::<G>(&buf);

        let z1 = b1 + &(c * &claim_x);
        let z2 = b2 + &(c * &blind_x);
        let z3 = b3 + &(c * &claim_y);
        let z4 = b4 + &(c * &blind_y);
        let z5 = b5 + &(c * &(blind_prod - &(blind_x * &claim_y)));
        let z = [z1, z2, z3, z4, z5];
        let proof = Self {
            comm_alpha,
            comm_beta,
            comm_delta,
            z: z.to_vec(),
        };
        (proof, comm_x, comm_y, comm_prod)
    }

    pub fn verify(
        &self,
        params: &MultiCommitmentSetupParameters<G>,
        comm_x: G::Affine,
        comm_y: G::Affine,
        comm_prod: G::Affine,
        transcript: &mut Transcript,
    ) -> bool {
        let z1 = self.z[0];
        let z2 = self.z[1];
        let z3 = self.z[2];
        let z4 = self.z[3];
        let z5 = self.z[4];

        transcript.append_message(b"X", &math::to_bytes!(comm_x).unwrap());
        transcript.append_message(b"Y", &math::to_bytes!(comm_y).unwrap());
        transcript.append_message(b"Z", &math::to_bytes!(comm_prod).unwrap());
        transcript.append_message(b"alpha", &math::to_bytes!(self.comm_alpha).unwrap());
        transcript.append_message(b"beta", &math::to_bytes!(self.comm_beta).unwrap());
        transcript.append_message(b"delta", &math::to_bytes!(self.comm_delta).unwrap());

        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"c", &mut buf);
        let c = random_bytes_to_fr::<G>(&buf);

        let rs1_lhs = self.comm_alpha + comm_x.mul(c).into_affine();
        let rs1_rhs = poly_commit_vec::<G>(&params.generators, &vec![z1], &params.h, z2);
        let rs1 = rs1_lhs == rs1_rhs;

        let rs2_lhs = self.comm_beta + comm_y.mul(c).into_affine();
        let rs2_rhs = poly_commit_vec::<G>(&params.generators, &vec![z3], &params.h, z4);
        let rs2 = rs2_lhs == rs2_rhs;

        let rs3_lhs = self.comm_delta + comm_prod.mul(c).into_affine();
        let rs3_rhs = poly_commit_vec::<G>(&vec![comm_x], &vec![z3], &params.h, z5);
        let rs3 = rs3_lhs == rs3_rhs;

        rs1 && rs2 && rs3
    }
}

pub struct DotProductProof<G: Curve> {
    pub z_vec: Vec<G::Fr>,
    pub delta: G::Affine,
    pub beta: G::Affine,
    pub z_delta: G::Fr,
    pub z_beta: G::Fr,
}

impl<G: Curve> DotProductProof<G> {
    pub fn prover<R: Rng>(
        params: &PolyCommitmentSetupParameters<G>,
        x_vec: &Vec<G::Fr>,
        blind_x: G::Fr,
        a_vec: &Vec<G::Fr>,
        y: G::Fr,
        blind_y: G::Fr,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> (Self, G::Affine, G::Affine) {
        assert_eq!(a_vec.len(), x_vec.len());
        assert!(params.n >= a_vec.len());
        let size = a_vec.len();

        let d_vec = (0..size).map(|_| G::Fr::rand(rng)).collect::<Vec<_>>();
        let r_beta = G::Fr::rand(rng);
        let r_delta = G::Fr::rand(rng);

        let comm_x =
            poly_commit_vec::<G>(&params.gen_n.generators, &x_vec, &params.gen_n.h, blind_x);
        transcript.append_message(b"Cx", &math::to_bytes!(comm_x).unwrap());

        let comm_y =
            poly_commit_vec::<G>(&params.gen_1.generators, &vec![y], &params.gen_1.h, blind_y);
        transcript.append_message(b"Cy", &math::to_bytes!(comm_y).unwrap());

        let delta =
            poly_commit_vec::<G>(&params.gen_n.generators, &d_vec, &params.gen_n.h, r_delta);
        transcript.append_message(b"delta", &math::to_bytes!(comm_x).unwrap());

        let dotprod_a_d = (0..size).map(|i| a_vec[i] * &d_vec[i]).product();
        let beta = poly_commit_vec::<G>(
            &params.gen_1.generators,
            &vec![dotprod_a_d],
            &params.gen_1.h,
            r_beta,
        );
        transcript.append_message(b"beta", &math::to_bytes!(comm_y).unwrap());

        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"c", &mut buf);
        let c = random_bytes_to_fr::<G>(&buf);

        let z_vec = (0..d_vec.len())
            .map(|i| c * &x_vec[i] + &d_vec[i])
            .collect::<Vec<_>>();

        let z_delta = c * &blind_x + &r_delta;
        let z_beta = c * &blind_y + &r_beta;

        let proof = Self {
            z_vec,
            z_delta,
            z_beta,
            delta,
            beta,
        };

        (proof, comm_x, comm_y)
    }

    pub fn verify(
        &self,
        params: &PolyCommitmentSetupParameters<G>,
        comm_x: G::Affine,
        comm_y: G::Affine,
        a_vec: &Vec<G::Fr>,
        transcript: &mut Transcript,
    ) -> bool {
        transcript.append_message(b"Cx", &math::to_bytes!(comm_x).unwrap());
        transcript.append_message(b"Cy", &math::to_bytes!(comm_y).unwrap());
        transcript.append_message(b"delta", &math::to_bytes!(self.delta).unwrap());
        transcript.append_message(b"beta", &math::to_bytes!(self.beta).unwrap());

        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"c", &mut buf);
        let c = random_bytes_to_fr::<G>(&buf);

        let rs1_lhs = comm_x.mul(c).into_affine() + self.delta;
        let rs1_rhs = poly_commit_vec::<G>(
            &params.gen_n.generators,
            &self.z_vec,
            &params.gen_n.h,
            self.z_delta,
        );
        let rs1 = rs1_lhs == rs1_rhs;

        let rs2_lhs = comm_y.mul(c).into_affine() + self.beta;
        let dotprod_z_a = (0..a_vec.len())
            .map(|i| self.z_vec[i] * &a_vec[i])
            .product();
        let rs2_rhs = poly_commit_vec::<G>(
            &params.gen_1.generators,
            &vec![dotprod_z_a],
            &params.gen_n.h,
            self.z_beta,
        );
        let rs2 = rs2_lhs == rs2_rhs;

        rs1 && rs2
    }
}

pub struct LogDotProductProof<G: Curve> {
    pub bullet_reduce_proof: BulletReduceProof<G>,
    pub delta: G::Affine,
    pub beta: G::Affine,
    pub z1: G::Fr,
    pub z2: G::Fr,
}

impl<G: Curve> LogDotProductProof<G> {
    pub fn prover<R: Rng>(
        params: &PolyCommitmentSetupParameters<G>,
        x_vec: &Vec<G::Fr>,
        blind_x: G::Fr,
        a_vec: &Vec<G::Fr>,
        y: G::Fr,
        blind_y: G::Fr,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> (Self, G::Affine, G::Affine) {
        assert_eq!(a_vec.len(), x_vec.len());
        assert!(params.n >= a_vec.len());
        let size = a_vec.len();

        let d = G::Fr::rand(rng);
        let r_beta = G::Fr::rand(rng);
        let r_delta = G::Fr::rand(rng);
        let blind_vec = (0..log2(size))
            .map(|_| (G::Fr::rand(rng), G::Fr::rand(rng)))
            .collect::<Vec<_>>();

        let comm_x =
            poly_commit_vec::<G>(&params.gen_n.generators, &x_vec, &params.gen_n.h, blind_x);
        transcript.append_message(b"Cx", &math::to_bytes!(comm_x).unwrap());

        let comm_y =
            poly_commit_vec::<G>(&params.gen_1.generators, &vec![y], &params.gen_1.h, blind_y);
        transcript.append_message(b"Cy", &math::to_bytes!(comm_y).unwrap());

        let blind_gamma = blind_x + &blind_y;
        let (bullet_reduce_proof, _gamma_hat, x_hat, a_hat, g_hat, r_hat_gamma) =
            BulletReduceProof::prover(&params, &x_vec, &a_vec, blind_gamma, &blind_vec, transcript);
        let y_hat = x_hat * &a_hat;

        let delta = poly_commit_vec::<G>(&vec![g_hat], &vec![d], &params.gen_1.h, r_delta);
        transcript.append_message(b"delta", &math::to_bytes!(delta).unwrap());

        let beta =
            poly_commit_vec::<G>(&params.gen_1.generators, &vec![d], &params.gen_1.h, r_beta);
        transcript.append_message(b"beta", &math::to_bytes!(beta).unwrap());

        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"c", &mut buf);
        let c = random_bytes_to_fr::<G>(&buf);
        let z1 = d + &(c * &y_hat);
        let z2 = a_hat * &(c * &r_hat_gamma + &r_beta) + &r_delta;

        let proof = Self {
            bullet_reduce_proof,
            z1,
            z2,
            delta,
            beta,
        };

        (proof, comm_x, comm_y)
    }

    pub fn verify(
        &self,
        params: &PolyCommitmentSetupParameters<G>,
        comm_x: G::Affine,
        comm_y: G::Affine,
        a_vec: &Vec<G::Fr>,
        transcript: &mut Transcript,
    ) -> bool {
        transcript.append_message(b"Cx", &math::to_bytes!(comm_x).unwrap());
        transcript.append_message(b"Cy", &math::to_bytes!(comm_y).unwrap());

        let gamma = comm_x + comm_y;
        let (a_hat, g_hat, gamma_hat) =
            self.bullet_reduce_proof
                .verify(&params.gen_n.generators, gamma, a_vec, transcript);

        transcript.append_message(b"delta", &math::to_bytes!(self.delta).unwrap());
        transcript.append_message(b"beta", &math::to_bytes!(self.beta).unwrap());

        let mut buf = [0u8; 31];
        transcript.challenge_bytes(b"c", &mut buf);
        let c = random_bytes_to_fr::<G>(&buf);

        let lhs = (gamma_hat.mul(c) + &self.beta.into_projective()).mul(a_hat)
            + &self.delta.into_projective();
        let rhs = (g_hat.into_projective() + &params.gen_1.generators[0].mul(a_hat)).mul(self.z1)
            + &(params.gen_1.h.mul(self.z2));

        lhs == rhs
    }

    pub fn reduce_prover<R: Rng>(
        params: &PolyCommitmentSetupParameters<G>,
        poly: &Vec<G::Fr>,
        blind_poly: &Vec<G::Fr>,
        ry: &Vec<G::Fr>,
        ry_blind: G::Fr,
        eval: G::Fr,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> (Self, G::Affine) {
        let n = poly.len();
        let size = log2(n) as usize;
        assert_eq!(ry.len(), size);
        let l_size = (2usize).pow((size / 2) as u32);
        let r_size = (2usize).pow((size - size / 2) as u32);
        let mut blinds = blind_poly.clone();
        if blind_poly.len() == 0 {
            blinds = vec![G::Fr::zero(); l_size];
        }
        assert_eq!(l_size, blinds.len());
        let l_eq_ry = eval_eq::<G>(&(ry[0..size / 2].to_vec()));
        let r_eq_ry = eval_eq::<G>(&ry[size / 2..size].to_vec());
        let lz = (0..r_size)
            .map(|j| {
                (0..l_size)
                    .map(|i| l_eq_ry[i] * &poly[i * r_size + j])
                    .sum()
            })
            .collect::<Vec<G::Fr>>();
        let lz_blind: G::Fr = (0..l_size).map(|i| l_eq_ry[i] * &blinds[i]).sum();
        let (proof, _, comm_y) = Self::prover(
            params, &lz, lz_blind, &r_eq_ry, eval, ry_blind, rng, transcript,
        );

        (proof, comm_y)
    }

    pub fn reduce_verifier(
        &self,
        params: &PolyCommitmentSetupParameters<G>,
        ry: &Vec<G::Fr>,
        comms_witness: &Vec<G::Affine>,
        comm_ry: G::Affine,
        transcript: &mut Transcript,
    ) -> bool {
        let size = ry.len();
        let l_eq_ry = eval_eq::<G>(&(ry[0..size / 2].to_vec()));
        let r_eq_ry = eval_eq::<G>(&ry[size / 2..size].to_vec());
        let comm_lz = poly_commit_vec::<G>(
            &comms_witness,
            &l_eq_ry.clone(),
            &params.gen_1.h,
            G::Fr::zero(),
        );
        self.verify(params, comm_lz, comm_ry, &r_eq_ry, transcript)
    }
}

pub struct BulletReduceProof<G: Curve> {
    pub l_vec: Vec<G::Affine>,
    pub r_vec: Vec<G::Affine>,
}

impl<G: Curve> BulletReduceProof<G> {
    pub fn prover(
        params: &PolyCommitmentSetupParameters<G>,
        a_vec: &Vec<G::Fr>,
        b_vec: &Vec<G::Fr>,
        blind_gamma: G::Fr,
        blind_vec: &Vec<(G::Fr, G::Fr)>,
        transcript: &mut Transcript,
    ) -> (Self, G::Affine, G::Fr, G::Fr, G::Affine, G::Fr) {
        let mut g_vec = params.gen_n.generators.clone();
        let q = params.gen_1.generators[0];
        let h = params.gen_1.h;

        let mut a_vec = a_vec.clone();
        let mut b_vec = b_vec.clone();

        let mut n = a_vec.len();
        assert!(n.is_power_of_two());
        assert_eq!(n, b_vec.len());
        let lg_n = log2(n) as usize;
        let mut l_vec: Vec<G::Affine> = Vec::with_capacity(lg_n);
        let mut r_vec: Vec<G::Affine> = Vec::with_capacity(lg_n);
        let mut blinds_iter = blind_vec.iter();
        let mut blind_fin = blind_gamma;

        while n > 1 {
            // P computes:
            n = n / 2;
            let (al, ar) = a_vec.split_at(n);
            let (bl, br) = b_vec.split_at(n);
            let cl: G::Fr = inner_product::<G>(al, br);
            let cr: G::Fr = inner_product::<G>(ar, bl);
            let (gl, gr) = g_vec.split_at(n);
            // let (hL, hR) = h_vec.split_at(n);
            let (blind_l, blind_r) = blinds_iter.next().unwrap();
            // let L: G::G1Projective = VariableBaseMSM::multi_scalar_mul(&gr.to_vec().append(&mut vec![Q, H]) , al.to_vec().append(&mut vec![cl, *blind_l]));
            // let R: G::G1Projective = VariableBaseMSM::multi_scalar_mul(&gl.to_vec().append(&mut vec![Q, H]) , ar.to_vec().append(&mut vec![cr, *blind_r]));
            let mut l = VariableBaseMSM::multi_scalar_mul(
                gr,
                al.into_iter()
                    .map(|e| e.into_repr())
                    .collect::<Vec<_>>()
                    .as_slice(),
            );
            l += &(VariableBaseMSM::multi_scalar_mul(
                vec![q, h].as_slice().clone(),
                vec![cl, *blind_l]
                    .as_slice()
                    .into_iter()
                    .map(|e| e.into_repr())
                    .collect::<Vec<_>>()
                    .as_slice(),
            ));
            let mut r = VariableBaseMSM::multi_scalar_mul(
                gl,
                ar.into_iter()
                    .map(|e| e.into_repr())
                    .collect::<Vec<_>>()
                    .as_slice(),
            );
            r += &(VariableBaseMSM::multi_scalar_mul(
                vec![q, h].as_slice().clone(),
                vec![cr, *blind_r]
                    .as_slice()
                    .into_iter()
                    .map(|e| e.into_repr())
                    .collect::<Vec<_>>()
                    .as_slice(),
            ));
            // P -> V: L, R
            let l_aff = l.into_affine();
            let r_aff = r.into_affine();
            l_vec.push(l_aff);
            r_vec.push(r_aff);
            // V challenge x, send to P
            transcript.append_message(b"L", &math::to_bytes!(l_aff).unwrap());
            transcript.append_message(b"R", &math::to_bytes!(r_aff).unwrap());
            // V challenge x
            let mut buf_x = [0u8; 31];
            transcript.challenge_bytes(b"x", &mut buf_x);
            let x = random_bytes_to_fr::<G>(&buf_x);
            let x_inv = x.inverse().unwrap();
            // P & V compute:
            let g_new: Vec<G::Affine> = (0..n)
                .map(|i| (gl[i].mul(x_inv) + &(gr[i].mul(x))).into_affine())
                .collect();
            // let P_new = L * x*x + P + R * x_inv*x_inv;
            // P computes:
            let a_new: Vec<G::Fr> = (0..n).map(|i| al[i] * &x + &(ar[i] * &x_inv)).collect();
            let b_new: Vec<G::Fr> = (0..n).map(|i| bl[i] * &x_inv + &(br[i] * &x)).collect();
            a_vec = a_new;
            b_vec = b_new;
            g_vec = g_new;
            // P = P_new;
            blind_fin = blind_fin + &(x * &x * blind_l) + &(x_inv * &x_inv * blind_r);
        }
        assert_eq!(a_vec.len(), 1);
        assert_eq!(b_vec.len(), 1);
        let a = a_vec[0];
        let b = b_vec[0];
        let g = g_vec[0];

        let proof = Self {
            l_vec: l_vec,
            r_vec: r_vec,
        };

        let gamma_hat = VariableBaseMSM::multi_scalar_mul(
            &vec![g, q, h],
            &[a.into_repr(), (a * &b).into_repr(), blind_fin.into_repr()],
        );

        (proof, gamma_hat.into_affine(), a, b, g, blind_fin)
    }

    pub fn verify(
        &self,
        g_vec: &Vec<G::Affine>,
        gamma: G::Affine,
        b_vec: &Vec<G::Fr>,
        transcript: &mut Transcript,
    ) -> (G::Fr, G::Affine, G::Affine) {
        let lg_n = self.l_vec.len();
        let n = 1 << lg_n;
        assert_eq!(lg_n, self.r_vec.len());
        let mut x_sq_vec = Vec::with_capacity(lg_n);
        let mut x_inv_sq_vec = Vec::with_capacity(lg_n);
        let mut allinv = G::Fr::one();
        for i in 0..lg_n {
            transcript.append_message(b"L", &math::to_bytes!(self.l_vec[i]).unwrap());
            transcript.append_message(b"R", &math::to_bytes!(self.r_vec[i]).unwrap());
            // V challenge x
            let mut buf_x = [0u8; 31];
            transcript.challenge_bytes(b"x", &mut buf_x);
            let x = random_bytes_to_fr::<G>(&buf_x);
            let x_inv = x.inverse().unwrap();
            x_sq_vec.push(x * &x);
            x_inv_sq_vec.push(x_inv * &x_inv);
            allinv = allinv * &x_inv;
        }
        // Compute s values inductively. Here adpots optimization from Dalek.
        let mut s: Vec<G::Fr> = Vec::with_capacity(n);
        s.push(allinv);
        for i in 1..n {
            let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
            let k = 1 << lg_i;
            // The challenges are stored in "creation order" as [u_k,...,u_1],
            // so u_{lg(i)+1} = is indexed by (lg_n-1) - lg_i
            let u_lg_i_sq = x_sq_vec[(lg_n - 1) - lg_i];
            s.push(s[i - k] * &u_lg_i_sq);
        }
        let mut inv_s = s.clone();
        inv_s.reverse();
        let b_s = (0..n).map(|i| b_vec[i] * &s[i]).sum();
        let g_hat = VariableBaseMSM::multi_scalar_mul(
            &g_vec[0..s.len()].to_vec().clone(),
            &s.into_iter().map(|e| e.into_repr()).collect::<Vec<_>>(),
        );
        let mut gamma_hat = VariableBaseMSM::multi_scalar_mul(
            &self.l_vec.as_slice(),
            &x_sq_vec
                .into_iter()
                .map(|e| e.into_repr())
                .collect::<Vec<_>>(),
        );
        gamma_hat += &VariableBaseMSM::multi_scalar_mul(
            &self.r_vec,
            &x_inv_sq_vec
                .into_iter()
                .map(|e| e.into_repr())
                .collect::<Vec<_>>(),
        );
        gamma_hat += &VariableBaseMSM::multi_scalar_mul(
            &vec![gamma],
            &vec![G::Fr::one()]
                .into_iter()
                .map(|e| e.into_repr())
                .collect::<Vec<_>>(),
        );
        (b_s, g_hat.into_affine(), gamma_hat.into_affine())
    }
}

pub fn inner_product<G: Curve>(a: &[G::Fr], b: &[G::Fr]) -> G::Fr {
    assert_eq!(a.len(), b.len());
    let out = (0..a.len()).map(|i| a[i] * &b[i]).sum();
    out
}
