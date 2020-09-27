use crate::r1cs::SynthesisError;
use crate::spartan::data_structure::{random_bytes_to_fr, InnerProductProof};
use crate::Vec;
use math::{
    bytes::ToBytes, log2, msm::VariableBaseMSM, AffineCurve, Field, One, PairingEngine, PrimeField,
    ProjectiveCurve,
};
use merlin::Transcript;

pub fn bullet_inner_product_proof<E: PairingEngine>(
    g_vec: &Vec<E::G1Affine>,
    q: E::G1Affine,
    h: E::G1Affine,
    a_vec: &Vec<E::Fr>,
    b_vec: &Vec<E::Fr>,
    gamma_blind: E::Fr,
    blinds_vec: &[(E::Fr, E::Fr)],
    transcript: &mut Transcript,
) -> Result<(InnerProductProof<E>, E::Fr, E::Fr, E::G1Affine, E::Fr), SynthesisError> {
    let mut a_vec = a_vec.clone();
    let mut b_vec = b_vec.clone();
    let mut g_vec = g_vec.clone();

    let mut n = a_vec.len();
    assert!(n.is_power_of_two());
    assert_eq!(n, b_vec.len());
    let lg_n = log2(n) as usize;
    let mut l_vec: Vec<E::G1Affine> = Vec::with_capacity(lg_n);
    let mut r_vec: Vec<E::G1Affine> = Vec::with_capacity(lg_n);
    let mut blinds_iter = blinds_vec.iter();
    let mut blind_fin = gamma_blind;
    while n > 1 {
        // P computes:
        n = n / 2;
        let (al, ar) = a_vec.split_at(n);
        let (bl, br) = b_vec.split_at(n);

        let cl: E::Fr = inner_product::<E>(al, br);
        let cr: E::Fr = inner_product::<E>(ar, bl);

        let (gl, gr) = g_vec.split_at(n);

        // let (hL, hR) = h_vec.split_at(n);

        let (blind_l, blind_r) = blinds_iter.next().unwrap();

        // let L: E::G1Projective = VariableBaseMSM::multi_scalar_mul(&gr.to_vec().append(&mut vec![Q, H]) , al.to_vec().append(&mut vec![cl, *blind_l]));
        // let R: E::G1Projective = VariableBaseMSM::multi_scalar_mul(&gl.to_vec().append(&mut vec![Q, H]) , ar.to_vec().append(&mut vec![cr, *blind_r]));

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
        let x = random_bytes_to_fr::<E>(&buf_x);
        let x_inv = x.inverse().unwrap();

        // P & V compute:
        let g_new: Vec<E::G1Affine> = (0..n)
            .map(|i| (gl[i].mul(x_inv) + &(gr[i].mul(x))).into_affine())
            .collect();
        // let P_new = L * x*x + P + R * x_inv*x_inv;

        // P computes:
        let a_new: Vec<E::Fr> = (0..n).map(|i| al[i] * &x + &(ar[i] * &x_inv)).collect();
        let b_new: Vec<E::Fr> = (0..n).map(|i| bl[i] * &x_inv + &(br[i] * &x)).collect();

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

    let proof = InnerProductProof::<E> {
        l_vec: l_vec,
        r_vec: r_vec,
    };

    Ok((proof, a, b, g, blind_fin))
}

pub fn bullet_inner_product_verify<E: PairingEngine>(
    g_vec: &Vec<E::G1Affine>,
    proof: &InnerProductProof<E>,
    gamma: E::G1Affine,
    b_vec: Vec<E::Fr>,
    transcript: &mut Transcript,
) -> Result<(E::Fr, E::G1Affine, E::G1Affine), SynthesisError> {
    let lg_n = proof.l_vec.len();
    let n = 1 << lg_n;
    assert_eq!(lg_n, proof.r_vec.len());

    let mut x_sq_vec = Vec::with_capacity(lg_n);
    let mut x_inv_sq_vec = Vec::with_capacity(lg_n);
    let mut allinv = E::Fr::one();
    for i in 0..lg_n {
        transcript.append_message(b"L", &math::to_bytes!(proof.l_vec[i]).unwrap());
        transcript.append_message(b"R", &math::to_bytes!(proof.r_vec[i]).unwrap());

        // V challenge x
        let mut buf_x = [0u8; 31];
        transcript.challenge_bytes(b"x", &mut buf_x);
        let x = random_bytes_to_fr::<E>(&buf_x);
        let x_inv = x.inverse().unwrap();
        x_sq_vec.push(x * &x);
        x_inv_sq_vec.push(x_inv * &x_inv);
        allinv = allinv * &x_inv;
    }

    // Compute s values inductively. Here adpots optimization from Dalek.
    let mut s: Vec<E::Fr> = Vec::with_capacity(n);
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
        &proof.l_vec.as_slice(),
        &x_sq_vec
            .into_iter()
            .map(|e| e.into_repr())
            .collect::<Vec<_>>(),
    );
    gamma_hat += &VariableBaseMSM::multi_scalar_mul(
        &proof.r_vec,
        &x_inv_sq_vec
            .into_iter()
            .map(|e| e.into_repr())
            .collect::<Vec<_>>(),
    );

    gamma_hat += &VariableBaseMSM::multi_scalar_mul(
        &vec![gamma],
        &vec![E::Fr::one()]
            .into_iter()
            .map(|e| e.into_repr())
            .collect::<Vec<_>>(),
    );

    Ok((b_s, g_hat.into_affine(), gamma_hat.into_affine()))
}

pub fn inner_product<E: PairingEngine>(a: &[E::Fr], b: &[E::Fr]) -> E::Fr {
    assert_eq!(a.len(), b.len());
    let out = (0..a.len()).map(|i| a[i] * &b[i]).sum();
    out
}
