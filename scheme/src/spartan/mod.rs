pub mod commitments;
pub mod data_structure;
pub mod inner_product;
pub mod polynomial;
pub mod prover;
pub mod r1cs;
pub mod setup;
pub mod spark;
pub mod test;
pub mod verify;

pub mod snark {
    use math::Curve;
    use rand::Rng;

    use crate::r1cs::{ConstraintSynthesizer, SynthesisError};

    use super::data_structure::{EncodeCommit, EncodeMemory, SnarkParameters};
    use super::r1cs::R1CSInstance;

    pub type Proof<G> = super::data_structure::SNARKProof<G>;

    pub struct Parameters<G: Curve> {
        params: SnarkParameters<G>,
        r1cs: R1CSInstance<G>,
        encode: EncodeMemory<G>,
        encode_comm: EncodeCommit<G>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct ProveKey<G: Curve> {
        params: SnarkParameters<G>,
        r1cs: R1CSInstance<G>,
        encode: EncodeMemory<G>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct VerifyKey<G: Curve> {
        params: SnarkParameters<G>,
        r1cs: R1CSInstance<G>,
        encode_comm: EncodeCommit<G>,
    }

    impl<G: Curve> Parameters<G> {
        pub fn keypair(self) -> (ProveKey<G>, VerifyKey<G>) {
            (
                ProveKey {
                    params: self.params.clone(),
                    r1cs: self.r1cs.clone(),
                    encode: self.encode,
                },
                VerifyKey {
                    params: self.params,
                    r1cs: self.r1cs,
                    encode_comm: self.encode_comm,
                },
            )
        }
    }

    pub fn generate_random_parameters<G: Curve, C: ConstraintSynthesizer<G::Fr>, R: Rng>(
        c: C,
        rng: &mut R,
    ) -> Result<Parameters<G>, SynthesisError> {
        let r1cs = super::r1cs::generate_r1cs::<G, C>(c)?;

        let params = super::setup::generate_setup_snark_parameters::<G, R>(
            rng,
            r1cs.num_aux,
            r1cs.num_inputs,
            r1cs.num_constraints,
        )?;

        let (encode, encode_comm) = super::spark::encode::<G, R>(&params, &r1cs, rng)?;

        Ok(Parameters {
            params,
            r1cs,
            encode,
            encode_comm,
        })
    }

    pub fn create_random_proof<G: Curve, C: ConstraintSynthesizer<G::Fr>, R: Rng>(
        pk: &ProveKey<G>,
        c: C,
        rng: &mut R,
    ) -> Result<Proof<G>, SynthesisError> {
        super::prover::create_snark_proof(&pk.params, &pk.r1cs, c, &pk.encode, rng)
    }

    pub fn verify_proof<G: Curve>(
        vk: &VerifyKey<G>,
        proof: &Proof<G>,
        publics: &[G::Fr],
    ) -> Result<bool, SynthesisError> {
        super::verify::verify_snark_proof::<G>(
            &vk.params,
            &vk.r1cs,
            publics,
            proof,
            &vk.encode_comm,
        )
    }
}

pub mod nizk {
    use math::Curve;
    use rand::Rng;

    use crate::r1cs::{ConstraintSynthesizer, SynthesisError};

    use super::data_structure::NizkParameters;
    use super::r1cs::R1CSInstance;

    pub type Proof<G> = super::data_structure::NIZKProof<G>;

    pub struct Parameters<G: Curve> {
        params: NizkParameters<G>,
        r1cs: R1CSInstance<G>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct ProveKey<G: Curve> {
        params: NizkParameters<G>,
        r1cs: R1CSInstance<G>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct VerifyKey<G: Curve> {
        params: NizkParameters<G>,
        r1cs: R1CSInstance<G>,
    }

    impl<G: Curve> Parameters<G> {
        pub fn keypair(self) -> (ProveKey<G>, VerifyKey<G>) {
            (
                ProveKey {
                    params: self.params.clone(),
                    r1cs: self.r1cs.clone(),
                },
                VerifyKey {
                    params: self.params,
                    r1cs: self.r1cs,
                },
            )
        }
    }

    pub fn generate_random_parameters<G: Curve, C: ConstraintSynthesizer<G::Fr>, R: Rng>(
        c: C,
        rng: &mut R,
    ) -> Result<Parameters<G>, SynthesisError> {
        let r1cs = super::r1cs::generate_r1cs::<G, C>(c)?;

        let params = super::setup::generate_setup_nizk_parameters::<G, R>(
            rng,
            r1cs.num_aux,
            r1cs.num_inputs,
        )?;

        Ok(Parameters { params, r1cs })
    }

    pub fn create_random_proof<G: Curve, C: ConstraintSynthesizer<G::Fr>, R: Rng>(
        pk: &ProveKey<G>,
        c: C,
        rng: &mut R,
    ) -> Result<Proof<G>, SynthesisError> {
        super::prover::create_nizk_proof(&pk.params, &pk.r1cs, c, rng)
    }

    pub fn verify_proof<G: Curve>(
        vk: &VerifyKey<G>,
        proof: &Proof<G>,
        publics: &[G::Fr],
    ) -> Result<bool, SynthesisError> {
        super::verify::verify_nizk_proof::<G>(&vk.params, &vk.r1cs, publics, proof)
    }
}
