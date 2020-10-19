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
    use math::PairingEngine;
    use rand::Rng;

    use crate::r1cs::{ConstraintSynthesizer, SynthesisError};

    use super::data_structure::{EncodeCommit, EncodeMemory, SnarkParameters};
    use super::r1cs::R1CSInstance;

    pub type Proof<E> = super::data_structure::SNARKProof<E>;

    pub struct Parameters<E: PairingEngine> {
        params: SnarkParameters<E>,
        r1cs: R1CSInstance<E>,
        encode: EncodeMemory<E>,
        encode_comm: EncodeCommit<E>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct ProveKey<E: PairingEngine> {
        params: SnarkParameters<E>,
        r1cs: R1CSInstance<E>,
        encode: EncodeMemory<E>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct VerifyKey<E: PairingEngine> {
        params: SnarkParameters<E>,
        r1cs: R1CSInstance<E>,
        encode_comm: EncodeCommit<E>,
    }

    impl<E: PairingEngine> Parameters<E> {
        pub fn keypair(self) -> (ProveKey<E>, VerifyKey<E>) {
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

    pub fn generate_random_parameters<E: PairingEngine, C: ConstraintSynthesizer<E::Fr>, R: Rng>(
        c: C,
        rng: &mut R,
    ) -> Result<Parameters<E>, SynthesisError> {
        let r1cs = super::r1cs::generate_r1cs::<E, C>(c)?;

        let params = super::setup::generate_setup_snark_parameters::<E, R>(
            rng,
            r1cs.num_aux,
            r1cs.num_inputs,
            r1cs.num_constraints,
        )?;

        let (encode, encode_comm) = super::spark::encode::<E, R>(&params, &r1cs, rng)?;

        Ok(Parameters {
            params,
            r1cs,
            encode,
            encode_comm,
        })
    }

    pub fn create_random_proof<E: PairingEngine, C: ConstraintSynthesizer<E::Fr>, R: Rng>(
        pk: &ProveKey<E>,
        c: C,
        rng: &mut R,
    ) -> Result<Proof<E>, SynthesisError> {
        super::prover::create_snark_proof(&pk.params, &pk.r1cs, c, &pk.encode, rng)
    }

    pub fn verify_proof<E: PairingEngine>(
        vk: &VerifyKey<E>,
        proof: &Proof<E>,
        publics: &[E::Fr],
    ) -> Result<bool, SynthesisError> {
        super::verify::verify_snark_proof::<E>(
            &vk.params,
            &vk.r1cs,
            publics,
            proof,
            &vk.encode_comm,
        )
    }
}

pub mod nizk {
    use math::PairingEngine;
    use rand::Rng;

    use crate::r1cs::{ConstraintSynthesizer, SynthesisError};

    use super::data_structure::NizkParameters;
    use super::r1cs::R1CSInstance;

    pub type Proof<E> = super::data_structure::NIZKProof<E>;

    pub struct Parameters<E: PairingEngine> {
        params: NizkParameters<E>,
        r1cs: R1CSInstance<E>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct ProveKey<E: PairingEngine> {
        params: NizkParameters<E>,
        r1cs: R1CSInstance<E>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct VerifyKey<E: PairingEngine> {
        params: NizkParameters<E>,
        r1cs: R1CSInstance<E>,
    }

    impl<E: PairingEngine> Parameters<E> {
        pub fn keypair(self) -> (ProveKey<E>, VerifyKey<E>) {
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

    pub fn generate_random_parameters<E: PairingEngine, C: ConstraintSynthesizer<E::Fr>, R: Rng>(
        c: C,
        rng: &mut R,
    ) -> Result<Parameters<E>, SynthesisError> {
        let r1cs = super::r1cs::generate_r1cs::<E, C>(c)?;

        let params = super::setup::generate_setup_nizk_parameters::<E, R>(
            rng,
            r1cs.num_aux,
            r1cs.num_inputs,
        )?;

        Ok(Parameters { params, r1cs })
    }

    pub fn create_random_proof<E: PairingEngine, C: ConstraintSynthesizer<E::Fr>, R: Rng>(
        pk: &ProveKey<E>,
        c: C,
        rng: &mut R,
    ) -> Result<Proof<E>, SynthesisError> {
        super::prover::create_nizk_proof(&pk.params, &pk.r1cs, c, rng)
    }

    pub fn verify_proof<E: PairingEngine>(
        vk: &VerifyKey<E>,
        proof: &Proof<E>,
        publics: &[E::Fr],
    ) -> Result<bool, SynthesisError> {
        super::verify::verify_nizk_proof::<E>(&vk.params, &vk.r1cs, publics, proof)
    }
}
