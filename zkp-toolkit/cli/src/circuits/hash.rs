use ckb_zkp::gadgets::mimc::{hash, mimc};
use ckb_zkp::math::PrimeField;
use ckb_zkp::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

use super::{CliCircuit, Publics};

pub struct Hash<F: PrimeField> {
    image: Option<Vec<u8>>,
    _f: std::marker::PhantomData<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Hash<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let value = if let Some(bytes) = self.image {
            mimc(cs.ns(|| "mimc-gadget"), Some(&bytes))?
        } else {
            mimc(cs.ns(|| "mimc-gadget"), None)?
        };

        let _ = cs.alloc_input(
            || "image",
            || value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        Ok(())
    }
}

impl<F: PrimeField> CliCircuit<F> for Hash<F> {
    fn power_off() -> Self {
        Hash {
            image: None,
            _f: Default::default(),
        }
    }

    fn power_on(args: &[String]) -> (Self, Publics<F>) {
        let image_bytes = args[0].as_bytes();
        let hash_image = hash(image_bytes);
        (
            Hash {
                image: Some(image_bytes.to_vec()),
                _f: Default::default(),
            },
            Publics::Hash(hash_image),
        )
    }

    fn options() -> String {
        "[image string]".to_owned()
    }
}
