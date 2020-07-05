use math::{FromBytes, PairingEngine, PrimeField, ToBytes};
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

use crate::{Gadget, GadgetProof, Vec};

pub struct Mini<F: PrimeField> {
    pub x: Option<F>,
    pub y: Option<F>,
    pub z: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Mini<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let var_x = cs.alloc(|| "x", || self.x.ok_or(SynthesisError::AssignmentMissing))?;

        let var_y = cs.alloc(|| "y", || self.y.ok_or(SynthesisError::AssignmentMissing))?;

        let var_z = cs.alloc_input(
            || "z(output)",
            || self.z.ok_or(SynthesisError::AssignmentMissing),
        )?;

        cs.enforce(
            || "x * (y + 2) = z",
            |lc| lc + var_x,
            |lc| lc + var_y + (F::from(2u32), CS::one()),
            |lc| lc + var_z,
        );

        Ok(())
    }
}

#[cfg(feature = "groth16")]
pub fn groth16_prove<E: PairingEngine, R: rand::Rng>(
    g: &Gadget,
    pk: &[u8],
    mut rng: R,
) -> Result<GadgetProof, ()> {
    use scheme::groth16::{create_random_proof, Parameters};
    match g {
        Gadget::Mini(x, y, z) => {
            let repr_x = <E::Fr as PrimeField>::BigInt::from(*x as u64);
            let repr_y = <E::Fr as PrimeField>::BigInt::from(*y as u64);
            let repr_z = <E::Fr as PrimeField>::BigInt::from(*z as u64);
            let mc = Mini::<E::Fr> {
                x: Some(<E::Fr as PrimeField>::from_repr(repr_x)),
                y: Some(<E::Fr as PrimeField>::from_repr(repr_y)),
                z: Some(<E::Fr as PrimeField>::from_repr(repr_z)),
            };

            let params = Parameters::<E>::read(pk).map_err(|_| ())?;

            let proof = create_random_proof(mc, &params, &mut rng).map_err(|_| ())?;

            let mut p_bytes = Vec::new();
            proof.write(&mut p_bytes).map_err(|_| ())?;

            Ok(GadgetProof::Mini(*z, p_bytes))
        }
        _ => Err(()),
    }
}

#[cfg(feature = "groth16")]
pub fn groth16_verify<E: PairingEngine>(
    g: GadgetProof,
    vk: &[u8],
    is_pp: bool,
) -> Result<bool, ()> {
    use scheme::groth16::{
        prepare_verifying_key, verify_proof, PreparedVerifyingKey, Proof, VerifyingKey,
    };
    match g {
        GadgetProof::Mini(z, p_bytes) => {
            let proof = Proof::<E>::read(&p_bytes[..]).map_err(|_| ())?;

            let pvk = if is_pp {
                PreparedVerifyingKey::<E>::read(vk).map_err(|_| ())?
            } else {
                let vk = VerifyingKey::<E>::read(vk).map_err(|_| ())?;
                prepare_verifying_key(&vk)
            };
            let repr_z = <E::Fr as PrimeField>::BigInt::from(z as u64);

            verify_proof(&pvk, &proof, &[<E::Fr as PrimeField>::from_repr(repr_z)]).map_err(|_| ())
        }
        _ => Err(()),
    }
}

#[cfg(feature = "bulletproofs")]
pub fn bulletproofs_prove<E: PairingEngine, R: rand::Rng>(
    g: &Gadget,
    _pk: &[u8],
    mut rng: R,
) -> Result<GadgetProof, ()> {
    use scheme::bulletproofs::arithmetic_circuit::create_proof;

    match g {
        Gadget::Mini(x, y, z) => {
            let repr_x = <E::Fr as PrimeField>::BigInt::from(*x as u64);
            let repr_y = <E::Fr as PrimeField>::BigInt::from(*y as u64);
            let repr_z = <E::Fr as PrimeField>::BigInt::from(*z as u64);
            let mc = Mini::<E::Fr> {
                x: Some(<E::Fr as PrimeField>::from_repr(repr_x)),
                y: Some(<E::Fr as PrimeField>::from_repr(repr_y)),
                z: Some(<E::Fr as PrimeField>::from_repr(repr_z)),
            };

            let (generators, r1cs_circuit, proof, assignment) =
                create_proof::<E, _, _>(mc, &mut rng).map_err(|_| ())?;

            let mut p_bytes = Vec::new();
            generators.write(&mut p_bytes).map_err(|_| ())?;
            r1cs_circuit.write(&mut p_bytes).map_err(|_| ())?;
            proof.write(&mut p_bytes).map_err(|_| ())?;
            (assignment.s.len() as u64)
                .write(&mut p_bytes)
                .map_err(|_| ())?;
            for i in &assignment.s {
                i.write(&mut p_bytes).map_err(|_| ())?;
            }

            Ok(GadgetProof::Mini(*z, p_bytes))
        }
        _ => Err(()),
    }
}

#[cfg(feature = "bulletproofs")]
pub fn bulletproofs_verify<E: PairingEngine>(
    g: GadgetProof,
    _vk: &[u8],
    _is_pp: bool,
) -> Result<bool, ()> {
    use scheme::bulletproofs::arithmetic_circuit::{verify_proof, Generators, Proof, R1csCircuit};
    match g {
        GadgetProof::Mini(_z, p_bytes) => {
            let mut bytes = &p_bytes[..];
            let generators = Generators::<E>::read(&mut bytes).map_err(|_| ())?;
            let r1cs_circuit = R1csCircuit::<E>::read(&mut bytes).map_err(|_| ())?;
            let proof = Proof::<E>::read(&mut bytes).map_err(|_| ())?;
            let s_len = u64::read(&mut bytes).map_err(|_| ())?;
            let mut s = vec![];
            for _ in 0..s_len {
                let v = E::Fr::read(&mut bytes).map_err(|_| ())?;
                s.push(v);
            }

            Ok(verify_proof(&generators, &proof, &r1cs_circuit, &s))
        }
        _ => Err(()),
    }
}
