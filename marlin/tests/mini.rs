use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::PrimeField;
use ark_std::test_rng;
use zkp_marlin::{create_random_proof, index, universal_setup, verify_proof};
use zkp_r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

struct Mini<F: PrimeField> {
    pub x: Option<F>,
    pub y: Option<F>,
    pub z: Option<F>,
    pub num: u32,
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

        for _ in 0..self.num {
            cs.enforce(
                || "x * (y + 2) = z",
                |lc| lc + var_x,
                |lc| lc + var_y + (F::from(2u32), CS::one()),
                |lc| lc + var_z,
            );
        }

        Ok(())
    }
}

#[test]
fn mini_marlin() {
    let rng = &mut test_rng();
    let num = 10;

    // TRUSTED SETUP
    println!("Marlin setup...");
    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };

    let srs = universal_setup::<E, _>(2usize.pow(10), rng).unwrap();
    println!("marlin indexer...");
    let (ipk, ivk) = index(&srs, c).unwrap();

    let circuit = Mini {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: num,
    };

    let proof = create_random_proof(&ipk, circuit, rng).unwrap();

    assert!(verify_proof(&ivk, &proof, &[Fr::from(10u32)]).unwrap());
}
