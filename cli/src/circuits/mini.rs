use ark_ff::PrimeField;
use zkp_r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

use super::{CliCircuit, Publics};

pub struct Mini<F: PrimeField> {
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

impl<F: PrimeField> CliCircuit<F> for Mini<F> {
    fn power_off() -> Self {
        Mini {
            x: None,
            y: None,
            z: None,
            num: 10,
        }
    }

    fn power_on(args: &[String]) -> (Self, Publics<F>) {
        let x = args[0]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");
        let y = args[1]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");
        let z = args[2]
            .as_str()
            .parse::<u64>()
            .expect("Interger parse error");

        (
            Mini {
                x: Some(F::from(x)),
                y: Some(F::from(y)),
                z: Some(F::from(z)),
                num: 10,
            },
            Publics::Mini(z),
        )
    }

    fn options() -> String {
        "[x] [y] [z]".to_owned()
    }
}
