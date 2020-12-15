use ckb_zkp::math::Field;
use ckb_zkp::r1cs::ConstraintSynthesizer;

pub enum Publics<F: Field> {
    Mini(u64),
    Hash(F),
}

pub trait CliCircuit<F: Field>: Sized + ConstraintSynthesizer<F> {
    fn power_off() -> Self;

    fn power_on(args: &[String]) -> (Self, Publics<F>);

    fn options() -> String;
}

pub mod hash;
pub mod mini;
