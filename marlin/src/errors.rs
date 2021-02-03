use zkp_r1cs::SynthesisError;

use crate::ahp::Error as AHPError;
use crate::pc::Error as PCError;
use crate::String;

#[derive(Debug)]
pub enum Error {
    IndexTooLarge,
    MissingEval(String),
    AHPError(AHPError),
    PCError(PCError),
}

impl From<AHPError> for Error {
    fn from(err: AHPError) -> Self {
        Error::AHPError(err)
    }
}

impl From<PCError> for Error {
    fn from(err: PCError) -> Self {
        Error::PCError(err)
    }
}

impl From<Error> for SynthesisError {
    fn from(_err: Error) -> SynthesisError {
        SynthesisError::Unsatisfiable // Maybe can better.
    }
}

impl From<PCError> for SynthesisError {
    fn from(_err: PCError) -> SynthesisError {
        SynthesisError::Unsatisfiable // Maybe can better.
    }
}

impl From<AHPError> for SynthesisError {
    fn from(_err: AHPError) -> SynthesisError {
        SynthesisError::Unsatisfiable // Maybe can better.
    }
}
