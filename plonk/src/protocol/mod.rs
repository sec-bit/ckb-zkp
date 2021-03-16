use crate::composer::Error as CSError;

mod preprocessor;
pub use preprocessor::{PreprocessorInfo, PreprocessorKeys};

mod prover;
pub use prover::Prover;

mod verifier;
pub use verifier::Verifier;

#[derive(Debug)]
pub enum Error {
    SynthesisError(CSError),
}

impl From<CSError> for Error {
    fn from(err: CSError) -> Error {
        Error::SynthesisError(err)
    }
}
