use ark_std::string::String;

use crate::ahp::Error as AHPError;

#[derive(Debug)]
pub enum Error<E> {
    PolynomialDegreeTooLarge,
    CircuitTooLarge,
    AlreadyPreprocessed,
    MissingEvaluation(String),
    PolynomialCommitmentError(E),
    PolynomialProtocolError(AHPError),
    Other,
}

impl<E> From<AHPError> for Error<E> {
    fn from(err: AHPError) -> Self {
        Error::PolynomialProtocolError(err)
    }
}

impl<E> Error<E> {
    pub fn from_pc_err(err: E) -> Self {
        Error::PolynomialCommitmentError(err)
    }
}
