use crate::protocol::Error as PError;

#[derive(Debug)]
pub enum Error<E> {
    PolynomialDegreeTooLarge,
    CircuitTooLarge,
    AlreadyPreprocessed,
    MissingEvaluation(String),
    PolynomialCommitmentError(E),
    PolynomialProtocolError(PError),
    Other,
}

impl<E> From<PError> for Error<E> {
    fn from(err: PError) -> Self {
        Error::PolynomialProtocolError(err)
    }
}

impl<E> Error<E> {
    pub fn from_pc_err(err: E) -> Self {
        Error::PolynomialCommitmentError(err)
    }
}
