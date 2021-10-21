use ark_std::string::String;
use std::io;

use crate::ahp::Error as AHPError;

#[derive(Debug)]
pub enum Error {
    PolynomialDegreeTooLarge,
    CircuitTooLarge,
    AlreadyPreprocessed,
    MissingEvaluation(String),
    // PolynomialCommitmentError(E),
    PolynomialProtocolError(AHPError),
    Other,
    IoError(io::Error),
}

impl From<AHPError> for Error {
    fn from(err: AHPError) -> Self {
        Error::PolynomialProtocolError(err)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}