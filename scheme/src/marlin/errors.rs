use crate::marlin::ahp::Error as AHPError;
use crate::marlin::pc::Error as PCError;

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
