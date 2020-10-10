// The following code is from (scipr-lab's zexe)[https://github.com/scipr-lab/zexe] and thanks for their work

use core::fmt;
use math::io;

use super::super::kzg10::Error as KZG10Error;
use super::super::clinkv2_ipa::ipa::Error as IPAError;

/// This is an error that could occur during circuit synthesis contexts,
/// such as CRS generation, proving or verification.
#[derive(Debug)]
pub enum SynthesisError {
    /// During synthesis, we lacked knowledge of a variable assignment.
    AssignmentMissing,
    /// During synthesis, we divided by zero.
    DivisionByZero,
    /// During synthesis, we constructed an unsatisfiable constraint system.
    Unsatisfiable,
    /// During synthesis, our polynomials ended up being too high of degree
    PolynomialDegreeTooLarge,
    /// During proof generation, we encountered an identity in the CRS
    UnexpectedIdentity,
    /// During proof generation, we encountered an I/O error with the CRS
    IoError(io::Error),
    /// During verification, our verifying key was malformed.
    MalformedVerifyingKey,
    /// During CRS generation, we observed an unconstrained auxiliary variable
    UnconstrainedVariable,
    /// Incorrect Index during Variable allocation.
    IncorrectIndex,
    /// Error when committing polynomials.
    KZG10PolyComError(KZG10Error),
    /// Error when committing polynomials.
    IPAPolyComError(IPAError),
}

impl From<io::Error> for SynthesisError {
    fn from(e: io::Error) -> SynthesisError {
        SynthesisError::IoError(e)
    }
}

impl From<KZG10Error> for SynthesisError {
    fn from(e: KZG10Error) -> SynthesisError {
        SynthesisError::KZG10PolyComError(e)
    }
}

impl From<IPAError> for SynthesisError {
    fn from(e: IPAError) -> SynthesisError {
        SynthesisError::IPAPolyComError(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SynthesisError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl fmt::Display for SynthesisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            SynthesisError::AssignmentMissing => {
                write!(f, "an assignment for a variable could not be computed")
            }
            SynthesisError::DivisionByZero => write!(f, "division by zero"),
            SynthesisError::Unsatisfiable => write!(f, "unsatisfiable constraint system"),
            SynthesisError::PolynomialDegreeTooLarge => write!(f, "polynomial degree is too large"),
            SynthesisError::UnexpectedIdentity => {
                write!(f, "encountered an identity element in the CRS")
            }
            SynthesisError::IoError(err) => write!(f, "I/O error: {:?}", err),
            SynthesisError::MalformedVerifyingKey => write!(f, "malformed verifying key"),
            SynthesisError::UnconstrainedVariable => {
                write!(f, "auxiliary variable was unconstrained")
            }
            SynthesisError::IncorrectIndex => {
                write!(f, "Incorrect Index during Variable allocation")
            }
            /*SynthesisError::PolyCommitError => {
                write!(f, "Error when committing polynomials")
            }*/
            SynthesisError::KZG10PolyComError(err) => write!(f, "KZG10 PolyCommit error: {:?}", err),
            SynthesisError::IPAPolyComError(err) => write!(f, "IPA PolyCommit error: {:?}", err),
        }
    }
}
