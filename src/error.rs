use std::fmt::{self, Display, Formatter};


#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidKeySize,
    InvalidNonceSize,
    InvalidTag,
}

impl Display for Error {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        match self {
            Error::InvalidNonceSize => {
                write!(fmt, "invalid nonce size")
            }
            Error::InvalidInputSize => {
                write!(fmt, "invalid input size")
            }
            Error::InvalidTag => {
                write!(fmt, "invalid authentication tag")
            }
        }
    }
}

impl std::error::Error for Error {}
