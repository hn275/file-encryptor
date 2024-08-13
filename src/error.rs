use std::{error, fmt, io, process, result};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    IO(String),
}

impl error::Error for Error {}

unsafe impl Send for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IO(msg) => write!(f, "{}", msg),
        }
    }
}

impl process::Termination for Error {
    fn report(self) -> process::ExitCode {
        match self {
            Self::IO(_) => process::ExitCode::from(1),
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value.to_string())
    }
}
