use std::{error, fmt, io, process, result};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    IO(String),
    Key,
    Other(String),
}

impl Error {
    pub fn status_code(&self) -> u8 {
        match self {
            Self::Other(_) => 1,
            Self::IO(_) => 2,
            Self::Key => 3,
        }
    }
}

impl error::Error for Error {}

unsafe impl Send for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IO(msg) => write!(f, "{}", msg),
            Self::Key => write!(f, "Invalid key"),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl process::Termination for Error {
    fn report(self) -> process::ExitCode {
        self.status_code().into()
    }
}

impl From<io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value.to_string())
    }
}

impl From<anyhow::Error> for Error {
    fn from(value: anyhow::Error) -> Self {
        Self::Other(value.to_string())
    }
}
