use std::{
    fmt::Display,
    process::{ExitCode, Termination},
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[allow(dead_code)]
pub enum Error {
    IO(String),
    Key(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IO(msg) => write!(f, "{}", msg),
            Self::Key(msg) => write!(f, "{}", msg),
        }
    }
}

impl Termination for Error {
    fn report(self) -> ExitCode {
        match self {
            Self::IO(_) => ExitCode::from(1),
            Self::Key(_) => ExitCode::from(2),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value.to_string())
    }
}
