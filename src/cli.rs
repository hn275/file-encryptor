use clap::{Parser, Subcommand};

/// A small Rust program to deal with file encryption.
#[derive(Parser, Debug)]
pub struct CLI {
    /// Action to perform on the input file
    #[command(subcommand)]
    pub action: Action,

    /// Key used to perform the ciphering action
    /// TODO: implement this
    #[arg(short, long)]
    pub key: Option<String>,

    /// Receiver of the file, this will be used as authenticated data.
    /// TODO: implement this
    #[arg(short, long)]
    pub auth_data: Option<String>,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Action {
    /// Decrypt a file
    Open {
        /// input file
        input_file: String,

        /// output file to write to
        #[arg(short, long)]
        write: Option<String>,

        /// additional authenticated data
        /// TODO: implement this
        #[arg(short, long)]
        aad: Option<String>,
    },

    /// Encrypt a file
    Seal {
        /// input file
        input_file: String,

        /// output file to write to
        #[arg(short, long)]
        write: Option<String>,

        /// additional authenticated data
        /// TODO: implement this
        #[arg(short, long)]
        aad: Option<String>,
    },

    /// Read in a key, process and hash. The input key will be read in _at most 64 bytes_.
    KeyGen {
        /// password
        #[arg(short, long)]
        password: Option<String>,

        #[arg(short, long)]
        base64: bool,
    },
}
