use crate::{
    error,
    ioutils::{FileArg, IO},
};

pub fn open(arg: &FileArg) -> error::Result<()> {
    let mut _io = IO::new(&arg.input_file, &arg.output_file)?;

    Ok(())
}
