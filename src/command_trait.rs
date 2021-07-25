
use crate::passman_error::*;

pub trait Command {
    /// execute the command. the first value in args is the command itself.
    fn exec(&self, args: Vec<&str>) -> PassmanResult<()>;

    /// get the name of this command.
    fn get_command_name(&self) -> &'static str;
}