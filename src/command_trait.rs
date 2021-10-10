
use crate::passman_error::*;

pub trait Command {
    /// execute the command. the 'args' parameter should contain all command-line arguments, including the process name and the name of this command.
    fn exec(&self, args: Vec<&str>) -> PassmanResult<()>;

    /// get the name of this command.
    fn get_command_name(&self) -> &'static str;

    /// the maximum amount of arguments that this command may take - this doesn't include the name of the process and the name of the command.
    fn max_args(&self) -> usize;    
}