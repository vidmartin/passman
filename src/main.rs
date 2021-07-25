
mod passman_error;
mod command_trait;
mod commands;
mod cryptostuff;
mod profiles;
mod in_and_out;

extern crate crypto;
extern crate rpassword;
extern crate base64;
extern crate console;

use crate::passman_error::{PassmanError, PassmanResult};

use std::fs;
use std::path;
use std::env;

fn main() {
    env::set_current_dir(env::current_exe().unwrap().parent().unwrap()).unwrap();

    if !path::Path::new(profiles::PROFILES_DIR).is_dir() {
        fs::create_dir(profiles::PROFILES_DIR).unwrap();
    }

    match main_err() {
        Ok(()) => { },
        Err(err) => {
            println!("{}", err.to_string());
        }
    }
}

fn main_err() -> PassmanResult<()> {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() > 3 {
         return Err(PassmanError::TooManyArgs) 
    } 

    let verb = args.get(1).map(|val| val.as_str());

    let commands = commands::get_command_dict();

    return match verb {
        None => Err(PassmanError::NoVerb),
        Some(s) => {
            match commands.get(s) {
                None => { 
                    Err(PassmanError::InvalidVerb(s.to_owned()))
                },
                Some(command_boxed) => {
                    command_boxed.exec(args.iter().map(String::as_str).collect())
                }
            }
        }
    };
}

