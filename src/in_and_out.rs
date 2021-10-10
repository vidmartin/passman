
use crate::passman_error::*;

use std::io::{self, Write};

pub fn print_flush(msg: &str) {
    print!("{}", msg);
    io::stdout().flush().unwrap();
}

pub fn input_password_for_profile(profile: &str) -> String {
    print_flush(format!("password for {}: ", profile).as_str());
    return rpassword::read_password()
        .expect("couldn't read password");
}

pub fn input_new_password() -> PassmanResult<String> {
    print_flush("enter new password: ");
    let pwd1 = rpassword::read_password()
        .expect("couldn't read password");
    print_flush("confirm password: ");
    let pwd2 = rpassword::read_password()
        .expect("couldn't read password");

    return if pwd1 == pwd2 { Ok(pwd1) } else { Err(PassmanError::PasswordNotConfirmed) } 
}

pub fn input_new_value(value_name: &str) -> String {
    print_flush(format!("enter new value for '{}': ", value_name).as_str());
    return rpassword::read_password().unwrap();
}
