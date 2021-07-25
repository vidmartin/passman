
use crate::command_trait::Command;
use crate::passman_error::*;
use crate::in_and_out::*;
use crate::profiles::*;
use std::collections::HashMap;

struct GetCommand;
impl Command for GetCommand {
    fn exec(&self, args: Vec<&str>) -> PassmanResult<()> {
        let path_args = PwdPathArgs::from(args)?;
        let password = input_password_for_profile(path_args.get_profile());
        authenticate_profile(path_args.get_profile(), password.as_str())?;
        let value = get_value(path_args.get_profile(), path_args.get_password_name(), password.as_str())?;
        let out_msg = format!("value of '{}': {}", path_args.get_password_name(), value);
        print_flush(out_msg.as_str());
        console::Term::stdout().read_key().unwrap();
        print_flush(format!("\r{}\r", std::iter::repeat(" ").take(out_msg.len()).collect::<String>()).as_str());

        return Ok(());
    }

    fn get_command_name(&self) -> &'static str {
        "get"
    }

    fn max_args(&self) -> usize {
        1
    }    
}

struct SetCommand;
impl Command for SetCommand {
    fn exec(&self, args: Vec<&str>) -> PassmanResult<()> {
        let path_args = PwdPathArgs::from(args)?;
        let password = input_password_for_profile(path_args.get_profile());
        authenticate_profile(path_args.get_profile(), password.as_str())?;
        validate_name(path_args.get_password_name())?;
        set_value(path_args.get_profile(), path_args.get_password_name(), password.as_str())?;

        return Ok(());
    }

    fn get_command_name(&self) -> &'static str {
        "set"
    }

    fn max_args(&self) -> usize {
        1
    }
}

struct DelCommand;
impl Command for DelCommand {
    fn exec(&self, args: Vec<&str>) -> PassmanResult<()> {
        let path_args = PwdPathArgs::from(args)?;
        let password = input_password_for_profile(path_args.get_profile());
        authenticate_profile(path_args.get_profile(), password.as_str())?;
        del_value(path_args.get_profile(), path_args.get_password_name(), password.as_str())?;

        return Ok(());
    }

    fn get_command_name(&self) -> &'static str {
        "del"
    }

    fn max_args(&self) -> usize {
        1
    }    
}

struct ListCommand;
impl Command for ListCommand {
    fn exec(&self, args: Vec<&str>) -> PassmanResult<()> {
        if args.len() == 2 {
            let profiles = list_profiles().collect::<Vec<String>>();
            println!("all profiles:");
            println!("{}", profiles.join("\n"));
        } else if args.len() == 3 {
            let profile_name = get_profile_name_single(&args)?;
            let password = input_password_for_profile(profile_name);
            authenticate_profile(profile_name, password.as_str())?;
            let names = list_value_names(profile_name, password.as_str());
            println!("names of passwords in profile '{}':", profile_name);
            println!("{}", names.join("\n"));
        } else {
            return Err(PassmanError::MissingArgument);
        }

        return Ok(());
    }

    fn get_command_name(&self) -> &'static str {
        "list"
    }

    fn max_args(&self) -> usize {
        1
    }    
}

struct SetProfilePasswordCommand;
impl Command for SetProfilePasswordCommand {
    fn exec(&self, args: Vec<&str>) -> PassmanResult<()> {
        let profile_name = get_profile_name_single(&args)?;
        let old_password = input_password_for_profile(profile_name);
        authenticate_profile(profile_name, old_password.as_str())?;
        set_profile_password(profile_name, old_password.as_str())?;

        return Ok(());
    }

    fn get_command_name(&self) -> &'static str {
        "set-profile-password"
    }

    fn max_args(&self) -> usize {
        1
    }    
}

struct AddProfileCommand;
impl Command for AddProfileCommand {
    fn exec(&self, args: Vec<&str>) -> PassmanResult<()> {
        let profile_name = get_profile_name_single(&args)?;
        validate_name(profile_name)?;
        match new_profile(profile_name) {
            Ok(()) => println!("profile created successfully"),
            Err(err) => println!("an error occured: {}", err)
        };

        return Ok(());
    }

    fn get_command_name(&self) -> &'static str {
        "add-profile"
    }

    fn max_args(&self) -> usize {
        1
    }    
}

struct DelProfileCommand;
impl Command for DelProfileCommand {
    fn exec(&self, args: Vec<&str>) -> PassmanResult<()> {
        let profile_name = get_profile_name_single(&args)?;
        let password = input_password_for_profile(profile_name);
        authenticate_profile(profile_name, password.as_str())?;
        del_profile(profile_name)?;

        return Ok(());
    }

    fn get_command_name(&self) -> &'static str {
        "del-profile"
    }

    fn max_args(&self) -> usize {
        1
    }    
}

struct CopyProfileCommand;
impl Command for CopyProfileCommand {
    fn exec(&self, args: Vec<&str>) -> PassmanResult<()> {
        let profile_name_from = get_profile_name_at::<2>(&args)?;
        let profile_name_to = get_profile_name_at::<3>(&args)?;
        copy_profile(profile_name_from, profile_name_to)?;

        println!("profile '{}' copied to '{}' successsfully", profile_name_from, profile_name_to);

        return Ok(());
    }

    fn get_command_name(&self) -> &'static str {
        "copy-profile"
    }

    fn max_args(&self) -> usize {
        2
    }    
}

pub fn get_command_dict() -> HashMap<&'static str, Box<dyn Command>> {
    let commands: Vec<Box<dyn Command>> = vec![
        Box::new(GetCommand),
        Box::new(SetCommand),
        Box::new(DelCommand),
        Box::new(ListCommand),
        Box::new(SetProfilePasswordCommand),
        Box::new(AddProfileCommand),        
        Box::new(DelProfileCommand) ,
        Box::new(CopyProfileCommand)       
    ];

    commands.into_iter().map(|command| -> (&'static str, Box<dyn Command>) { 
            (command.get_command_name(), command) 
        })
        .collect::<HashMap<&'static str, Box<dyn Command>>>()
}