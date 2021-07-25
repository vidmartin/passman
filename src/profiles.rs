
use crate::passman_error::*;
use crate::cryptostuff::*;
use crate::in_and_out::*;

use std::io::{self, BufRead, Write};
use std::path::{self, Path};
use std::fs::{self, File};

pub const DEFAULT_PROFILE: &str = "default";
pub const PROFILES_DIR: &str = "./profiles";
pub const PROFILE_FILENAME_EXTENSION: &str = "txt";
pub const PROFILE_TEMP_FILENAME_EXTENSION: &str = "temp";
pub const PROFILE_BACKUP_FILENAME_EXTENSION: &str = "bak";

pub fn get_profile_name_single<'a>(args: &'a Vec<&'a str>) -> PassmanResult<&'a str> {
    args.get(2).map(|val| *val)
        .ok_or(PassmanError::MissingArgument)
}

pub fn get_profile_name_at<'a, const I: usize>(args: &'a Vec<&'a str>) -> PassmanResult<&'a str> {
    args.get(I).map(|val| *val)
        .ok_or(PassmanError::MissingArgument)
}

pub fn validate_name(profile: &str) -> Result<(), PassmanError> {
    if profile.chars().all(|ch| ch.is_alphanumeric() || ch == '_' || ch == '-') {
        Ok(())
    } else {
        Err(PassmanError::InvalidName)
    }
}

pub fn profile_path(profile: &str, extension: &str) -> path::PathBuf {
    // TODO: proper errors
    Path::new(PROFILES_DIR)
        .canonicalize()
        .expect("couldn't get absolute path")
        .join(format!("{}.{}", profile, extension))    
}


pub fn authenticate_profile(profile: &str, password: &str) -> Result<(), PassmanError> {
    let pwd_hash_base64_attempt = hash_str(password);

    let file = File::open(profile_path(profile, PROFILE_FILENAME_EXTENSION))
        .map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => PassmanError::ProfileNotFound,
            _ => PassmanError::Unexpected(Box::new(err))
        })?;

    let mut reader = io::BufReader::new(file);
    let mut pwd_hash_base64_correct = String::new();
    reader.read_line(&mut pwd_hash_base64_correct).into_passman_result()?; // first line - check hash

    return if pwd_hash_base64_attempt == pwd_hash_base64_correct.trim() {
        Ok(())
    } else {
        Err(PassmanError::IncorrectPassword)
    }
}

pub fn new_profile(profile: &str) -> Result<(), PassmanError> {
    let profile_path = profile_path(profile, PROFILE_FILENAME_EXTENSION);
    if profile_path.exists() {
        return Err(PassmanError::ProfileAlreadyExists);
    }

    let password = input_new_password()?;
    let password_hash = hash_str(password.as_str());

    let file = File::create(profile_path).unwrap();
    let mut writer = io::BufWriter::new(file);    

    writer.write((password_hash + "\n").as_bytes()).unwrap();

    return Ok(());
}

pub fn get_value(profile: &str, value_name: &str, profile_password: &str) -> Result<String, PassmanError> {
    let value_name_hash = encrypt_str(value_name, profile_password);

    let src_file_path = profile_path(profile, PROFILE_FILENAME_EXTENSION);
    let src_file = File::open(src_file_path).unwrap();
    let src_file_reader = io::BufReader::new(src_file);

    for line in src_file_reader.lines().skip(1).map(Result::unwrap) {
        let split = line.split(":").collect::<Vec<&str>>();    
        if split.len() != 2 {
            return Err(PassmanError::FileFormat);
        }

        if split[0] == value_name_hash {
            return Ok(decrypt_str(split[1], profile_password));
        }
    }

    return Err(PassmanError::NameNotFound);
}

pub fn temp_to_src(temp_path: &path::PathBuf, src_path: &path::PathBuf, bak_path: &path::PathBuf) {
    let renaming_result = {
        // move the temporary file into the source file, but before that backup the source file
        fs::rename(src_path, bak_path)
            .and_then(|()| fs::rename( temp_path, src_path))
    };

    if renaming_result.is_err() {
        // if something went wrong, restore the backup
        fs::rename(bak_path, src_path).unwrap();
    }

    fs::remove_file(bak_path).unwrap(); // delete backup file
}

pub fn set_value(profile: &str, value_name: &str, profile_password: &str) -> Result<(), PassmanError> {
    let value_name_hash = encrypt_str(value_name, profile_password);

    let new_value = input_new_value(value_name);
    let new_value_encrypted = encrypt_str(new_value.as_str(), profile_password);

    let temp_file_path = profile_path(profile, PROFILE_TEMP_FILENAME_EXTENSION);
    let src_file_path = profile_path(profile, PROFILE_FILENAME_EXTENSION);
    let bak_file_path = profile_path(profile, PROFILE_BACKUP_FILENAME_EXTENSION);

    let temp_file = File::create(&temp_file_path).unwrap();
    let src_file = File::open(&src_file_path).unwrap();

    let mut temp_file_writer = io::BufWriter::new(temp_file);
    let mut src_file_reader = io::BufReader::new(src_file);

    let mut found_value: bool = false;

    let mut first_line = String::new();
    src_file_reader.read_line(&mut first_line).unwrap();
    temp_file_writer.write(first_line.as_bytes()).unwrap();

    for line in src_file_reader.lines()
        .map(Result::unwrap) {
        if line.trim().is_empty() {
            continue; // skip empty lines
        }

        let mut split = line.split(':').collect::<Vec<&str>>();
        if split.len() != 2 {
            return Err(PassmanError::FileFormat);
        }

        if split[0] == value_name_hash { // we found the value we want
            split[1] = new_value_encrypted.as_str();
            found_value = true;
        }

        temp_file_writer.write((split.join(":") + "\n").as_bytes()).unwrap();
    }

    if !found_value {
        // if the value wasn't found in the file, put it on a new line
        temp_file_writer.write((value_name_hash + ":" + new_value_encrypted.as_str() + "\n").as_bytes()).unwrap();
    }

    temp_to_src(&temp_file_path, &src_file_path, &bak_file_path);

    return Ok(());
}

pub fn del_value(profile: &str, value_name: &str, password: &str) -> Result<(), PassmanError> {
    let value_name_hash = encrypt_str(value_name, password);

    let temp_file_path = profile_path(profile, PROFILE_TEMP_FILENAME_EXTENSION);
    let src_file_path = profile_path(profile, PROFILE_FILENAME_EXTENSION);
    let bak_file_path = profile_path(profile, PROFILE_BACKUP_FILENAME_EXTENSION);

    let temp_file = File::create(&temp_file_path).unwrap();
    let src_file = File::open(&src_file_path).unwrap();

    let mut temp_file_writer = io::BufWriter::new(temp_file);
    let mut src_file_reader = io::BufReader::new(src_file);

    let mut found_value: bool = false;

    let mut first_line = String::new();
    src_file_reader.read_line(&mut first_line).unwrap();
    temp_file_writer.write(first_line.as_bytes()).unwrap();

    for line in src_file_reader.lines().map(Result::unwrap) {
        if line.trim().is_empty() {
            continue; // skip empty lines
        }

        let split = line.split(':').collect::<Vec<&str>>();
        if split.len() != 2 {
            return Err(PassmanError::FileFormat);
        }

        if split[0] == value_name_hash { // we found the value we want
            found_value = true;
            continue;
        }

        temp_file_writer.write((line + "\n").as_bytes()).unwrap();
    }

    if !found_value {
        return Err(PassmanError::NameNotFound);
    }

    temp_to_src(&temp_file_path, &src_file_path, &bak_file_path);

    return Ok(());
}

pub fn list_profiles() -> Box<dyn Iterator<Item = String>> {
    Box::new(fs::read_dir(PROFILES_DIR).unwrap().map(Result::unwrap)
        .filter(|entry| entry.file_type().unwrap().is_file())
        .map(|entry| path::PathBuf::from(entry.file_name()))
        .filter(|path| path.extension().unwrap().to_str().unwrap() == PROFILE_FILENAME_EXTENSION)
        .map(|path| path.with_extension("").file_name().unwrap().to_str().unwrap().to_owned()))
}

pub fn list_value_names<'a>(profile: &'a str, profile_password: &'a str) -> Vec<String> {
    let src_file_path = profile_path(profile, PROFILE_FILENAME_EXTENSION);
    let src_file = File::open(&src_file_path).unwrap();
    let src_file_reader = io::BufReader::new(src_file);

    src_file_reader.lines().map(Result::unwrap)
        .skip(1) // skip password hash
        .map(|line| line.split(':').map(|s| s.to_owned()).collect::<Vec<String>>())
        .filter(|line| line.len() == 2)
        .map(|line| decrypt_str(line[0].as_str(), profile_password))
        .collect::<Vec<String>>()
}

pub fn set_profile_password(profile_name: &str, profile_old_password: &str) -> Result<(), PassmanError> {
    let profile_new_password = input_new_password()?;
    let profile_new_password_hash = hash_str(profile_new_password.as_str());

    let temp_file_path = profile_path(profile_name, PROFILE_TEMP_FILENAME_EXTENSION);
    let src_file_path = profile_path(profile_name, PROFILE_FILENAME_EXTENSION);
    let bak_file_path = profile_path(profile_name, PROFILE_BACKUP_FILENAME_EXTENSION);

    let temp_file = File::create(&temp_file_path).unwrap();
    let src_file = File::open(&src_file_path).unwrap();

    let mut temp_file_writer = io::BufWriter::new(temp_file);
    let src_file_reader = io::BufReader::new(src_file);

    temp_file_writer.write((profile_new_password_hash + "\n").as_bytes()).unwrap();

    for line in src_file_reader.lines().skip(1).map(Result::unwrap) {
        let split = line.split(':').collect::<Vec<&str>>();

        if split.len() != 2 {
            return Err(PassmanError::FileFormat);
        }

        let name_decrypted = decrypt_str(split[0], profile_old_password);
        let value_decrypted = decrypt_str(split[1], profile_old_password);

        let name_encrypted = encrypt_str(name_decrypted.as_str(), profile_new_password.as_str());
        let value_encrypted = encrypt_str(value_decrypted.as_str(), profile_new_password.as_str());

        temp_file_writer.write((name_encrypted + ":" + value_encrypted.as_str() + "\n").as_bytes()).unwrap();
    }

    temp_to_src(&temp_file_path, &src_file_path, &bak_file_path);

    return Ok(());    
}

pub fn del_profile(profile_name: &str) -> Result<(), PassmanError> {
    let path = profile_path(profile_name, PROFILE_FILENAME_EXTENSION);
    fs::remove_file(path).unwrap();
    return Ok(());
}

pub fn copy_profile(profile_name_from: &str, profile_name_to: &str) -> Result<(), PassmanError> {
    let path_from = profile_path(profile_name_from, PROFILE_FILENAME_EXTENSION);
    let path_to = profile_path(profile_name_to, PROFILE_FILENAME_EXTENSION);
    fs::copy(path_from, path_to).unwrap();
    return Ok(());
}

pub struct PwdPathArgs<'a> {
    path: Vec<&'a str>
}

impl PwdPathArgs<'_> {
    pub fn from<'a, T: IntoIterator<Item = &'a str>>(args: T) -> PassmanResult<PwdPathArgs<'a>> {        
        match args.into_iter().nth(2) {
            None => return Err(PassmanError::MissingArgument),
            Some(s) => {
                let mut split = s.split('.')
                    .collect::<Vec<&str>>();
                if split.len() > 2 {
                    return Err(PassmanError::InvalidPath(s.to_owned()))
                }
                if split.len() == 1 {
                    split.insert(0, DEFAULT_PROFILE);
                }
                if split.iter().any(|s| s.is_empty()) {
                    return Err(PassmanError::MissingArgument);
                }

                return Ok(PwdPathArgs { path: split });
            }
        }
    }

    pub fn get_profile(&self) -> &str {
        self.path[0]
    }

    pub fn get_password_name(&self) -> &str {
        self.path[1]
    }
}