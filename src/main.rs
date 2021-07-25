
extern crate crypto;
extern crate rpassword;
extern crate base64;
extern crate console;

use std::io::{self, BufRead, Read, Write};
use std::path::{self, Path};
use std::fs::{self, File};
use std::env::{self};
use std::ptr::hash;
use std::rc::{Rc};

use crypto::buffer::{self, ReadBuffer, WriteBuffer};
use crypto::digest::Digest;

fn main() {
    env::set_current_dir(env::current_exe().unwrap().parent().unwrap()).unwrap();
    // println!("{}", authenticate_profile(DEFAULT_PROFILE, &get_password_for_profile(DEFAULT_PROFILE)));

    if !path::Path::new(PROFILES_DIR).is_dir() {
        fs::create_dir(PROFILES_DIR).unwrap();
    }

    match main_err() {
        Ok(()) => { },
        Err(err) => {
            println!("{}", err.to_string());
        }
    }
}

#[derive(Debug, Clone)]
enum PassmanError {
    InvalidVerb(String),
    InvalidPath(String),
    MissingArgument,
    TooManyArgs,
    IncorrectPassword,
    PasswordNotConfirmed,
    ProfileNotFound,
    ProfileAlreadyExists,
    NameNotFound,
    InvalidName,
    FileFormat,
    Unexpected(Rc<dyn std::error::Error>)
}

type PassmanResult<T> = Result<T, PassmanError>;

impl std::fmt::Display for PassmanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::InvalidVerb(verb) => if verb == "" { "no verb specified".to_owned() } else { format!("invalid verb '{}'", verb) },
            Self::InvalidPath(path) => format!("invalid path '{}'", path),
            Self::MissingArgument => "missing argument!".to_owned(),
            Self::TooManyArgs => "too many arguments!".to_owned(),
            Self::IncorrectPassword => "incorrect password!".to_owned(),
            Self::PasswordNotConfirmed => "password confirmation unsuccessful".to_owned(),
            Self::ProfileNotFound => "profile doesn't exist".to_owned(),
            Self::ProfileAlreadyExists => "profile already exists".to_owned(),
            Self::InvalidName => "invalid name".to_owned(),
            Self::FileFormat => "file not in correct format".to_owned(),
            Self::NameNotFound => "name not found".to_owned(),
            Self::Unexpected(rc) => format!("unexpected error - {}", rc),
            _ => "unknown error".to_owned()
        })
    }
}

const DEFAULT_PROFILE: &str = "default";
const PROFILES_DIR: &str = "./profiles";
const PROFILE_FILENAME_EXTENSION: &str = "txt";
const PROFILE_TEMP_FILENAME_EXTENSION: &str = "temp";
const PROFILE_BACKUP_FILENAME_EXTENSION: &str = "bak";

fn main_err() -> PassmanResult<()> {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() > 3 {
         return Err(PassmanError::TooManyArgs) 
    } 

    let verb = args.get(1);

    match verb.map(String::as_str) {
        None => { return Err(PassmanError::InvalidVerb("".to_string())) },
        Some("get") => {            
            let path_args = PwdPathArgs::from(args)?;
            let password = input_password_for_profile(path_args.get_profile());
            authenticate_profile(path_args.get_profile(), password.as_str())?;
            let value = get_value(path_args.get_profile(), path_args.get_password_name(), password.as_str())?;
            let out_msg = format!("value of '{}': {}", path_args.get_password_name(), value);
            print_flush(out_msg.as_str());
            console::Term::stdout().read_key().unwrap();
            print_flush(format!("\r{}\r", std::iter::repeat(" ").take(out_msg.len()).collect::<String>()).as_str());
        },
        Some("set") => {
            let path_args = PwdPathArgs::from(args)?;
            let password = input_password_for_profile(path_args.get_profile());
            authenticate_profile(path_args.get_profile(), password.as_str())?;
            validate_name(path_args.get_password_name())?;
            set_value(path_args.get_profile(), path_args.get_password_name(), password.as_str())?;
        },
        Some("del") => {
            let path_args = PwdPathArgs::from(args)?;
            let password = input_password_for_profile(path_args.get_profile());
            authenticate_profile(path_args.get_profile(), password.as_str())?;
            del_value(path_args.get_profile(), path_args.get_password_name(), password.as_str())?;
        },
        Some("list") => {
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
        },
        Some("set-profile-password") => {
            let profile_name = get_profile_name_single(&args)?;
            let old_password = input_password_for_profile(profile_name);
            authenticate_profile(profile_name.as_str(), old_password.as_str())?;
            set_profile_password(profile_name, old_password.as_str())?;
        },
        Some("add-profile") => {
            let profile_name = get_profile_name_single(&args)?;
            validate_name(profile_name)?;
            match new_profile(profile_name) {
                Ok(()) => println!("profile created successfully"),
                Err(err) => println!("an error occured: {}", err)
            }
        },
        Some("del-profile") => {
            let profile_name = get_profile_name_single(&args)?;
            let password = input_password_for_profile(profile_name.as_str());
            authenticate_profile(profile_name, password.as_str())?;
            del_profile(profile_name)?;
        },
        Some(s) => { 
            return Err(PassmanError::InvalidVerb(s.to_string())) 
        }
    };

    return Ok(());
}

fn get_profile_name_single(args: &Vec<String>) -> PassmanResult<&String> {
    args.get(2).ok_or(PassmanError::MissingArgument)
}

fn print_flush(msg: &str) {
    print!("{}", msg);
    io::stdout().flush().unwrap();
}

fn input_password_for_profile(profile: &str) -> String {
    print_flush(format!("password for {}: ", profile).as_str());
    return rpassword::read_password()
        .expect("couldn't read password");
}

fn input_new_password() -> PassmanResult<String> {
    print_flush("enter new password: ");
    let pwd1 = rpassword::read_password()
        .expect("couldn't read password");
    print_flush("confirm password: ");
    let pwd2 = rpassword::read_password()
        .expect("couldn't read password");

    return if pwd1 == pwd2 { Ok(pwd1) } else { Err(PassmanError::PasswordNotConfirmed) } 
}

fn input_new_value(value_name: &str) -> String {
    print_flush(format!("enter new value for '{}': ", value_name).as_str());
    return rpassword::read_password().unwrap();
}

fn validate_name(profile: &str) -> Result<(), PassmanError> {
    if profile.chars().all(|ch| ch.is_alphanumeric() || ch == '_' || ch == '-') {
        Ok(())
    } else {
        Err(PassmanError::InvalidName)
    }
}

fn profile_path(profile: &str, extension: &str) -> path::PathBuf {
    // TODO: proper errors
    Path::new(PROFILES_DIR)
        .canonicalize()
        .expect("couldn't get absolute path")
        .join(format!("{}.{}", profile, extension))    
}

fn hash_str(input: &str) -> String {
    let mut hasher = crypto::sha2::Sha256::new();
    hasher.input_str(input);
    let mut pwd_hash_bytes_attempt_store: [u8; 256] = [0; 256];    
    hasher.result(&mut pwd_hash_bytes_attempt_store);
    let pwd_hash_bytes_attempt = &pwd_hash_bytes_attempt_store[0..hasher.output_bytes()];
    return base64::encode(pwd_hash_bytes_attempt);
}

fn encrypt_str(input: &str, key_str: &str) -> String {
    let key = get_key_from_password(key_str);

    let mut encryptor = crypto::aes::cbc_encryptor(
        crypto::aes::KeySize::KeySize256,
        &key, &key[0..16], crypto::blockmodes::PkcsPadding);
        
    let encrypted_data = transform_data(
        input.as_bytes(),
        |read_buf, write_buf| {
            encryptor.encrypt(read_buf, write_buf, true)
        }
    ).unwrap();

    return base64::encode(encrypted_data);
}

fn decrypt_str(input_str: &str, key_str: &str) -> String {
    let key = get_key_from_password(key_str);

    let mut decryptor = crypto::aes::cbc_decryptor(
        crypto::aes::KeySize::KeySize256,
        &key, &key[0..16], crypto::blockmodes::PkcsPadding);

    let input_bytes = base64::decode(input_str).unwrap();
        
    let decrypted_data = transform_data(
        input_bytes.as_ref(),
        |read_buf, write_buf| {
            decryptor.decrypt(read_buf, write_buf, true)
        }
    ).unwrap();

    return String::from_utf8(decrypted_data).unwrap();
}

fn get_key_from_password(password: &str) -> Vec<u8> {
    let mut key: [u8; 32] = [0; 32];
    for (index, byte) in password.as_bytes().iter().enumerate() {
        key[index] = *byte;

        if index + 1 == key.len() {
            break;
        }
    }

    return key.to_vec();
}

fn transform_data<F>(input: &[u8], mut iteration: F) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError>
    where F: FnMut(&mut crypto::buffer::RefReadBuffer, &mut crypto::buffer::RefWriteBuffer) -> Result<crypto::buffer::BufferResult, crypto::symmetriccipher::SymmetricCipherError>
{
    let mut output_vec = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(input);
    let mut write_buffer_array: [u8; 4096] = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut write_buffer_array);

    loop {
        let result = iteration(&mut read_buffer, &mut write_buffer)?;

        output_vec.extend(write_buffer.take_read_buffer().take_remaining().iter());

        match result {
            buffer::BufferResult::BufferUnderflow => break,
            buffer::BufferResult::BufferOverflow => { }
        }
    }

    return Ok(output_vec);
}

fn authenticate_profile(profile: &str, password: &str) -> Result<(), PassmanError> {
    let pwd_hash_base64_attempt = hash_str(password);

    let file = File::open(profile_path(profile, PROFILE_FILENAME_EXTENSION))
        .map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => PassmanError::ProfileNotFound,
            _ => PassmanError::Unexpected(Rc::from(err))
        })?;

    let mut reader = io::BufReader::new(file);
    let mut pwd_hash_base64_correct = String::new();
    reader.read_line(&mut pwd_hash_base64_correct).unwrap(); // first line - check hash

    return if pwd_hash_base64_attempt == pwd_hash_base64_correct.trim() {
        Ok(())
    } else {
        Err(PassmanError::IncorrectPassword)
    }
}

fn new_profile(profile: &str) -> Result<(), PassmanError> {
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

fn get_value(profile: &str, value_name: &str, profile_password: &str) -> Result<String, PassmanError> {
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

fn temp_to_src(temp_path: &path::PathBuf, src_path: &path::PathBuf, bak_path: &path::PathBuf) {
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

fn set_value(profile: &str, value_name: &str, profile_password: &str) -> Result<(), PassmanError> {
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

fn del_value(profile: &str, value_name: &str, password: &str) -> Result<(), PassmanError> {
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

fn list_profiles() -> Box<dyn Iterator<Item = String>> {
    Box::new(fs::read_dir(PROFILES_DIR).unwrap().map(Result::unwrap)
        .filter(|entry| entry.file_type().unwrap().is_file())
        .map(|entry| path::PathBuf::from(entry.file_name()))
        .filter(|path| path.extension().unwrap().to_str().unwrap() == PROFILE_FILENAME_EXTENSION)
        .map(|path| path.with_extension("").file_name().unwrap().to_str().unwrap().to_owned()))
}

fn list_value_names<'a>(profile: &'a str, profile_password: &'a str) -> Vec<String> {
    let src_file_path = profile_path(profile, PROFILE_FILENAME_EXTENSION);
    let src_file = File::open(&src_file_path).unwrap();
    let mut src_file_reader = io::BufReader::new(src_file);

    src_file_reader.lines().map(Result::unwrap)
        .skip(1) // skip password hash
        .map(|line| line.split(':').map(|s| s.to_owned()).collect::<Vec<String>>())
        .filter(|line| line.len() == 2)
        .map(|line| decrypt_str(line[0].as_str(), profile_password))
        .collect::<Vec<String>>()
}

fn set_profile_password(profile_name: &str, profile_old_password: &str) -> Result<(), PassmanError> {
    let profile_new_password = input_new_password()?;
    let profile_new_password_hash = hash_str(profile_new_password.as_str());

    let temp_file_path = profile_path(profile_name, PROFILE_TEMP_FILENAME_EXTENSION);
    let src_file_path = profile_path(profile_name, PROFILE_FILENAME_EXTENSION);
    let bak_file_path = profile_path(profile_name, PROFILE_BACKUP_FILENAME_EXTENSION);

    let temp_file = File::create(&temp_file_path).unwrap();
    let src_file = File::open(&src_file_path).unwrap();

    let mut temp_file_writer = io::BufWriter::new(temp_file);
    let mut src_file_reader = io::BufReader::new(src_file);

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

fn del_profile(profile_name: &str) -> Result<(), PassmanError> {
    let path = profile_path(profile_name, PROFILE_FILENAME_EXTENSION);
    fs::remove_file(path).unwrap();
    return Ok(());
}

struct PwdPathArgs {
    path: Vec<String>
}

impl PwdPathArgs {
    fn from<T: IntoIterator<Item = String>>(args: T) -> PassmanResult<PwdPathArgs> {        
        match args.into_iter().nth(2) {
            None => return Err(PassmanError::MissingArgument),
            Some(s) => {
                let mut split = s.split('.')
                    .map(|slice| slice.trim().to_owned())
                    .collect::<Vec<String>>();
                if split.len() > 2 {
                    return Err(PassmanError::InvalidPath(s))
                }
                if split.len() == 1 {
                    split.insert(0, DEFAULT_PROFILE.to_owned());
                }
                if split.iter().any(|s| s.is_empty()) {
                    return Err(PassmanError::MissingArgument);
                }

                return Ok(PwdPathArgs { path: split });
            }
        }
    }

    fn get_profile(&self) -> &str {
        self.path[0].as_str()
    }

    fn get_password_name(&self) -> &str {
        self.path[1].as_str()
    }
}