
#[derive(Debug)]
pub enum PassmanError {
    NoVerb,
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
    Unexpected(Box<dyn std::error::Error>)
}

pub type PassmanResult<T> = Result<T, PassmanError>;

impl std::fmt::Display for PassmanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::NoVerb => "no verb specified!".to_owned(),
            Self::InvalidVerb(verb) => format!("invalid verb '{}'", verb),
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
            Self::Unexpected(err) => format!("unexpected error - {}", err),
            _ => "unknown error".to_owned()
        })
    }
}

pub trait IntoPassmanResult<T> {
    fn into_passman_result(self) -> PassmanResult<T>;
}

impl<TResult, TError> IntoPassmanResult<TResult> for Result<TResult, TError>
    where TError: std::error::Error + 'static {
    fn into_passman_result(self) -> PassmanResult<TResult> {
        self.map_err(|err| PassmanError::Unexpected(Box::new(err)))
    }
}