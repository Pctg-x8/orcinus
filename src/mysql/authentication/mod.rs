mod clear_text;
mod secure_password;
mod sha256;

pub use self::clear_text::*;
pub use self::secure_password::*;
pub use self::sha256::*;

pub trait Authentication {
    const NAME: &'static str;

    fn generate(&self, password: &str) -> Vec<u8>;
}
