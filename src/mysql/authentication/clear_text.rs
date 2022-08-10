pub struct ClearText;
impl super::Authentication for ClearText {
    const NAME: &'static str = "mysql_clear_password";

    fn generate(&self, password: &str) -> Vec<u8> {
        password.as_bytes().to_owned()
    }
}
