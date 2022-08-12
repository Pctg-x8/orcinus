use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1};

pub struct Native41<'s> {
    pub server_data_1: &'s [u8],
    pub server_data_2: &'s [u8],
}
impl super::Authentication for Native41<'_> {
    const NAME: &'static str = "mysql_native_password";

    fn generate(&self, password: &str) -> Vec<u8> {
        let password_sha1 = digest(&SHA1, password.as_bytes());
        let mut concat_data = Vec::with_capacity(40);
        concat_data.extend(self.server_data_1);
        concat_data.extend(&self.server_data_2[..(20 - self.server_data_1.len())]);
        concat_data.extend(digest(&SHA1, password_sha1.as_ref()).as_ref());
        let concat_data_sha1 = digest(&SHA1, &concat_data);

        password_sha1
            .as_ref()
            .into_iter()
            .zip(concat_data_sha1.as_ref().into_iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }
}
