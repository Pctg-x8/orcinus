pub struct SHA256<'k> {
    pub server_public_keyfile: Option<&'k [u8]>,
    pub scramble_buffer_1: &'k [u8],
    pub scramble_buffer_2: &'k [u8],
}
impl super::Authentication for SHA256<'_> {
    const NAME: &'static str = "sha256_password";

    fn generate(&self, password: &str) -> Vec<u8> {
        if password.is_empty() {
            return Vec::new();
        }

        match self.server_public_keyfile {
            // public key retrieval is needed
            None => vec![0x01],
            Some(k) => {
                let scrambled_password = password
                    .bytes()
                    .zip(
                        self.scramble_buffer_1
                            .iter()
                            .chain(self.scramble_buffer_2.iter()),
                    )
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<_>>();
                let key = ring::signature::RsaKeyPair::from_pkcs8(k).expect("invalid keyfile");
                let mut signature = vec![0u8; key.public_modulus_len()];
                key.sign(
                    &ring::signature::RSA_PKCS1_SHA256,
                    &ring::rand::SystemRandom::new(),
                    &scrambled_password,
                    &mut signature,
                )
                .expect("Failed to sign password");
                signature
            }
        }
    }
}

#[repr(transparent)]
pub struct CachedSHA256<'k>(pub SHA256<'k>);
impl super::Authentication for CachedSHA256<'_> {
    const NAME: &'static str = "caching_sha2_password";

    fn generate(&self, password: &str) -> Vec<u8> {
        self.0.generate(password)
    }
}
