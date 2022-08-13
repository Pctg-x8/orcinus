use rsa::{pkcs8::DecodePublicKey, PaddingScheme, PublicKey, RsaPublicKey};
use sha2::Sha256;

pub struct SHA256<'k> {
    pub server_spki_der: Option<&'k [u8]>,
    pub scramble_buffer_1: &'k [u8],
    pub scramble_buffer_2: &'k [u8],
}
impl super::Authentication for SHA256<'_> {
    const NAME: &'static str = "sha256_password";

    fn generate(&self, password: &str) -> Vec<u8> {
        if password.is_empty() {
            return Vec::new();
        }

        match self.server_spki_der {
            // fast path
            None => {
                let hashed_password =
                    ring::digest::digest(&ring::digest::SHA256, password.as_bytes());
                let xor_target = ring::digest::digest(
                    &ring::digest::SHA256,
                    &ring::digest::digest(&ring::digest::SHA256, hashed_password.as_ref())
                        .as_ref()
                        .iter()
                        .chain(self.scramble_buffer_1.iter())
                        .chain(self.scramble_buffer_2[..self.scramble_buffer_2.len() - 1].iter())
                        .copied()
                        .collect::<Vec<_>>(),
                );

                hashed_password
                    .as_ref()
                    .iter()
                    .zip(xor_target.as_ref().iter())
                    .map(|(&a, &b)| a ^ b)
                    .collect()
            }
            Some(k) => {
                let scrambled_password = password
                    .bytes()
                    .zip(
                        self.scramble_buffer_1
                            .iter()
                            .chain(self.scramble_buffer_2.iter())
                            .cycle(),
                    )
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<_>>();
                let key = RsaPublicKey::from_public_key_der(k).expect("invalid spki format");
                let padding = PaddingScheme::new_oaep::<Sha256>();
                key.encrypt(&mut rand::thread_rng(), padding, &scrambled_password)
                    .expect("Failed to encrypt password")
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
