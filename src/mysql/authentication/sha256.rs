use futures_util::{future::LocalBoxFuture, FutureExt};
use rsa::{pkcs8::DecodePublicKey, PaddingScheme, PublicKey, RsaPublicKey};
use sha2::Sha256;

use crate::{
    protos::{write_packet, AuthMoreData, AuthMoreDataResponse, GenericOKErrPacket, OKPacket},
    CommunicationError,
};

pub struct SHA256<'k> {
    pub server_spki_der: Option<&'k [u8]>,
    pub scramble_buffer_1: &'k [u8],
    pub scramble_buffer_2: &'k [u8],
}
impl<'s> super::Authentication<'s> for SHA256<'_> {
    const NAME: &'static str = "sha256_password";
    type OperationF = LocalBoxFuture<'s, Result<(OKPacket, u8), CommunicationError>>;

    fn run(
        &'s self,
        _stream: &'s mut (impl crate::PacketReader + tokio::io::AsyncWriteExt + Unpin),
        _con_info: &'s super::ConnectionInfo,
        _first_sequence_id: u8,
    ) -> Self::OperationF {
        todo!("sha256_password authentication")
    }
}

pub fn caching_sha2_gen_fast_auth_response(password: &str, salt1: &[u8], salt2: &[u8]) -> Vec<u8> {
    // xor(sha256(password), sha256(sha256(sha256(password)) + salt1 + salt2))
    // ref: https://dev.mysql.com/blog-archive/mysql-8-0-4-new-default-authentication-plugin-caching_sha2_password/

    let hashed_password = ring::digest::digest(&ring::digest::SHA256, password.as_bytes());
    let xor_target = ring::digest::digest(
        &ring::digest::SHA256,
        &ring::digest::digest(&ring::digest::SHA256, hashed_password.as_ref())
            .as_ref()
            .iter()
            .chain(salt1.iter())
            .chain(salt2.iter())
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

#[repr(transparent)]
pub struct CachedSHA256<'k>(pub SHA256<'k>);
impl<'s, 'k> super::Authentication<'s> for CachedSHA256<'k> {
    const NAME: &'static str = "caching_sha2_password";
    type OperationF = LocalBoxFuture<'s, Result<(OKPacket, u8), CommunicationError>>;

    fn run(
        &'s self,
        stream: &'s mut (impl crate::PacketReader + tokio::io::AsyncWriteExt + Unpin),
        con_info: &'s super::ConnectionInfo,
        first_sequence_id: u8,
    ) -> Self::OperationF {
        async move {
            if con_info.password.is_empty() {
                // empty password authentication

                con_info
                    .send_handshake_response(stream, &[], Some(Self::NAME), first_sequence_id)
                    .await?;
                stream.flush().await?;
                let (resp, sequence_id) =
                    GenericOKErrPacket::read_packet(stream, con_info.client_capabilities)
                        .await?
                        .into_result()?;

                return Ok((resp, sequence_id));
            }

            // first try: fast path for cached authentication history
            let auth_response = caching_sha2_gen_fast_auth_response(
                con_info.password,
                &self.0.scramble_buffer_1,
                &self.0.scramble_buffer_2[..self.0.scramble_buffer_2.len() - 1],
            );

            con_info
                .send_handshake_response(
                    stream,
                    &auth_response,
                    Some(Self::NAME),
                    first_sequence_id,
                )
                .await?;
            stream.flush().await?;
            let (AuthMoreData(resp), last_sequence_id) =
                AuthMoreDataResponse::read_packet(stream, con_info.client_capabilities)
                    .await?
                    .into_result()?;

            if resp == [0x03] {
                // ok
                return GenericOKErrPacket::read_packet(stream, con_info.client_capabilities)
                    .await?
                    .into_result()
                    .map_err(From::from);
            }
            assert_eq!(resp, [0x04]); // requires full authentication

            let (server_spki_der, last_sequence_id) = if let Some(spki_der) = self.0.server_spki_der
            {
                (spki_der, last_sequence_id)
            } else {
                todo!("public key retrieval");
            };

            let scrambled_password = con_info
                .password
                .bytes()
                .zip(
                    self.0
                        .scramble_buffer_1
                        .iter()
                        .chain(self.0.scramble_buffer_2.iter())
                        .cycle(),
                )
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>();
            let key =
                RsaPublicKey::from_public_key_der(server_spki_der).expect("invalid spki format");
            let padding = PaddingScheme::new_oaep::<Sha256>();
            let auth_response = key
                .encrypt(&mut rand::thread_rng(), padding, &scrambled_password)
                .expect("Failed to encrypt password");

            write_packet(stream, &auth_response, last_sequence_id + 1).await?;
            stream.flush().await?;
            GenericOKErrPacket::read_packet(stream, con_info.client_capabilities)
                .await?
                .into_result()
                .map_err(From::from)
        }
        .boxed_local()
    }
}
