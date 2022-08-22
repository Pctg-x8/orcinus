use futures_util::{future::LocalBoxFuture, FutureExt};
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    protos::{ClientPacketSendExt, GenericOKErrPacket, OKPacket},
    CommunicationError,
};

pub fn gen_secure_password_auth_response(password: &str, salt1: &[u8], salt2: &[u8]) -> Vec<u8> {
    let password_sha1 = digest(&SHA1, password.as_bytes());
    let mut concat_data = Vec::with_capacity(40);
    concat_data.extend(salt1.iter().chain(salt2.iter()).take(20));
    concat_data.extend(digest(&SHA1, password_sha1.as_ref()).as_ref());
    let concat_data_sha1 = digest(&SHA1, &concat_data);

    password_sha1
        .as_ref()
        .into_iter()
        .zip(concat_data_sha1.as_ref().into_iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

pub struct Native41<'s> {
    pub server_data_1: &'s [u8],
    pub server_data_2: &'s [u8],
}
impl<'s> super::Authentication<'s> for Native41<'_> {
    const NAME: &'static str = "mysql_native_password";
    type OperationF = LocalBoxFuture<'s, Result<(OKPacket, u8), CommunicationError>>;

    fn run(
        &'s self,
        stream: &'s mut (impl AsyncReadExt + AsyncWriteExt + Unpin + ?Sized),
        con_info: &'s super::ConnectionInfo,
        first_sequence_id: u8,
    ) -> Self::OperationF {
        async move {
            let payload = gen_secure_password_auth_response(
                con_info.password,
                self.server_data_1,
                self.server_data_2,
            );

            con_info
                .make_handshake_response(&payload, Some(Self::NAME))
                .write_packet(stream, first_sequence_id)
                .await?;
            stream.flush().await?;
            let (resp, sequence_id) =
                GenericOKErrPacket::read_packet(stream, con_info.client_capabilities)
                    .await?
                    .into_result()?;

            Ok((resp, sequence_id))
        }
        .boxed_local()
    }

    fn run_sync(
        &self,
        stream: &mut (impl std::io::Read + std::io::Write + ?Sized),
        con_info: &super::ConnectionInfo,
        first_sequence_id: u8,
    ) -> Result<(OKPacket, u8), CommunicationError> {
        let payload = gen_secure_password_auth_response(
            con_info.password,
            self.server_data_1,
            self.server_data_2,
        );

        con_info
            .make_handshake_response(&payload, Some(Self::NAME))
            .write_packet_sync(stream, first_sequence_id)?;
        stream.flush()?;
        let (resp, sequence_id) =
            GenericOKErrPacket::read_packet_sync(stream, con_info.client_capabilities)?
                .into_result()?;

        Ok((resp, sequence_id))
    }
}
