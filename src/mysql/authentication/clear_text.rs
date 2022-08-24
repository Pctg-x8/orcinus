use std::io::{Read, Write};

use futures_util::{future::BoxFuture, FutureExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    protos::{
        write_packet, write_packet_sync, AsyncReceivePacket, GenericOKErrPacket, OKPacket,
        ReceivePacket,
    },
    CommunicationError,
};

pub struct ClearText;
impl super::Authentication for ClearText {
    const NAME: &'static str = "mysql_clear_password";

    fn run_sync(
        &self,
        mut stream: impl Read + Write,
        con_info: &super::ConnectionInfo,
        first_sequence_id: u8,
    ) -> Result<(OKPacket, u8), CommunicationError> {
        let mut buf = Vec::with_capacity(con_info.password.as_bytes().len() + 1);
        buf.extend(con_info.password.bytes());
        buf.push(0);

        write_packet_sync(
            &mut stream,
            con_info.make_handshake_response(&buf, Some(Self::NAME)),
            first_sequence_id,
        )?;
        stream.flush()?;
        let (resp, sequence_id) =
            GenericOKErrPacket::read_packet(stream, con_info.client_capabilities)?.into_result()?;

        Ok((resp, sequence_id))
    }
}
impl<'s, S> super::AsyncAuthentication<'s, S> for ClearText
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 's,
{
    type OperationF = BoxFuture<'s, Result<(OKPacket, u8), CommunicationError>>;

    fn run(
        &'s self,
        mut stream: S,
        con_info: &'s super::ConnectionInfo,
        first_sequence_id: u8,
    ) -> Self::OperationF {
        async move {
            let mut buf = Vec::with_capacity(con_info.password.as_bytes().len() + 1);
            buf.extend(con_info.password.bytes());
            buf.push(0);

            write_packet(
                &mut stream,
                con_info.make_handshake_response(&buf, Some(<Self as super::Authentication>::NAME)),
                first_sequence_id,
            )
            .await?;
            stream.flush().await?;
            let (resp, sequence_id) =
                GenericOKErrPacket::read_packet_async(stream, con_info.client_capabilities)
                    .await?
                    .into_result()?;

            Ok((resp, sequence_id))
        }
        .boxed()
    }
}
