use std::io::{Read, Write};

use futures_util::{future::LocalBoxFuture, FutureExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    protos::{ClientPacketSendExt, GenericOKErrPacket, OKPacket},
    CommunicationError,
};

pub struct ClearText;
impl<'s> super::Authentication<'s> for ClearText {
    const NAME: &'static str = "mysql_clear_password";
    type OperationF = LocalBoxFuture<'s, Result<(OKPacket, u8), CommunicationError>>;

    fn run(
        &'s self,
        stream: &'s mut (impl AsyncReadExt + AsyncWriteExt + Unpin + ?Sized),
        con_info: &'s super::ConnectionInfo,
        first_sequence_id: u8,
    ) -> Self::OperationF {
        async move {
            let mut buf = Vec::with_capacity(con_info.password.as_bytes().len() + 1);
            buf.extend(con_info.password.bytes());
            buf.push(0);

            con_info
                .make_handshake_response(&buf, Some(Self::NAME))
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
        stream: &mut (impl Read + Write + ?Sized),
        con_info: &super::ConnectionInfo,
        first_sequence_id: u8,
    ) -> Result<(OKPacket, u8), CommunicationError> {
        let mut buf = Vec::with_capacity(con_info.password.as_bytes().len() + 1);
        buf.extend(con_info.password.bytes());
        buf.push(0);

        con_info
            .make_handshake_response(&buf, Some(Self::NAME))
            .write_packet_sync(stream, first_sequence_id)?;
        stream.flush()?;
        let (resp, sequence_id) =
            GenericOKErrPacket::read_packet_sync(stream, con_info.client_capabilities)?
                .into_result()?;

        Ok((resp, sequence_id))
    }
}
