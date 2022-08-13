use futures_util::{future::LocalBoxFuture, FutureExt};
use tokio::io::AsyncWriteExt;

use crate::{
    protos::{GenericOKErrPacket, OKPacket},
    CommunicationError, PacketReader,
};

pub struct ClearText;
impl<'s> super::Authentication<'s> for ClearText {
    const NAME: &'static str = "mysql_clear_password";
    type OperationF = LocalBoxFuture<'s, Result<(OKPacket, u8), CommunicationError>>;

    fn run(
        &'s self,
        stream: &'s mut (impl PacketReader + AsyncWriteExt + Unpin),
        con_info: &'s super::ConnectionInfo,
        first_sequence_id: u8,
    ) -> Self::OperationF {
        async move {
            let mut buf = Vec::with_capacity(con_info.password.as_bytes().len() + 1);
            buf.extend(con_info.password.bytes());
            buf.push(0);

            con_info
                .send_handshake_response(stream, &buf, Some(Self::NAME), first_sequence_id)
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
}
