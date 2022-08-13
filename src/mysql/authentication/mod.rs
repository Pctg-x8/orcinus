mod clear_text;
mod secure_password;
mod sha256;

use tokio::io::AsyncWriteExt;

use crate::protos::CapabilityFlags;
use crate::protos::ClientPacket;
use crate::protos::HandshakeResponse320;
use crate::protos::HandshakeResponse41;
use crate::protos::OKPacket;
use crate::CommunicationError;
use crate::PacketReader;

pub use self::clear_text::*;
pub use self::secure_password::*;
pub use self::sha256::*;

pub struct ConnectionInfo<'s> {
    pub client_capabilities: CapabilityFlags,
    pub max_packet_size: u32,
    pub character_set: u8,
    pub username: &'s str,
    pub password: &'s str,
    pub database: Option<&'s str>,
}
impl ConnectionInfo<'_> {
    pub async fn send_handshake_response(
        &self,
        stream: &mut (impl AsyncWriteExt + Unpin),
        auth_response: &[u8],
        auth_plugin_name: Option<&str>,
        sequence_id: u8,
    ) -> std::io::Result<()> {
        if self.client_capabilities.support_41_protocol() {
            HandshakeResponse41 {
                capability: self.client_capabilities,
                max_packet_size: self.max_packet_size,
                character_set: self.character_set,
                username: self.username,
                auth_response,
                database: self.database,
                auth_plugin_name,
                connect_attrs: Default::default(),
            }
            .write_packet(stream, sequence_id)
            .await
        } else {
            HandshakeResponse320 {
                capability: self.client_capabilities,
                max_packet_size: self.max_packet_size,
                username: self.username,
                auth_response,
                database: self.database,
            }
            .write_packet(stream, sequence_id)
            .await
        }
    }
}

pub trait Authentication<'s> {
    const NAME: &'static str;
    type OperationF: std::future::Future<Output = Result<(OKPacket, u8), CommunicationError>> + 's;

    fn run(
        &'s self,
        stream: &'s mut (impl PacketReader + AsyncWriteExt + Unpin),
        con_info: &'s ConnectionInfo,
        first_sequence_id: u8,
    ) -> Self::OperationF;
}
