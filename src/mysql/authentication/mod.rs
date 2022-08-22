mod clear_text;
mod secure_password;
mod sha256;

use std::io::Read;
use std::io::Write;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::protos::CapabilityFlags;
use crate::protos::ClientPacket;
use crate::protos::HandshakeResponse320;
use crate::protos::HandshakeResponse41;
use crate::protos::OKPacket;
use crate::CommunicationError;

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
    #[inline]
    pub fn make_handshake_response<'s>(
        &'s self,
        auth_response: &'s [u8],
        auth_plugin_name: Option<&'s str>,
    ) -> Box<dyn ClientPacket + 's> {
        if self.client_capabilities.support_41_protocol() {
            Box::new(HandshakeResponse41 {
                capability: self.client_capabilities,
                max_packet_size: self.max_packet_size,
                character_set: self.character_set,
                username: self.username,
                auth_response,
                database: self.database,
                auth_plugin_name,
                connect_attrs: Default::default(),
            })
        } else {
            Box::new(HandshakeResponse320 {
                capability: self.client_capabilities,
                max_packet_size: self.max_packet_size,
                username: self.username,
                auth_response,
                database: self.database,
            })
        }
    }
}

pub trait Authentication<'s> {
    const NAME: &'static str;
    type OperationF: std::future::Future<Output = Result<(OKPacket, u8), CommunicationError>> + 's;

    fn run(
        &'s self,
        stream: &'s mut (impl AsyncRead + AsyncWrite + Unpin + ?Sized),
        con_info: &'s ConnectionInfo,
        first_sequence_id: u8,
    ) -> Self::OperationF;

    fn run_sync(
        &self,
        stream: &mut (impl Read + Write + ?Sized),
        con_info: &ConnectionInfo,
        first_sequence_id: u8,
    ) -> Result<(OKPacket, u8), CommunicationError>;
}
