mod clear_text;
mod secure_password;
mod sha256;

use std::io::Read;
use std::io::Write;

use crate::protos::CapabilityFlags;
use crate::protos::ClientPacket;
use crate::protos::HandshakeResponse320;
use crate::protos::HandshakeResponse41;
use crate::protos::OKPacket;
use crate::CommunicationError;

pub use self::clear_text::*;
pub use self::secure_password::*;
pub use self::sha256::*;

/// Detailed connection information to perform Authentication flow
pub struct ConnectionInfo<'s> {
    pub client_capabilities: CapabilityFlags,
    pub max_packet_size: u32,
    pub character_set: u8,
    pub username: &'s str,
    pub password: &'s str,
    pub database: Option<&'s str>,
}
impl ConnectionInfo<'_> {
    /// Make a handshake response with authentication responses
    #[inline]
    pub fn make_handshake_response<'s>(
        &'s self,
        auth_response: &'s [u8],
        auth_plugin_name: Option<&'s str>,
    ) -> Box<dyn ClientPacket + Sync + Send + 's> {
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

/// An Authentication Plugin implementation
pub trait Authentication {
    /// Authentication Plugin name
    const NAME: &'static str;

    /// Run Authentication flow
    fn run_sync(
        &self,
        stream: impl Read + Write,
        con_info: &ConnectionInfo,
        first_sequence_id: u8,
    ) -> Result<(OKPacket, u8), CommunicationError>;
}
/// Asynchronous implementation of Authentication flow
pub trait AsyncAuthentication<'s, S: 's + Send>: Authentication {
    /// Future type of Authentication flow
    type OperationF: std::future::Future<Output = Result<(OKPacket, u8), CommunicationError>>
        + Send
        + 's;

    /// Run Authentication flow
    fn run(
        &'s self,
        stream: S,
        con_info: &'s ConnectionInfo,
        first_sequence_id: u8,
    ) -> Self::OperationF;
}
