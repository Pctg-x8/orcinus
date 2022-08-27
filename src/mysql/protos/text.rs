/// Tells to server to close the connection: https://dev.mysql.com/doc/internals/en/com-quit.html
pub struct QuitCommand;
impl super::ClientPacket for QuitCommand {
    fn serialize_payload(&self) -> Vec<u8> {
        vec![0x01]
    }
}

mod query;
pub use self::query::*;
