pub struct QuitCommand;
impl super::ClientPacket for QuitCommand {
    fn serialize_payload(&self) -> Vec<u8> {
        vec![0x01]
    }
}
