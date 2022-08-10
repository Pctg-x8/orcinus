use super::super::PacketReader;


/// https://dev.mysql.com/doc/internals/en/capability-flags.html#packet-Protocol::CapabilityFlags
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct CapabilityFlags(pub u32);
impl CapabilityFlags {
    pub const fn new() -> Self {
        Self(0)
    }

    pub async fn read_lower_bits(reader: &mut (impl PacketReader + Unpin)) -> std::io::Result<Self> {
        reader.read_u16_le().await.map(|x| Self(x as _))
    }

    pub async fn additional_read_upper_bits(self, reader: &mut (impl PacketReader + Unpin)) -> std::io::Result<Self> {
        reader.read_u16_le().await.map(|x| Self((x as u32) << 16 | self.0))
    }

    pub fn use_long_password(&self) -> bool {
        (self.0 & 0x0000_0001) != 0
    }

    pub fn send_found_rows_at_eof(&self) -> bool {
        (self.0 & 0x0000_0002) != 0
    }

    pub fn support_longer_flags(&self) -> bool {
        (self.0 & 0x0000_0004) != 0
    }

    pub fn support_connect_with_db(&self) -> bool {
        (self.0 & 0x0000_0008) != 0
    }
    pub fn set_support_connect_with_db(&mut self) -> &mut Self {
        self.0 |= 0x0000_0008;
        self
    }

    pub fn no_schema(&self) -> bool {
        (self.0 & 0x0000_0010) != 0
    }

    pub fn support_41_protocol(&self) -> bool {
        (self.0 & 0x0000_0200) != 0
    }
    pub fn set_support_41_protocol(&mut self) -> &mut Self {
        self.0 |= 0x0000_0200;
        self
    }

    pub fn support_secure_connection(&self) -> bool {
        (self.0 & 0x0000_8000) != 0
    }
    pub fn set_support_secure_connection(&mut self) -> &mut Self {
        self.0 |= 0x0000_8000;
        self
    }

    pub fn support_plugin_auth(&self) -> bool {
        (self.0 & 0x0008_0000) != 0
    }
    pub fn set_support_plugin_auth(&mut self) -> &mut Self {
        self.0 |= 0x0008_0000;
        self
    }

    pub fn support_connect_attrs(&self) -> bool {
        (self.0 & 0x0010_0000) != 0
    }
    pub fn set_support_connect_attrs(&mut self) -> &mut Self {
        self.0 |= 0x0010_0000;
        self
    }

    pub fn support_plugin_auth_lenenc_client_data(&self) -> bool {
        (self.0 & 0x0020_0000) != 0
    }
    pub fn set_support_plugin_auth_lenenc_client_data(&mut self) -> &mut Self {
        self.0 |= 0x0020_0000;
        self
    }
}