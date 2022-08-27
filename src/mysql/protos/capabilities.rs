#[repr(transparent)]
#[derive(Clone, Copy)]
/// Client/Server Capability Flags: https://dev.mysql.com/doc/internals/en/capability-flags.html#packet-Protocol::CapabilityFlags
pub struct CapabilityFlags(pub u32);
impl CapabilityFlags {
    /// Creates empty flags
    pub const fn new() -> Self {
        Self(0)
    }

    /// Transform 16-bit value as lower bits of flags
    pub const fn from_lower_bits(lb: u16) -> Self {
        Self(lb as _)
    }

    /// Combines passed 16-bit value as upper bits of flags
    pub const fn combine_upper_bytes(self, ub: u16) -> Self {
        Self(self.0 & 0xffff | ((ub as u32) << 16))
    }

    /// Use the improved version of Old Password Authentication.
    pub const fn use_long_password(&self) -> bool {
        (self.0 & 0x0000_0001) != 0
    }
    /// Sets to use the improved version of Old Password Authentication.
    pub fn set_use_long_password(&mut self) -> &mut Self {
        self.0 |= 0x0000_0001;
        self
    }

    /// Send found rows instead of affected rows in EOF Packet
    pub const fn send_found_rows_at_eof(&self) -> bool {
        (self.0 & 0x0000_0002) != 0
    }

    /// Handshake Response packet contains database name
    pub const fn support_connect_with_db(&self) -> bool {
        (self.0 & 0x0000_0008) != 0
    }
    /// Set to Handshake Response packet contains database name
    pub fn set_connect_with_db(&mut self) -> &mut Self {
        self.0 |= 0x0000_0008;
        self
    }
    /// Set to Handshake Response packet does not contains database name
    pub fn clear_connect_with_db(&mut self) -> &mut Self {
        self.0 &= !0x0000_0008;
        self
    }

    /// Server does not permit `database.table.column` format
    pub const fn no_schema(&self) -> bool {
        (self.0 & 0x0000_0010) != 0
    }

    /// Client/Server supports Protocol 4.1
    pub const fn support_41_protocol(&self) -> bool {
        (self.0 & 0x0000_0200) != 0
    }
    /// Set Protocol 4.1 support
    pub fn set_support_41_protocol(&mut self) -> &mut Self {
        self.0 |= 0x0000_0200;
        self
    }

    /// Server can be connected with SSL/Client will connect with SSL
    pub const fn support_ssl(&self) -> bool {
        (self.0 & 0x0000_0800) != 0
    }
    /// Set to client will connect with SSL
    pub fn set_support_ssl(&mut self) -> &mut Self {
        self.0 |= 0x0000_0800;
        self
    }

    /// Expects client to receive status flags in EOF Packet
    pub const fn support_transaction(&self) -> bool {
        (self.0 & 0x0000_2000) != 0
    }

    /// Supports Native41 Authentication Method
    pub const fn support_secure_connection(&self) -> bool {
        (self.0 & 0x0000_8000) != 0
    }
    /// Set to support Native41 Authentication Method
    pub fn set_support_secure_connection(&mut self) -> &mut Self {
        self.0 |= 0x0000_8000;
        self
    }

    /// Supports authentication plugin
    pub const fn support_plugin_auth(&self) -> bool {
        (self.0 & 0x0008_0000) != 0
    }
    /// Set to support authentication plugin
    pub fn set_client_plugin_auth(&mut self) -> &mut Self {
        self.0 |= 0x0008_0000;
        self
    }
    /// Set to do not support authentication plugin
    pub fn clear_plugin_auth(&mut self) -> &mut Self {
        self.0 &= !0x0008_0000;
        self
    }

    /// Connection Attributes included in Handshake Response packet
    pub const fn support_connect_attrs(&self) -> bool {
        (self.0 & 0x0010_0000) != 0
    }
    /// Set to include connection attributes in Handshake Response packet
    pub fn set_client_connect_attrs(&mut self) -> &mut Self {
        self.0 |= 0x0010_0000;
        self
    }
    /// Set to do not include connection attributes in Handshake Response packet
    pub fn clear_client_connect_attrs(&mut self) -> &mut Self {
        self.0 &= !0x0010_0000;
        self
    }

    /// Length of plugin auth response will be sent by Length-encoded integer
    pub const fn support_plugin_auth_lenenc_client_data(&self) -> bool {
        (self.0 & 0x0020_0000) != 0
    }
    /// Set to send Length of plugin auth response as Length-encoded integer
    pub fn set_support_plugin_auth_lenenc_client_data(&mut self) -> &mut Self {
        self.0 |= 0x0020_0000;
        self
    }

    /// Supports to receive session state changes after a OK Packet
    pub const fn support_session_track(&self) -> bool {
        (self.0 & 0x0080_0000) != 0
    }

    /// Supports deprecated EOF Packets after Text resultset rows
    pub const fn support_deprecate_eof(&self) -> bool {
        (self.0 & 0x0100_0000) != 0
    }
    /// Set to support deprecated EOF Packets after Text resultset rows
    pub fn set_support_deprecate_eof(&mut self) -> &mut Self {
        self.0 |= 0x0100_0000;
        self
    }
}
impl std::fmt::Debug for CapabilityFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:032b}", self.0)
    }
}
impl std::ops::BitAnd for CapabilityFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}
impl std::ops::BitOr for CapabilityFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
