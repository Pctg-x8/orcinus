#[repr(transparent)]
#[derive(Clone, Copy)]
/// Server Status Flags: https://dev.mysql.com/doc/internals/en/status-flags.html#packet-Protocol::StatusFlags
pub struct StatusFlags(pub u16);
impl StatusFlags {
    /// Creates empty flags
    pub const fn new() -> Self {
        Self(0)
    }

    /// More resultset exists after EOF/OK Packet
    pub fn more_result_exists(&self) -> bool {
        (self.0 & 0x0008) != 0
    }

    /// Server state has changed
    pub fn has_state_changed(&self) -> bool {
        (self.0 & 0x4000) != 0
    }
}
impl std::fmt::Debug for StatusFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016b}", self.0)
    }
}
impl Default for StatusFlags {
    fn default() -> Self {
        Self::new()
    }
}
