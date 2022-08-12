#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct StatusFlags(pub u16);
impl StatusFlags {
    pub const fn new() -> Self {
        Self(0)
    }

    pub fn has_state_changed(&self) -> bool {
        (self.0 & 0x4000) != 0
    }
}
impl std::fmt::Debug for StatusFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016b}", self.0)
    }
}
