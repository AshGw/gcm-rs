pub const BLOCK_SIZE: usize = 16;
pub const NONCE_SIZE: usize = BLOCK_SIZE - 4;
pub const TAG_SIZE: usize = BLOCK_SIZE;
pub const C_SIZE: usize = TAG_SIZE; // C for common size, ion mean none else
pub const ZEROED_BLOCK: [u8; C_SIZE] = [0u8; C_SIZE];
