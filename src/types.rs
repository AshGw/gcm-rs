use crate::constants::C_SIZE;
use crate::error::Error;
use anyhow::Result as AnyRes;

pub type Result<T> = AnyRes<T, Error>;

pub type Bytes = [u8];
pub type BlockBytes = [u8; C_SIZE];
pub type Nonce = Bytes;
pub type Key = Bytes;
pub type CTRInitializer = u32;
