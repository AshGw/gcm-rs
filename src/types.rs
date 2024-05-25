use crate::error::Error;
use anyhow::Result as AnyRes;

pub type Result<T> = AnyRes<T, Error>;

pub type Bytes = [u8];
pub type Nonce = Bytes;
pub type Key = Bytes;
pub type CTRInitializer = u32;
