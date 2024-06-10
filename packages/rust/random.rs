use getrandom::getrandom;

fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    getrandom(&mut bytes).expect("This should never happen");
    bytes
}

pub fn gen_key() -> Vec<u8> {
    random_bytes(32)
}

pub fn gen_nonce() -> Vec<u8> {
    random_bytes(12)
}
