use rand::rngs::OsRng;
use rand::RngCore;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn fill(dst: &mut [u8]) {
    OsRng.fill_bytes(dst);
}
