use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

pub fn generate_request_id(n: usize) -> String {
    let mut bytes = vec![0u8; n / 2];
    rand::rng().fill_bytes(&mut bytes);
    let hex_str = hex::encode(bytes);
    hex_str[..n].to_string()
}

pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
