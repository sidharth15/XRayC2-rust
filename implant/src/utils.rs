use rand::RngCore;

pub fn generate_request_id(n: usize) -> String {
    let mut bytes = vec![0u8; n / 2];
    rand::rng().fill_bytes(&mut bytes);
    let hex_str = hex::encode(bytes);
    hex_str[..n].to_string()
}

