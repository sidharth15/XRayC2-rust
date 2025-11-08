use std::collections::HashMap;

mod model;
use model::AWSTraceSegment;

mod utils;
use utils::compute_hmac_sha256;
use utils::generate_request_id;

fn main() {
    let mut annotations = HashMap::new();
    annotations.insert("env".to_string(), "dev".to_string());
    annotations.insert("version".to_string(), "1.0".to_string());

    let segment = AWSTraceSegment {
        name: "example-segment".to_string(),
        id: "12345".to_string(),
        trace_id: "trace-abc-123".to_string(),
        start_time: 1000.0,
        end_time: 2000.0,
        annotations,
    };

    let id = generate_request_id(16);
    println!("{}", id);

    let key = b"my-secret-key";
    let data = b"hello world";

    let hmac = compute_hmac_sha256(key, data);

    println!("HMAC (hex): {}", hex::encode(hmac));

    println!("{}", serde_json::to_string_pretty(&segment).unwrap());
}
