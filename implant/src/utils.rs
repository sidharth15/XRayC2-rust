use crate::model::AWSTraceSegment; // Import our model
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::{rngs::ThreadRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

// Use reqwest types for Client, Request, and all Headers
use reqwest::blocking::{Client, Request};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, HOST};

// --- Helper functions (Ported from Go) ---

fn thread_rng() -> ThreadRng {
    rand::thread_rng()
}

// This is a 1:1 port of your Go `generateRequestId`
pub fn generate_request_id(n: usize) -> String {
    let mut bytes = vec![0u8; n / 2];
    thread_rng().fill_bytes(&mut bytes);
    let hex_str = hex::encode(bytes);
    hex_str[..n].to_string()
}

// This is a 1:1 port of your Go `computeHMACSHA256`
pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// --- Constants (from Go logic) ---
const REGION: &str = "eu-west-1"; // Or your desired region
const SERVICE: &str = "xray";

//
// --- CORE FIX: Ported sign_aws_request ---
//
// This function is now a 1:1 port of the Go `signAWSRequest`.
// It operates *directly* on a mutable `reqwest::blocking::Request`.
//
pub fn sign_aws_request(
    request: &mut Request,
    body: &[u8],
    access_key: &str,
    secret_key: &str,
) -> Result<(), Box<dyn Error>> {
    let now = Utc::now();
    let datestamp = now.format("%Y%m%d").to_string();
    let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();

    // Create payload hash
    let payload_hash = {
        let mut hasher = Sha256::new();
        hasher.update(body);
        hex::encode(hasher.finalize())
    };

    // Get host from the request URL
    let host = request
        .url()
        .host_str()
        .unwrap_or_default()
        .to_string();

    // Set required headers on the request
    let headers = request.headers_mut();
    headers.insert(HOST, HeaderValue::from_str(&host)?);
    headers.insert("X-Amz-Date", HeaderValue::from_str(&timestamp)?);
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-amz-json-1.1"),
    );

    // Create canonical request
    let canonical_headers = format!(
        "content-type:{}\nhost:{}\nx-amz-date:{}\n",
        headers.get(CONTENT_TYPE).unwrap().to_str()?,
        headers.get(HOST).unwrap().to_str()?,
        headers.get("X-Amz-Date").unwrap().to_str()?
    );
    let signed_headers = "content-type;host;x-amz-date";

    let canonical_request = format!(
        "{method}\n{path}\n{query}\n{headers}\n{signed_headers}\n{payload_hash}",
        method = request.method().as_str(),
        path = request.url().path(),
        query = request.url().query().unwrap_or(""),
        headers = canonical_headers,
    );

    // Create string to sign
    let algorithm = "AWS4-HMAC-SHA256";
    let credential_scope = format!("{}/{}/{}/aws4_request", datestamp, REGION, SERVICE);

    let canonical_request_hash = {
        let mut h = Sha256::new();
        h.update(canonical_request.as_bytes());
        hex::encode(h.finalize())
    };

    let string_to_sign =
        format!("{algorithm}\n{timestamp}\n{credential_scope}\n{canonical_request_hash}");

    // Calculate signature
    let k_date = compute_hmac_sha256(
        format!("AWS4{}", secret_key).as_bytes(),
        datestamp.as_bytes(),
    );
    let k_region = compute_hmac_sha256(&k_date, REGION.as_bytes());
    let k_service = compute_hmac_sha256(&k_region, SERVICE.as_bytes());
    let k_signing = compute_hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(compute_hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    // Add authorization header
    let authorization = format!(
        "{alg} Credential={access}/{scope}, SignedHeaders={signed}, Signature={sig}",
        alg = algorithm,
        access = access_key,
        scope = credential_scope,
        signed = signed_headers,
        sig = signature
    );

    request
        .headers_mut()
        .insert(AUTHORIZATION, HeaderValue::from_str(&authorization)?);

    Ok(())
}

//
// --- CORE FIX: Ported publish_metrics ---
//
// This is now a 1:1 port of the Go `publishMetrics`.
// It builds a `reqwest::Request`, signs it, and sends it.
//
pub fn publish_metrics(
    instance_id: &str,
    response: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<(), Box<dyn Error>> {
    // Build the trace segment
    let now = Utc::now();
    let start = now.timestamp() as f64;
    let end = start + 0.1; // Matches Go logic

    let mut annotations: HashMap<String, String> = HashMap::from([
        ("service_type".into(), "health_check".into()),
        ("instance_id".into(), instance_id.to_string()),
        ("platform".into(), std::env::consts::OS.into()),
    ]);

    if !response.is_empty() {
        annotations.insert(
            "execution_result".into(),
            BASE64.encode(response.as_bytes()),
        );
    }

    let segment = AWSTraceSegment {
        name: "aws-application-monitoring".into(),
        id: generate_request_id(16),
        trace_id: format!("1-{:x}-{}", now.timestamp(), generate_request_id(24)),
        start_time: start,
        end_time: end,
        annotations,
    };

    // Serialize the segment
    let segment_json = serde_json::to_string(&segment)?;

    // Wrap as AWS payload
    let payload = serde_json::json!({
        "TraceSegmentDocuments": [ segment_json ]
    });
    let body = serde_json::to_vec(&payload)?; // Get payload as bytes

    // Build URL
    let url = format!("https://xray.{REGION}.amazonaws.com/TraceSegments");

    // Create client
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // Create the Request object
    // We *must* clone the body because `build()` consumes it,
    // but `sign_aws_request` needs to read it to compute the hash.
    let mut req: Request = client.post(&url).body(body.clone()).build()?;

    // Sign the request (this mutates `req` and adds auth headers)
    sign_aws_request(&mut req, &body, access_key, secret_key)?;

    // Send the *signed* request
    let resp = client.execute(req)?;

    // Optional: Check for errors
    if !resp.status().is_success() {
        eprintln!("Error publishing metrics: {:?}", resp.text());
        return Err("Failed to publish metrics".into());
    }

    Ok(())
}