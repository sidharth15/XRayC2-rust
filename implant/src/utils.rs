use chrono::Utc;
use hmac::{Hmac, Mac};
use http::{
    Request,
    header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderName, HeaderValue},
};
use rand::RngCore;
use sha2::{Digest, Sha256};

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

pub fn sign_aws_request<B>(
    request: &mut Request<B>,
    body: &[u8],
    region: &str,
    service: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Timestamps (UTC)
    let now = Utc::now();
    let datestamp = now.format("%Y%m%d").to_string();
    let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();

    // Payload hash
    let payload_hash = {
        let mut hasher = Sha256::new();
        hasher.update(body);
        hex::encode(hasher.finalize())
    };

    // Take an owned host string to avoid borrow conflicts before mutating headers
    let host = request.uri().host().unwrap_or_default().to_string();

    // Set required headers
    let x_amz_date = HeaderName::from_static("x-amz-date");
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(&host)?);
    request.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-amz-json-1.1"),
    );
    request
        .headers_mut()
        .insert(x_amz_date.clone(), HeaderValue::from_str(&timestamp)?);

    // Canonical request pieces
    let method = request.method().as_str();
    let path = request.uri().path();
    let query = request.uri().query().unwrap_or("");

    let canonical_headers = format!(
        "content-type:{}\nhost:{}\nx-amz-date:{}\n",
        request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/x-amz-json-1.1"),
        host,
        timestamp
    );
    let signed_headers = "content-type;host;x-amz-date";

    let canonical_request = format!(
        "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
    );

    // String to sign
    let algorithm = "AWS4-HMAC-SHA256";
    let credential_scope = format!("{}/{}/{}/aws4_request", datestamp, region, service);

    let canonical_request_hash = {
        let mut h = Sha256::new();
        h.update(canonical_request.as_bytes());
        hex::encode(h.finalize())
    };

    let string_to_sign =
        format!("{algorithm}\n{timestamp}\n{credential_scope}\n{canonical_request_hash}");

    // Derive signing key
    let k_date = compute_hmac_sha256(
        format!("AWS4{}", secret_key).as_bytes(),
        datestamp.as_bytes(),
    );
    let k_region = compute_hmac_sha256(&k_date, region.as_bytes());
    let k_service = compute_hmac_sha256(&k_region, service.as_bytes());
    let k_signing = compute_hmac_sha256(&k_service, b"aws4_request");

    // Signature
    let signature = hex::encode(compute_hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    // Authorization header
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
