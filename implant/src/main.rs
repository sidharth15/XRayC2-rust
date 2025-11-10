use std::env;

mod model;
mod utils;

// Main function now returns a Result to handle errors (like missing env vars)
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting metrics publisher...");

    // Read AWS credentials from environment variables
    // The Go code assumed these were global; in Rust, we load them.
    let access_key =
        env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID must be set");
    let secret_key =
        env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY must be set");

    // Call the ported function
    let instance_id = "rust-instance-001";
    let execution_result = "Test payload from Rust port";

    match utils::publish_metrics(instance_id, execution_result, &access_key, &secret_key) {
        Ok(()) => {
            println!("Successfully published metrics to AWS X-Ray.");
        }
        Err(e) => {
            eprintln!("Error publishing metrics: {}", e);
        }
    }

    Ok(())
}