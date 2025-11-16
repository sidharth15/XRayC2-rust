use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct AWSTraceSegment {
    pub name: String,
    pub id: String,
    #[serde(rename = "trace_id")]
    pub trace_id: String,
    #[serde(rename = "start_time")]
    pub start_time: f64,
    #[serde(rename = "end_time")]
    pub end_time: f64,
    pub annotations: HashMap<String, String>,
}
