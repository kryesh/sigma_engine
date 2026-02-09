//! Example demonstrating the Sigma rule matching engine
//!
//! This example shows how to:
//! - Parse Sigma rules from YAML
//! - Create a multithreaded log processor
//! - Send events in different formats
//! - Receive and process detections

use sigma_engine::{LogEvent, LogProcessor, LogSource, SigmaCollection, SigmaDocument};
use std::collections::HashMap;

fn main() {
    println!("=== Sigma Rule Matching Engine Demo ===\n");

    // Parse some example Sigma rules
    let rules_yaml = r#"
---
title: Suspicious PowerShell Encoded Command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - '-enc'
            - '-nop'
    condition: selection
level: high
---
title: Suspicious Command Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;

    println!("Parsing Sigma rules...");
    let collection = SigmaCollection::from_yaml(rules_yaml).expect("Failed to parse rules");
    
    let mut rules = Vec::new();
    for doc in &collection.documents {
        if let SigmaDocument::Rule(rule) = doc {
            println!("  - Loaded: {} (Level: {:?})", rule.title, rule.level);
            rules.push(rule.clone());
        }
    }

    // Create the log processor
    println!("\nCreating log processor with {} worker threads...", num_cpus::get() - 1);
    let processor = LogProcessor::new(rules).expect("Failed to create processor");

    // Start processing
    let (event_tx, detection_rx) = processor.start();

    println!("\nSending test events...\n");

    // Create log source for process creation events
    let log_source = LogSource {
        category: Some("process_creation".to_string()),
        product: Some("windows".to_string()),
        service: None,
        custom: HashMap::new(),
    };

    // Example 1: JSON format event (should NOT match)
    println!("1. Sending JSON event (normal cmd.exe):");
    let json_event = r#"{"EventID": 4688, "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c dir"}"#;
    println!("   {}", json_event);
    let event = LogEvent::from_json(log_source.clone(), json_event).unwrap();
    event_tx.send(event).unwrap();

    // Example 2: JSON format event with whoami (should match "Suspicious Command Execution")
    println!("\n2. Sending JSON event (cmd.exe with whoami):");
    let json_event = r#"{"EventID": 4688, "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami"}"#;
    println!("   {}", json_event);
    let event = LogEvent::from_json(log_source.clone(), json_event).unwrap();
    event_tx.send(event).unwrap();

    // Example 3: Field="Value" format (should match "Suspicious PowerShell Encoded Command")
    println!("\n3. Sending Field=Value event (PowerShell with -enc):");
    let field_value_event = r#"EventID="4688" Image="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" CommandLine="powershell.exe -enc QQBCAEMARABFAA== -nop""#;
    println!("   {}", field_value_event);
    let event = LogEvent::from_field_value_format(log_source.clone(), field_value_event);
    event_tx.send(event).unwrap();

    // Example 4: Plain text (with whoami, should match)
    println!("\n4. Sending plain text event (PowerShell with whoami):");
    let plain_event = "powershell.exe whoami".to_string();
    println!("   {}", plain_event);
    let event = LogEvent::from_plain(log_source.clone(), plain_event);
    event_tx.send(event).unwrap();

    // Drop sender to signal completion
    drop(event_tx);

    // Receive and display detections
    println!("\n=== Detections ===\n");
    let mut detection_count = 0;
    while let Ok(detection) = detection_rx.recv() {
        detection_count += 1;
        println!("🚨 ALERT #{}", detection_count);
        println!("   Rule: {}", detection.rule.title);
        println!("   Level: {:?}", detection.rule.level);
        
        if let Some(raw) = &detection.event.raw {
            println!("   Event: {}", raw);
        } else {
            println!("   Event fields: {:?}", detection.event.data);
        }
        println!();
    }

    println!("=== Summary ===");
    println!("Total detections: {}", detection_count);
    println!("Demo completed successfully!");
}
