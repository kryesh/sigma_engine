//! Example demonstrating base64offset and windash modifiers
//!
//! This example shows how the new base64offset and windash modifiers work
//! to catch obfuscated commands in various encodings.

use sigma_engine::{LogEvent, LogProcessor, LogSource, SigmaCollection, SigmaDocument};
use std::collections::HashMap;

fn main() {
    println!("=== Sigma Modifier Demonstration ===\n");

    // Example 1: base64offset modifier
    println!("Example 1: base64offset modifier");
    println!("-----------------------------------");
    
    let base64offset_yaml = r#"
title: PowerShell Base64 Encoded Command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|base64offset|contains: 'Invoke-WebRequest'
    condition: selection
level: high
"#;

    let collection = SigmaCollection::from_yaml(base64offset_yaml).unwrap();
    let rule = match &collection.documents[0] {
        SigmaDocument::Rule(r) => r.clone(),
        _ => panic!("Expected rule"),
    };

    let processor = LogProcessor::new(vec![rule]).unwrap();
    let (event_tx, detection_rx) = processor.start();

    let log_source = LogSource {
        category: Some("process_creation".to_string()),
        product: Some("windows".to_string()),
        service: None,
        custom: HashMap::new(),
    };

    // Send events with different base64 offset encodings
    // These would catch base64-encoded "Invoke-WebRequest" at different byte alignments
    let events = vec![
        r#"{"CommandLine": "powershell.exe -enc SW52b2tlLVdlYlJlcXVlc3Q="}"#, // offset 0
        r#"{"CommandLine": "powershell.exe -enc udm9rZS1XZWJSZXF1ZXN0"}"#,     // offset 1 variant
    ];

    for (i, event_json) in events.iter().enumerate() {
        let event = LogEvent::from_json(log_source.clone(), event_json).unwrap();
        event_tx.send(event).unwrap();
        println!("  Sent event {}: {}", i + 1, event_json);
    }

    drop(event_tx);

    let mut detection_count = 0;
    while let Ok(detection) = detection_rx.recv() {
        detection_count += 1;
        println!("  ✓ Matched: {}", detection.rule.title);
    }
    println!("  Total detections: {}\n", detection_count);

    // Example 2: windash modifier
    println!("Example 2: windash modifier");
    println!("----------------------------");
    
    let windash_yaml = r#"
title: Certificate Store Manipulation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|windash|contains: '-addstore'
    condition: selection
level: medium
"#;

    let collection = SigmaCollection::from_yaml(windash_yaml).unwrap();
    let rule = match &collection.documents[0] {
        SigmaDocument::Rule(r) => r.clone(),
        _ => panic!("Expected rule"),
    };

    let processor = LogProcessor::new(vec![rule]).unwrap();
    let (event_tx, detection_rx) = processor.start();

    // Send events with different dash character variants
    let events = vec![
        r#"{"CommandLine": "certutil.exe -addstore Root cert.cer"}"#,  // hyphen
        r#"{"CommandLine": "certutil.exe /addstore Root cert.cer"}"#,  // forward slash
        r#"{"CommandLine": "certutil.exe –addstore Root cert.cer"}"#,  // en-dash
        r#"{"CommandLine": "certutil.exe —addstore Root cert.cer"}"#,  // em-dash
    ];

    for (i, event_json) in events.iter().enumerate() {
        let event = LogEvent::from_json(log_source.clone(), event_json).unwrap();
        event_tx.send(event).unwrap();
        println!("  Sent event {}: {}", i + 1, event_json);
    }

    drop(event_tx);

    let mut detection_count = 0;
    while let Ok(detection) = detection_rx.recv() {
        detection_count += 1;
        println!("  ✓ Matched: {}", detection.rule.title);
    }
    println!("  Total detections: {}\n", detection_count);

    println!("=== Demo completed successfully! ===");
}
