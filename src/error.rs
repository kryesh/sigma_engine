//! Error types for the Sigma engine.

use thiserror::Error;

/// All errors that can occur during Sigma rule parsing.
#[derive(Debug, Error)]
pub enum Error {
    /// YAML deserialization error.
    #[error("YAML parsing error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// Error while parsing a condition expression.
    #[error("Condition parsing error: {0}")]
    Condition(String),

    /// A required field is missing from the YAML document.
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// A field has an invalid or unexpected value.
    #[error("Invalid value for field '{field}': {message}")]
    InvalidValue { field: String, message: String },

    /// An unknown or unsupported modifier was encountered.
    #[error("Invalid modifier: {0}")]
    InvalidModifier(String),

    /// A structural error in the detection section.
    #[error("Invalid detection: {0}")]
    InvalidDetection(String),

    /// A structural error at the document level.
    #[error("Invalid document: {0}")]
    InvalidDocument(String),
}

/// A convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;
