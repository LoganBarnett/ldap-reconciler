//! Field value management types for LDAP reconciliation.
//!
//! This module defines how field values are managed during reconciliation:
//! - Static: Always enforce the declared value
//! - Initial: Set once if absent, or if removed (reset to initial value)
//! - StaticFromPath: Read from file, always enforce
//! - InitialFromPath: Read from file on initial set only

use serde::Deserialize;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FieldValueError {
    #[error("Failed to read field value from path {path:?}: {source}")]
    PathRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Defines how a field value should be managed during reconciliation.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum FieldValue {
    /// Always enforce this exact value on every reconciliation.
    ///
    /// Use case: Service account attributes, group descriptions, any field
    /// that should always match the declared state.
    Static { value: String },

    /// Set once if absent, or if the field was removed (reset to initial value).
    ///
    /// Use case: User passwords, default shells, initial preferences that
    /// users can modify.
    Initial { value: String },

    /// Read value from path, always enforce.
    ///
    /// Use case: Service account passwords from agenix, certificates.
    StaticFromPath { path: PathBuf },

    /// Read value from path, treat as Initial.
    ///
    /// Use case: User passwords from agenix that should be set once.
    InitialFromPath { path: PathBuf },
}

impl FieldValue {
    /// Resolves the field value, reading from paths if necessary.
    pub fn resolve(&self) -> Result<ResolvedFieldValue, FieldValueError> {
        match self {
            FieldValue::Static { value } => Ok(ResolvedFieldValue::Static(value.clone())),
            FieldValue::Initial { value } => Ok(ResolvedFieldValue::Initial(value.clone())),
            FieldValue::StaticFromPath { path } => {
                let value = std::fs::read_to_string(path)
                    .map_err(|source| FieldValueError::PathRead {
                        path: path.clone(),
                        source,
                    })?
                    .trim()
                    .to_string();
                Ok(ResolvedFieldValue::Static(value))
            }
            FieldValue::InitialFromPath { path } => {
                let value = std::fs::read_to_string(path)
                    .map_err(|source| FieldValueError::PathRead {
                        path: path.clone(),
                        source,
                    })?
                    .trim()
                    .to_string();
                Ok(ResolvedFieldValue::Initial(value))
            }
        }
    }
}

/// A field value with paths resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedFieldValue {
    /// Always enforce this value.
    Static(String),
    /// Set only if absent or removed.
    Initial(String),
}

impl ResolvedFieldValue {
    /// Returns the value string.
    pub fn value(&self) -> &str {
        match self {
            ResolvedFieldValue::Static(v) | ResolvedFieldValue::Initial(v) => v,
        }
    }

    /// Returns true if this is a static field (should always be enforced).
    pub fn is_static(&self) -> bool {
        matches!(self, ResolvedFieldValue::Static(_))
    }

    /// Returns true if this is an initial field (set once).
    pub fn is_initial(&self) -> bool {
        matches!(self, ResolvedFieldValue::Initial(_))
    }
}
