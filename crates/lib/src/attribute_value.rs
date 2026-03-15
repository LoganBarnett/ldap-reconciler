//! Attribute value management for LDAP reconciliation.
//!
//! This module defines how attribute values are specified in the JSON5
//! configuration and how they are managed during reconciliation.
//!
//! # Value Types
//!
//! ## Shorthand (Managed Values)
//!
//! The simplest form - just a string or array of strings. These are always
//! managed (enforced on every reconciliation):
//!
//! ```json5
//! {
//!   cn: "Alice Smith",                    // Single value
//!   objectClass: ["inetOrgPerson", "person", "top"],  // Multiple values
//! }
//! ```
//!
//! ## Full Form
//!
//! For more control, use the full object form:
//!
//! ### Managed (Always Enforced)
//!
//! ```json5
//! {
//!   description: {
//!     managed: true,
//!     value: "Administrator account"
//!   },
//!   sshPublicKey: {
//!     managed: true,
//!     path: "/run/secrets/alice-ssh-key"
//!   }
//! }
//! ```
//!
//! ### Unmanaged (Set Once, Then User Can Modify)
//!
//! ```json5
//! {
//!   userPassword: {
//!     managed: false,
//!     initialValue: "changeme"
//!   },
//!   description: {
//!     managed: false,
//!     initialPath: "/run/secrets/initial-description"
//!   }
//! }
//! ```

use serde::{Deserialize, Deserializer};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttributeValueError {
  #[error("Failed to read value from path {path:?}: {source}")]
  PathRead {
    path: PathBuf,
    #[source]
    source: std::io::Error,
  },
}

/// Represents a single value or multiple values for an attribute.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ValueOrValues {
  /// A single value
  Single(String),
  /// Multiple values (LDAP attributes can have multiple values)
  Multiple(Vec<String>),
}

impl ValueOrValues {
  /// Returns the value(s) as a vector
  pub fn to_vec(&self) -> Vec<String> {
    match self {
      ValueOrValues::Single(s) => vec![s.clone()],
      ValueOrValues::Multiple(v) => v.clone(),
    }
  }
}

/// Defines how an attribute value should be managed during reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeValue {
  /// Shorthand: a string or array of strings (always managed)
  ///
  /// Examples:
  /// - `"Alice Smith"` - single value
  /// - `["val1", "val2"]` - multiple values
  Shorthand(ValueOrValues),

  /// Managed value: always enforce this exact value
  ///
  /// Example: `{ managed: true, value: "foo" }`
  ManagedValue { value: ValueOrValues },

  /// Managed from path: always enforce value read from file
  ///
  /// Example: `{ managed: true, path: "/secrets/key" }`
  ManagedPath { path: PathBuf },

  /// Unmanaged with initial value: set once if absent
  ///
  /// Example: `{ managed: false, initialValue: "changeme" }`
  UnmanagedInitialValue { initial_value: ValueOrValues },

  /// Unmanaged from initial path: set once from file if absent
  ///
  /// Example: `{ managed: false, initialPath: "/secrets/initial-pw" }`
  UnmanagedInitialPath { initial_path: PathBuf },
}

// Temporary struct for deserializing all possible fields
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttributeValueHelper {
  managed: Option<bool>,
  value: Option<ValueOrValues>,
  path: Option<PathBuf>,
  initial_value: Option<ValueOrValues>,
  initial_path: Option<PathBuf>,
}

// Helper enum for untagged deserialization
#[derive(Deserialize)]
#[serde(untagged)]
enum AttributeValueRaw {
  Shorthand(ValueOrValues),
  Object(AttributeValueHelper),
}

impl<'de> Deserialize<'de> for AttributeValue {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    use serde::de::Error;

    let raw = AttributeValueRaw::deserialize(deserializer)?;

    match raw {
      AttributeValueRaw::Shorthand(v) => Ok(AttributeValue::Shorthand(v)),
      AttributeValueRaw::Object(helper) => {
        // Validate field combinations by destructuring Options directly
        match (
                    helper.managed,
                    helper.value,
                    helper.path,
                    helper.initial_value,
                    helper.initial_path,
                ) {
                    // managed: true, value: ...
                    (Some(true), Some(value), None, None, None) => {
                        Ok(AttributeValue::ManagedValue { value })
                    }
                    // managed: true, path: ...
                    (Some(true), None, Some(path), None, None) => {
                        Ok(AttributeValue::ManagedPath { path })
                    }
                    // managed: false, initialValue: ...
                    (Some(false), None, None, Some(initial_value), None) => {
                        Ok(AttributeValue::UnmanagedInitialValue { initial_value })
                    }
                    // managed: false, initialPath: ...
                    (Some(false), None, None, None, Some(initial_path)) => {
                        Ok(AttributeValue::UnmanagedInitialPath { initial_path })
                    }
                    // Invalid combinations
                    (None, _, _, _, _) => Err(Error::custom("missing 'managed' field")),
                    (Some(true), None, None, _, _) => {
                        Err(Error::custom("managed: true requires 'value' or 'path'"))
                    }
                    (Some(false), _, _, None, None) => {
                        Err(Error::custom("managed: false requires 'initialValue' or 'initialPath'"))
                    }
                    (Some(true), _, _, Some(_), _) => {
                        Err(Error::custom("managed: true cannot have 'initialValue'"))
                    }
                    (Some(true), _, _, _, Some(_)) => {
                        Err(Error::custom("managed: true cannot have 'initialPath'"))
                    }
                    (Some(false), Some(_), _, _, _) => {
                        Err(Error::custom("managed: false cannot have 'value'"))
                    }
                    (Some(false), _, Some(_), _, _) => {
                        Err(Error::custom("managed: false cannot have 'path'"))
                    }
                    _ => Err(Error::custom("invalid field combination - can only specify one of: value, path, initialValue, initialPath")),
                }
      }
    }
  }
}

/// A resolved attribute value with values and management policy
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAttributeValue {
  /// The actual value(s)
  pub values: Vec<String>,
  /// Whether this value should always be enforced (managed)
  /// or only set if absent (unmanaged/initial)
  pub managed: bool,
}

impl AttributeValue {
  /// Resolves the attribute value, reading from paths if necessary.
  pub fn resolve(&self) -> Result<ResolvedAttributeValue, AttributeValueError> {
    match self {
      AttributeValue::Shorthand(v) => Ok(ResolvedAttributeValue {
        values: v.to_vec(),
        managed: true,
      }),
      AttributeValue::ManagedValue { value } => Ok(ResolvedAttributeValue {
        values: value.to_vec(),
        managed: true,
      }),
      AttributeValue::ManagedPath { path } => {
        let content = std::fs::read_to_string(path).map_err(|source| {
          AttributeValueError::PathRead {
            path: path.clone(),
            source,
          }
        })?;
        Ok(ResolvedAttributeValue {
          values: vec![content.trim().to_string()],
          managed: true,
        })
      }
      AttributeValue::UnmanagedInitialValue { initial_value } => {
        Ok(ResolvedAttributeValue {
          values: initial_value.to_vec(),
          managed: false,
        })
      }
      AttributeValue::UnmanagedInitialPath { initial_path } => {
        let content =
          std::fs::read_to_string(initial_path).map_err(|source| {
            AttributeValueError::PathRead {
              path: initial_path.clone(),
              source,
            }
          })?;
        Ok(ResolvedAttributeValue {
          values: vec![content.trim().to_string()],
          managed: false,
        })
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_shorthand_single_value() {
    let json = r#""Alice Smith""#;
    let value: AttributeValue = json5::from_str(json).unwrap();

    match &value {
      AttributeValue::Shorthand(ValueOrValues::Single(s)) => {
        assert_eq!(s, "Alice Smith");
      }
      _ => panic!("Expected Shorthand with Single value"),
    }

    let resolved = value.resolve().unwrap();
    assert_eq!(resolved.values, vec!["Alice Smith"]);
    assert!(resolved.managed);
  }

  #[test]
  fn test_shorthand_multiple_values() {
    let json = r#"["inetOrgPerson", "person", "top"]"#;
    let value: AttributeValue = json5::from_str(json).unwrap();

    match &value {
      AttributeValue::Shorthand(ValueOrValues::Multiple(v)) => {
        assert_eq!(v, &vec!["inetOrgPerson", "person", "top"]);
      }
      _ => panic!("Expected Shorthand with Multiple values"),
    }

    let resolved = value.resolve().unwrap();
    assert_eq!(resolved.values, vec!["inetOrgPerson", "person", "top"]);
    assert!(resolved.managed);
  }

  #[test]
  fn test_managed_value() {
    let json = r#"{ managed: true, value: "Administrator" }"#;
    let value: AttributeValue = json5::from_str(json).unwrap();

    let resolved = value.resolve().unwrap();
    assert_eq!(resolved.values, vec!["Administrator"]);
    assert!(resolved.managed);
  }

  #[test]
  fn test_unmanaged_initial_value() {
    let json = r#"{ managed: false, initialValue: "changeme" }"#;
    let value: AttributeValue = json5::from_str(json).unwrap();

    let resolved = value.resolve().unwrap();
    assert_eq!(resolved.values, vec!["changeme"]);
    assert!(!resolved.managed);
  }
}
