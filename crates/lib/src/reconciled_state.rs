//! Desired state definitions for LDAP reconciliation.
//!
//! This module defines the structure of the desired LDAP state as declared
//! in the JSON5 configuration file.
//!
//! # Example JSON5 Configuration
//!
//! ```json5
//! {
//!   baseDn: "dc=example,dc=org",
//!   entries: {
//!     "uid=alice,ou=users,dc=example,dc=org": {
//!       objectClass: ["inetOrgPerson", "organizationalPerson", "person", "top"],
//!       cn: "Alice Smith",
//!       sn: "Smith",
//!       mail: ["alice@example.org", "alice@company.com"],
//!       userPassword: {
//!         managed: false,
//!         initialPath: "/run/secrets/alice-password"
//!       },
//!       description: {
//!         managed: true,
//!         value: "Administrator account"
//!       }
//!     },
//!     "cn=admins,ou=groups,dc=example,dc=org": {
//!       objectClass: ["groupOfNames"],
//!       cn: "admins",
//!       member: ["uid=alice,ou=users,dc=example,dc=org"]
//!     }
//!   }
//! }
//! ```

use crate::attribute_value::{
  AttributeValue, AttributeValueError, ResolvedAttributeValue,
};
use serde::Deserialize;
use std::collections::HashMap;

/// The top-level desired state configuration.
///
/// This is completely schema-agnostic - it doesn't know about users, groups,
/// or any specific object classes. It just manages LDAP entries.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReconciledState {
  /// LDAP base DN (e.g., "dc=example,dc=org")
  pub base_dn: String,

  /// Map of DN -> Entry attributes
  ///
  /// The key is the full DN, the value is a map of attribute names to values.
  #[serde(default)]
  pub entries: HashMap<String, Entry>,
}

/// An LDAP entry with its attributes.
///
/// This is just a map of attribute names to their values.
/// The schema is determined by the `objectClass` attribute values.
pub type Entry = HashMap<String, AttributeValue>;

/// A resolved entry ready for LDAP operations.
pub type ResolvedEntry = HashMap<String, ResolvedAttributeValue>;

impl ReconciledState {
  /// Parses a JSON5 string into a ReconciledState.
  pub fn from_json5(json5: &str) -> Result<Self, json5::Error> {
    json5::from_str(json5)
  }

  /// Resolves all attribute values in all entries, reading from files if necessary.
  pub fn resolve(
    &self,
  ) -> Result<HashMap<String, ResolvedEntry>, AttributeValueError> {
    let mut resolved = HashMap::new();

    for (dn, entry) in &self.entries {
      let mut resolved_entry = HashMap::new();

      for (attr_name, attr_value) in entry {
        resolved_entry.insert(attr_name.clone(), attr_value.resolve()?);
      }

      resolved.insert(dn.clone(), resolved_entry);
    }

    Ok(resolved)
  }

  /// Converts a ResolvedEntry into owned (name, values) pairs.
  ///
  /// Returns a vector that the caller can then borrow from to create
  /// the HashSet references needed by `entry_add`.
  ///
  /// # Example
  /// ```ignore
  /// let resolved_entry = state.resolve()?.get("uid=alice,...").unwrap();
  /// let attrs_owned = ReconciledState::to_ldap_add_format(resolved_entry);
  ///
  /// // Create borrowed refs from owned data
  /// let attrs_borrowed: Vec<(&str, HashSet<&str>)> = attrs_owned
  ///     .iter()
  ///     .map(|(name, values)| {
  ///         (name.as_str(), values.iter().map(|v| v.as_str()).collect())
  ///     })
  ///     .collect();
  ///
  /// entry_add(&mut ldap, dn, attrs_borrowed)?;
  /// ```
  pub fn to_ldap_add_format(
    entry: &ResolvedEntry,
  ) -> Vec<(String, Vec<String>)> {
    entry
      .iter()
      .map(|(name, resolved_attr)| (name.clone(), resolved_attr.values.clone()))
      .collect()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_simple_entry() {
    let json5 = r#"
        {
          baseDn: "dc=test,dc=local",
          entries: {
            "uid=alice,ou=users,dc=test,dc=local": {
              cn: "Alice Smith",
              mail: "alice@test.local"
            }
          }
        }
        "#;

    let state = ReconciledState::from_json5(json5).unwrap();
    assert_eq!(state.base_dn, "dc=test,dc=local");
    assert_eq!(state.entries.len(), 1);

    let entry = state
      .entries
      .get("uid=alice,ou=users,dc=test,dc=local")
      .unwrap();
    assert_eq!(entry.len(), 2);
    assert!(entry.contains_key("cn"));
    assert!(entry.contains_key("mail"));
  }

  #[test]
  fn test_parse_multi_value_attribute() {
    let json5 = r#"
        {
          baseDn: "dc=test,dc=local",
          entries: {
            "uid=alice,ou=users,dc=test,dc=local": {
              objectClass: ["inetOrgPerson", "person", "top"],
              mail: ["alice@test.local", "alice@company.com"]
            }
          }
        }
        "#;

    let state = ReconciledState::from_json5(json5).unwrap();
    let resolved = state.resolve().unwrap();

    let entry = resolved.get("uid=alice,ou=users,dc=test,dc=local").unwrap();
    let object_class = entry.get("objectClass").unwrap();
    assert_eq!(object_class.values, vec!["inetOrgPerson", "person", "top"]);
    assert!(object_class.managed);

    let mail = entry.get("mail").unwrap();
    assert_eq!(mail.values, vec!["alice@test.local", "alice@company.com"]);
    assert!(mail.managed);
  }

  #[test]
  fn test_parse_managed_and_unmanaged() {
    let json5 = r#"
        {
          baseDn: "dc=test,dc=local",
          entries: {
            "uid=alice,ou=users,dc=test,dc=local": {
              cn: {
                managed: true,
                value: "Alice Smith"
              },
              userPassword: {
                managed: false,
                initialValue: "changeme"
              }
            }
          }
        }
        "#;

    let state = ReconciledState::from_json5(json5).unwrap();
    let resolved = state.resolve().unwrap();

    let entry = resolved.get("uid=alice,ou=users,dc=test,dc=local").unwrap();

    let cn = entry.get("cn").unwrap();
    assert_eq!(cn.values, vec!["Alice Smith"]);
    assert!(cn.managed);

    let password = entry.get("userPassword").unwrap();
    assert_eq!(password.values, vec!["changeme"]);
    assert!(!password.managed);
  }
}
