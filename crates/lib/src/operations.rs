//! LDAP operations for reconciling desired state.
//!
//! This module provides generic operations for managing LDAP entries.
//! It is schema-agnostic and works with any entry type.

use ldap3::{LdapConn, LdapError, Mod, SearchEntry};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OperationError {
  #[error("Failed to add entry at DN '{dn}': {source}")]
  AddFailed {
    dn: String,
    #[source]
    source: LdapError,
  },

  #[error("Failed to remove entry at DN '{dn}': {source}")]
  RemoveFailed {
    dn: String,
    #[source]
    source: LdapError,
  },

  #[error("Failed to get entry at DN '{dn}': {source}")]
  GetFailed {
    dn: String,
    #[source]
    source: LdapError,
  },

  #[error("Failed to modify entry at DN '{dn}': {source}")]
  ModifyFailed {
    dn: String,
    #[source]
    source: LdapError,
  },

  #[error("LDAP operation failed: {0}")]
  LdapError(#[from] LdapError),
}

/// Adds a generic entry to LDAP.
///
/// This operation is idempotent - if the entry already exists (LDAP error 68),
/// it is treated as success since the desired state (entry exists) is achieved.
///
/// # Arguments
/// * `ldap` - Active LDAP connection
/// * `dn` - Distinguished Name for the entry
/// * `attrs` - Attributes as (name, values) tuples
///
/// # Returns
/// The DN of the created entry.
pub fn entry_add(
  ldap: &mut LdapConn,
  dn: &str,
  attrs: Vec<(&str, HashSet<&str>)>,
) -> Result<String, OperationError> {
  match ldap.add(dn, attrs) {
    Ok(result) => match result.success() {
      Ok(_) => Ok(dn.to_string()),
      Err(err) => {
        // Check if this is "entry already exists" error (rc=68)
        // If so, treat as success for idempotency
        if let LdapError::LdapResult { result } = &err {
          if result.rc == 68 {
            return Ok(dn.to_string());
          }
        }
        Err(OperationError::AddFailed {
          dn: dn.to_string(),
          source: err,
        })
      }
    },
    Err(source) => Err(OperationError::AddFailed {
      dn: dn.to_string(),
      source,
    }),
  }
}

/// Removes an entry from LDAP.
///
/// This operation is idempotent - if the entry doesn't exist (LDAP error 32),
/// it is treated as success since the desired state (entry absent) is achieved.
///
/// # Arguments
/// * `ldap` - Active LDAP connection
/// * `dn` - Distinguished Name of the entry to remove
///
/// # Returns
/// The DN of the removed entry.
pub fn entry_remove(
  ldap: &mut LdapConn,
  dn: &str,
) -> Result<String, OperationError> {
  match ldap.delete(dn) {
    Ok(result) => match result.success() {
      Ok(_) => Ok(dn.to_string()),
      Err(err) => {
        // Check if this is "no such object" error (rc=32)
        // If so, treat as success for idempotency
        if let LdapError::LdapResult { result } = &err {
          if result.rc == 32 {
            return Ok(dn.to_string());
          }
        }
        Err(OperationError::RemoveFailed {
          dn: dn.to_string(),
          source: err,
        })
      }
    },
    Err(source) => Err(OperationError::RemoveFailed {
      dn: dn.to_string(),
      source,
    }),
  }
}

/// Checks if an entry exists at the given DN.
///
/// Returns `Ok(true)` if the entry exists, `Ok(false)` if it doesn't exist.
/// Treats "no such object" (rc=32) as false rather than an error.
pub fn entry_exists(
  ldap: &mut LdapConn,
  dn: &str,
) -> Result<bool, OperationError> {
  match ldap.search(dn, ldap3::Scope::Base, "(objectClass=*)", vec!["1.1"]) {
    Ok(result) => match result.success() {
      Ok(search_result) => Ok(!search_result.0.is_empty()),
      Err(err) => {
        // Check if this is "no such object" error (rc=32)
        // If so, return false instead of error
        if let LdapError::LdapResult { result } = &err {
          if result.rc == 32 {
            return Ok(false);
          }
        }
        Err(OperationError::LdapError(err))
      }
    },
    Err(err) => Err(OperationError::LdapError(err)),
  }
}

/// Retrieves an entry's attributes from LDAP.
///
/// Returns `Ok(None)` if the entry doesn't exist (LDAP error 32).
/// Returns `Ok(Some(attrs))` if the entry exists, where attrs is a map of
/// attribute names to their values.
///
/// # Arguments
/// * `ldap` - Active LDAP connection
/// * `dn` - Distinguished Name of the entry to retrieve
///
/// # Returns
/// `None` if the entry doesn't exist, or `Some(HashMap)` with the entry's attributes.
pub fn entry_get(
  ldap: &mut LdapConn,
  dn: &str,
) -> Result<Option<HashMap<String, Vec<String>>>, OperationError> {
  // Search for just this entry with all user attributes
  match ldap.search(dn, ldap3::Scope::Base, "(objectClass=*)", vec!["*"]) {
    Ok(result) => match result.success() {
      Ok((entries, _res)) => {
        // Convert Vec<SearchEntry> to our format
        match entries.into_iter().next() {
          Some(raw_entry) => {
            let entry = SearchEntry::construct(raw_entry);
            Ok(Some(entry.attrs))
          }
          None => Ok(None),
        }
      }
      Err(err) => {
        // Check if this is "no such object" error (rc=32)
        // If so, return None instead of error
        if let LdapError::LdapResult { result } = &err {
          if result.rc == 32 {
            return Ok(None);
          }
        }
        Err(OperationError::GetFailed {
          dn: dn.to_string(),
          source: err,
        })
      }
    },
    Err(source) => Err(OperationError::GetFailed {
      dn: dn.to_string(),
      source,
    }),
  }
}

/// Modifies an entry's attributes in LDAP.
///
/// Uses the LDAP modify operation to update, add, or delete attribute values.
/// The modifications are specified using `ldap3::Mod` enum variants:
/// - `Mod::Add(attr, values)` - Add values to an attribute
/// - `Mod::Replace(attr, values)` - Replace all values of an attribute
/// - `Mod::Delete(attr, Some(values))` - Delete specific values
/// - `Mod::Delete(attr, None)` - Delete entire attribute
///
/// # Arguments
/// * `ldap` - Active LDAP connection
/// * `dn` - Distinguished Name of the entry to modify
/// * `mods` - Vector of modifications to apply
///
/// # Returns
/// The DN of the modified entry.
///
/// # Example
/// ```ignore
/// use ldap3::Mod;
/// use std::collections::HashSet;
///
/// let mods = vec![
///     Mod::Replace("mail", HashSet::from(["newemail@example.org"])),
///     Mod::Add("description", HashSet::from(["Updated description"])),
/// ];
/// entry_modify(&mut ldap, "uid=alice,ou=users,dc=example,dc=org", mods)?;
/// ```
pub fn entry_modify(
  ldap: &mut LdapConn,
  dn: &str,
  mods: Vec<Mod<&str>>,
) -> Result<String, OperationError> {
  match ldap.modify(dn, mods) {
    Ok(result) => match result.success() {
      Ok(_) => Ok(dn.to_string()),
      Err(source) => Err(OperationError::ModifyFailed {
        dn: dn.to_string(),
        source,
      }),
    },
    Err(source) => Err(OperationError::ModifyFailed {
      dn: dn.to_string(),
      source,
    }),
  }
}
