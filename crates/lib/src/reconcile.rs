//! Reconciliation logic for LDAP entries.
//!
//! This module implements the core reconciliation algorithm that compares
//! desired state (from JSON5 configuration) with actual state (from LDAP)
//! and determines what operations are needed to achieve the desired state.

use crate::operations::{entry_add, entry_get, entry_modify, OperationError};
use crate::reconciled_state::{ReconciledState, ResolvedEntry};
use ldap3::{LdapConn, Mod};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReconcileError {
  #[error("Failed to resolve attribute values: {0}")]
  ResolveError(#[from] crate::attribute_value::AttributeValueError),

  #[error("LDAP operation failed: {0}")]
  OperationError(#[from] OperationError),
}

/// Result of reconciling a single entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryReconcileResult {
  /// Entry was created (didn't exist before)
  Created,
  /// Entry was modified (existed but had different attributes)
  Modified { changed_attributes: Vec<String> },
  /// Entry already matched desired state (no changes needed)
  Unchanged,
}

/// Summary of a reconciliation operation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReconcileReport {
  /// Entries that were created
  pub created: Vec<String>,
  /// Entries that were modified (DN -> list of changed attributes)
  pub modified: HashMap<String, Vec<String>>,
  /// Entries that were unchanged
  pub unchanged: Vec<String>,
}

impl ReconcileReport {
  /// Returns the total number of entries that were changed (created or modified).
  pub fn total_changed(&self) -> usize {
    self.created.len() + self.modified.len()
  }

  /// Returns the total number of entries processed.
  pub fn total_processed(&self) -> usize {
    self.created.len() + self.modified.len() + self.unchanged.len()
  }
}

/// Reconciles a single entry: ensures it exists and has the correct attributes.
///
/// # Managed vs Unmanaged Attributes
///
/// - **Managed** attributes are always enforced - if the current value differs
///   from desired, it will be replaced.
/// - **Unmanaged** attributes are only set if they don't exist in LDAP.
///   Once set, the user can modify them and changes won't be overwritten.
///
/// # Arguments
/// * `ldap` - Active LDAP connection
/// * `dn` - Distinguished Name of the entry
/// * `desired` - Desired state of the entry (resolved attributes)
///
/// # Returns
/// The reconciliation result indicating what action was taken.
pub fn reconcile_entry(
  ldap: &mut LdapConn,
  dn: &str,
  desired: &ResolvedEntry,
) -> Result<EntryReconcileResult, ReconcileError> {
  // Get current state from LDAP
  let current = entry_get(ldap, dn)?;

  match current {
    None => {
      // Entry doesn't exist - create it with all attributes
      create_entry(ldap, dn, desired)?;
      Ok(EntryReconcileResult::Created)
    }
    Some(current_attrs) => {
      // Entry exists - compare and update if needed
      let changed = update_entry(ldap, dn, desired, &current_attrs)?;
      if changed.is_empty() {
        Ok(EntryReconcileResult::Unchanged)
      } else {
        Ok(EntryReconcileResult::Modified {
          changed_attributes: changed,
        })
      }
    }
  }
}

/// Creates a new entry with all desired attributes.
fn create_entry(
  ldap: &mut LdapConn,
  dn: &str,
  desired: &ResolvedEntry,
) -> Result<(), OperationError> {
  // Convert to LDAP format - owned data that we'll borrow from
  let attrs_owned = ReconciledState::to_ldap_add_format(desired);

  // Create borrowed references for LDAP
  let attrs_borrowed: Vec<(&str, HashSet<&str>)> = attrs_owned
    .iter()
    .map(|(name, values)| {
      let value_set: HashSet<&str> =
        values.iter().map(|v| v.as_str()).collect();
      (name.as_str(), value_set)
    })
    .collect();

  entry_add(ldap, dn, attrs_borrowed)?;
  Ok(())
}

/// Updates an existing entry by comparing desired vs current state.
///
/// Returns a list of attribute names that were changed.
fn update_entry(
  ldap: &mut LdapConn,
  dn: &str,
  desired: &ResolvedEntry,
  current: &HashMap<String, Vec<String>>,
) -> Result<Vec<String>, OperationError> {
  // First pass: collect all modifications needed (with owned data)
  #[derive(Debug)]
  enum ModType {
    Add,
    Replace,
  }

  let mut modifications: Vec<(String, Vec<String>, ModType)> = Vec::new();

  for (attr_name, desired_attr) in desired {
    let current_values = current.get(attr_name.as_str());

    // For unmanaged attributes, only set if they don't exist
    if !desired_attr.managed {
      if current_values.is_none() {
        // Attribute doesn't exist - set initial value
        modifications.push((
          attr_name.clone(),
          desired_attr.values.clone(),
          ModType::Add,
        ));
      }
      // If attribute exists, don't touch it (unmanaged)
      continue;
    }

    // For managed attributes, always enforce the value
    match current_values {
      None => {
        // Attribute doesn't exist - add it
        modifications.push((
          attr_name.clone(),
          desired_attr.values.clone(),
          ModType::Add,
        ));
      }
      Some(current_vals) => {
        // Check if values differ (order-independent comparison)
        let current_set: HashSet<&String> = current_vals.iter().collect();
        let desired_set: HashSet<&String> =
          desired_attr.values.iter().collect();

        if current_set != desired_set {
          // Values differ - replace them
          modifications.push((
            attr_name.clone(),
            desired_attr.values.clone(),
            ModType::Replace,
          ));
        }
      }
    }
  }

  // If no changes needed, return early
  if modifications.is_empty() {
    return Ok(Vec::new());
  }

  // Second pass: create Mod operations from owned data
  let changed_attrs: Vec<String> = modifications
    .iter()
    .map(|(name, _, _)| name.clone())
    .collect();

  let mods: Vec<Mod<&str>> = modifications
    .iter()
    .map(|(name, values, mod_type)| {
      let value_set: HashSet<&str> =
        values.iter().map(|s| s.as_str()).collect();
      match mod_type {
        ModType::Add => Mod::Add(name.as_str(), value_set),
        ModType::Replace => Mod::Replace(name.as_str(), value_set),
      }
    })
    .collect();

  // Apply modifications
  entry_modify(ldap, dn, mods)?;

  Ok(changed_attrs)
}

/// Counts the number of RDN components in a DN.
///
/// This is used to determine the depth of an entry in the LDAP hierarchy.
/// More components = deeper in the tree = more dependent on parents.
///
/// # Example
/// ```ignore
/// dn_depth("dc=example,dc=org") // 2
/// dn_depth("ou=users,dc=example,dc=org") // 3
/// dn_depth("uid=alice,ou=users,dc=example,dc=org") // 4
/// ```
fn dn_depth(dn: &str) -> usize {
  // Count comma-separated components
  // Note: This is a simple approach that works for most DNs
  // A more robust solution would use an LDAP DN parser
  dn.split(',').count()
}

/// Orders DNs by depth for processing.
///
/// Returns DNs sorted shallow-to-deep (parents before children).
/// This ensures parent entries exist before we try to create children.
///
/// # Arguments
/// * `dns` - Iterator of DN strings
///
/// # Returns
/// Vector of DNs sorted by depth (shallowest first)
fn order_dns_for_creation<'a>(
  dns: impl Iterator<Item = &'a String>,
) -> Vec<&'a String> {
  let mut dn_list: Vec<&String> = dns.collect();
  dn_list.sort_by_key(|dn| dn_depth(dn));
  dn_list
}

/// Reconciles all entries in the desired state with automatic DN ordering.
///
/// Processes entries in dependency order: parents before children.
/// This ensures that parent entries exist before attempting to create
/// child entries, avoiding LDAP "no such object" errors.
///
/// # Arguments
/// * `ldap` - Active LDAP connection
/// * `state` - The desired state to reconcile
///
/// # Returns
/// A report summarizing the reconciliation results.
///
/// # Example
/// If the state contains:
/// - `uid=alice,ou=users,dc=example,dc=org`
/// - `ou=users,dc=example,dc=org`
/// - `dc=example,dc=org`
///
/// They will be processed in the order: dc → ou → uid (shallow to deep)
pub fn reconcile(
  ldap: &mut LdapConn,
  state: &ReconciledState,
) -> Result<ReconcileReport, ReconcileError> {
  // Resolve all attribute values
  let resolved = state.resolve()?;

  // Order DNs by depth (parents before children)
  let ordered_dns = order_dns_for_creation(resolved.keys());

  let mut report = ReconcileReport::default();

  // Process each entry in dependency order
  for dn in ordered_dns {
    let desired_entry = &resolved[dn];
    let result = reconcile_entry(ldap, dn, desired_entry)?;

    match result {
      EntryReconcileResult::Created => {
        report.created.push(dn.clone());
      }
      EntryReconcileResult::Modified { changed_attributes } => {
        report.modified.insert(dn.clone(), changed_attributes);
      }
      EntryReconcileResult::Unchanged => {
        report.unchanged.push(dn.clone());
      }
    }
  }

  Ok(report)
}
