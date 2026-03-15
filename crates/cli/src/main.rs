//! ldap-reconciler - LDAP state reconciliation tool
//!
//! # LLM Development Guidelines
//! When modifying this code:
//! - Keep configuration logic in config.rs
//! - Keep business logic out of main.rs - use separate modules
//! - Maintain the staged configuration pattern (CliRaw -> ConfigFileRaw -> Config)
//! - Use semantic error types with thiserror - NO anyhow blindly wrapping errors
//! - Add context at each error site explaining WHAT failed and WHY
//! - Keep logging structured and consistent

mod config;

use clap::Parser;
use config::{CliRaw, Config, ConfigError};
use ldap_reconciler_lib::{
  connect, init_logging, reconcile, ConnectionError, LdapConnectionConfig,
  ReconcileError, ReconciledState,
};
use std::path::PathBuf;
use thiserror::Error;
use tracing::{info, warn};

#[derive(Debug, Error)]
enum ApplicationError {
  #[error("Failed to load configuration during startup: {0}")]
  ConfigurationLoad(#[from] ConfigError),

  #[error("Failed to read state file at {path:?}: {source}")]
  StateFileRead {
    path: PathBuf,
    #[source]
    source: std::io::Error,
  },

  #[error("Failed to parse state file at {path:?}: {source}")]
  StateFileParse {
    path: PathBuf,
    #[source]
    source: json5::Error,
  },

  #[error("Failed to connect to LDAP server at {url}: {source}")]
  LdapConnection {
    url: String,
    #[source]
    source: ConnectionError,
  },

  #[error("Reconciliation failed: {0}")]
  Reconciliation(#[from] ReconcileError),
}

fn main() -> Result<(), ApplicationError> {
  let cli = CliRaw::parse();

  let config = Config::from_cli_and_file(cli).map_err(|e| {
    eprintln!("Configuration error: {}", e);
    ApplicationError::ConfigurationLoad(e)
  })?;

  init_logging(config.log_level, config.log_format);

  info!("Starting ldap-reconciler");
  info!(
    ldap_url = %config.ldap_url,
    state_file = %config.state_file.display(),
    dry_run = config.dry_run,
    "Configuration loaded successfully"
  );

  run(config)?;

  info!("Shutting down ldap-reconciler");
  Ok(())
}

fn run(config: Config) -> Result<(), ApplicationError> {
  // Load desired state from JSON5 file
  info!(path = %config.state_file.display(), "Loading state file");
  let state_contents =
    std::fs::read_to_string(&config.state_file).map_err(|source| {
      ApplicationError::StateFileRead {
        path: config.state_file.clone(),
        source,
      }
    })?;

  let reconciled_state: ReconciledState = json5::from_str(&state_contents)
    .map_err(|source| ApplicationError::StateFileParse {
      path: config.state_file.clone(),
      source,
    })?;

  info!(
    base_dn = %reconciled_state.base_dn,
    entries = reconciled_state.entries.len(),
    "State file loaded successfully"
  );

  if config.dry_run {
    warn!("DRY RUN MODE - No changes will be applied to LDAP");
    info!("Would reconcile the following entries:");
    for dn in reconciled_state.entries.keys() {
      info!("  - {}", dn);
    }
    return Ok(());
  }

  // Connect to LDAP
  info!(url = %config.ldap_url, "Connecting to LDAP server");
  let ldap_config = LdapConnectionConfig {
    url: config.ldap_url.clone(),
    bind_dn: config.ldap_bind_dn.clone(),
    bind_password: config.ldap_password.clone(),
  };

  let mut ldap = connect(&ldap_config).map_err(|source| {
    ApplicationError::LdapConnection {
      url: config.ldap_url.clone(),
      source,
    }
  })?;

  info!("Connected to LDAP server successfully");

  // Perform reconciliation
  info!("Starting reconciliation");
  let report = reconcile(&mut ldap, &reconciled_state)?;

  // Display results
  info!(
    created = report.created.len(),
    modified = report.modified.len(),
    unchanged = report.unchanged.len(),
    removed = report.removed.len(),
    total_changed = report.total_changed(),
    "Reconciliation completed"
  );

  if !report.created.is_empty() {
    info!("Created entries:");
    for dn in &report.created {
      info!("  + {}", dn);
    }
  }

  if !report.modified.is_empty() {
    info!("Modified entries:");
    for (dn, attrs) in &report.modified {
      info!("  ~ {} (changed: {})", dn, attrs.join(", "));
    }
  }

  if !report.removed.is_empty() {
    info!("Removed entries:");
    for dn in &report.removed {
      info!("  - {}", dn);
    }
  }

  if report.total_changed() == 0 {
    info!("No changes needed - LDAP state matches desired state");
  } else {
    info!("Successfully applied {} changes", report.total_changed());
  }

  Ok(())
}
