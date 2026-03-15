use clap::Parser;
use ldap_reconciler_lib::{LogFormat, LogLevel};
use serde::Deserialize;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
  #[error(
    "Failed to read configuration file at {path:?} during startup: {source}"
  )]
  FileRead {
    path: PathBuf,
    #[source]
    source: std::io::Error,
  },

  #[error("Failed to parse configuration file at {path:?}: {source}")]
  Parse {
    path: PathBuf,
    #[source]
    source: toml::de::Error,
  },

  #[error("Configuration validation failed: {0}")]
  Validation(String),
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct CliRaw {
  /// Log level (trace, debug, info, warn, error)
  #[arg(long, env = "LOG_LEVEL")]
  pub log_level: Option<String>,

  /// Log format (text, json)
  #[arg(long, env = "LOG_FORMAT")]
  pub log_format: Option<String>,

  /// Path to configuration file
  #[arg(short, long, env = "CONFIG_FILE")]
  pub config: Option<PathBuf>,

  /// LDAP server URL (e.g., ldap://localhost:389)
  #[arg(long, env = "LDAP_URL")]
  pub ldap_url: Option<String>,

  /// LDAP bind DN for authentication
  #[arg(long, env = "LDAP_BIND_DN")]
  pub ldap_bind_dn: Option<String>,

  /// LDAP bind password
  #[arg(long, env = "LDAP_PASSWORD")]
  pub ldap_password: Option<String>,

  /// Path to JSON5 desired state file
  #[arg(short, long, env = "STATE_FILE")]
  pub state_file: Option<PathBuf>,

  /// Dry run mode - show what would be changed without applying
  #[arg(long, default_value = "false")]
  pub dry_run: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct ConfigFileRaw {
  pub log_level: Option<String>,
  pub log_format: Option<String>,
  pub ldap_url: Option<String>,
  pub ldap_bind_dn: Option<String>,
  pub ldap_password: Option<String>,
  pub state_file: Option<PathBuf>,
}

impl ConfigFileRaw {
  pub fn from_file(path: &PathBuf) -> Result<Self, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|source| {
      ConfigError::FileRead {
        path: path.clone(),
        source,
      }
    })?;

    let config: ConfigFileRaw =
      toml::from_str(&contents).map_err(|source| ConfigError::Parse {
        path: path.clone(),
        source,
      })?;

    Ok(config)
  }
}

#[derive(Debug)]
pub struct Config {
  pub log_level: LogLevel,
  pub log_format: LogFormat,
  pub ldap_url: String,
  pub ldap_bind_dn: String,
  pub ldap_password: String,
  pub state_file: PathBuf,
  pub dry_run: bool,
}

impl Config {
  pub fn from_cli_and_file(cli: CliRaw) -> Result<Self, ConfigError> {
    let config_file = if let Some(config_path) = &cli.config {
      ConfigFileRaw::from_file(config_path)?
    } else {
      let default_config_path = PathBuf::from("config.toml");
      if default_config_path.exists() {
        ConfigFileRaw::from_file(&default_config_path)?
      } else {
        ConfigFileRaw::default()
      }
    };

    let log_level_str = cli
      .log_level
      .or(config_file.log_level)
      .unwrap_or_else(|| "info".to_string());

    let log_level = log_level_str
      .parse::<LogLevel>()
      .map_err(|e| ConfigError::Validation(e.to_string()))?;

    let log_format_str = cli
      .log_format
      .or(config_file.log_format)
      .unwrap_or_else(|| "text".to_string());

    let log_format = log_format_str
      .parse::<LogFormat>()
      .map_err(|e| ConfigError::Validation(e.to_string()))?;

    let ldap_url = cli.ldap_url.or(config_file.ldap_url).ok_or_else(|| {
      ConfigError::Validation(
        "LDAP URL is required (use --ldap-url or set in config file)"
          .to_string(),
      )
    })?;

    let ldap_bind_dn = cli
      .ldap_bind_dn
      .or(config_file.ldap_bind_dn)
      .ok_or_else(|| {
        ConfigError::Validation(
          "LDAP bind DN is required (use --ldap-bind-dn or set in config file)"
            .to_string(),
        )
      })?;

    let ldap_password = cli
      .ldap_password
      .or(config_file.ldap_password)
      .ok_or_else(|| {
        ConfigError::Validation(
          "LDAP password is required (use --ldap-password or set in config file)"
            .to_string(),
        )
      })?;

    let state_file =
      cli.state_file.or(config_file.state_file).ok_or_else(|| {
        ConfigError::Validation(
          "State file is required (use --state-file or set in config file)"
            .to_string(),
        )
      })?;

    Ok(Config {
      log_level,
      log_format,
      ldap_url,
      ldap_bind_dn,
      ldap_password,
      state_file,
      dry_run: cli.dry_run,
    })
  }
}
