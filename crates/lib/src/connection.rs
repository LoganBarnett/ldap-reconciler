use ldap3::{LdapConn, LdapError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConnectionError {
  #[error("Failed to connect to LDAP server at {url}: {source}")]
  ConnectionFailed {
    url: String,
    #[source]
    source: LdapError,
  },

  #[error("Failed to bind to LDAP server with DN '{bind_dn}': {source}")]
  BindFailed {
    bind_dn: String,
    #[source]
    source: LdapError,
  },

  #[error("LDAP operation failed: {0}")]
  OperationFailed(#[from] LdapError),
}

/// Configuration for connecting to an LDAP server
#[derive(Debug, Clone)]
pub struct LdapConnectionConfig {
  pub url: String,
  pub bind_dn: String,
  pub bind_password: String,
}

impl LdapConnectionConfig {
  pub fn new(
    url: impl Into<String>,
    bind_dn: impl Into<String>,
    bind_password: impl Into<String>,
  ) -> Self {
    Self {
      url: url.into(),
      bind_dn: bind_dn.into(),
      bind_password: bind_password.into(),
    }
  }
}

/// Establishes and authenticates a connection to an LDAP server
pub fn connect(
  config: &LdapConnectionConfig,
) -> Result<LdapConn, ConnectionError> {
  let mut ldap = LdapConn::new(&config.url).map_err(|source| {
    ConnectionError::ConnectionFailed {
      url: config.url.clone(),
      source,
    }
  })?;

  ldap
    .simple_bind(&config.bind_dn, &config.bind_password)
    .map_err(|source| ConnectionError::BindFailed {
      bind_dn: config.bind_dn.clone(),
      source,
    })?;

  Ok(ldap)
}
