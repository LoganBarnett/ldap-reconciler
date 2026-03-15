use std::collections::HashSet;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread;
use std::time::Duration;

/// Global counter for generating unique port numbers in tests
static PORT_COUNTER: AtomicU16 = AtomicU16::new(10389);

/// Generates a unique test identifier for naming LDAP records
/// This ensures tests can run in parallel without collision
pub fn generate_test_id(test_name: &str) -> String {
  use std::time::SystemTime;

  let timestamp = SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .unwrap()
    .as_millis();

  // Use thread ID to further ensure uniqueness in parallel execution
  let thread_id = std::thread::current().id();
  format!("test-{}-{:?}-{}", test_name, thread_id, timestamp)
}

/// Helper to create test record names with proper prefix
pub fn test_record_name(test_id: &str, record_name: &str) -> String {
  format!("{}-{}", test_id, record_name)
}

/// Configuration for a test OpenLDAP server
#[derive(Debug)]
pub struct TestLdapServerConfig {
  pub port: u16,
  pub base_dn: String,
  pub admin_dn: String,
  pub admin_password: String,
}

impl Default for TestLdapServerConfig {
  fn default() -> Self {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    Self {
      port,
      base_dn: "dc=test,dc=local".to_string(),
      admin_dn: "cn=admin,dc=test,dc=local".to_string(),
      admin_password: "admin".to_string(),
    }
  }
}

impl TestLdapServerConfig {
  pub fn url(&self) -> String {
    format!("ldap://localhost:{}", self.port)
  }
}

/// Manages an OpenLDAP server process for testing
pub struct TestLdapServer {
  process: Option<Child>,
  config: TestLdapServerConfig,
  // Keep data_dir alive for the lifetime of the server
  // The field must not be dropped while the server is running
  #[allow(dead_code)]
  data_dir: tempfile::TempDir,
}

impl TestLdapServer {
  /// Starts a new OpenLDAP server for testing
  pub fn start() -> Result<Self, Box<dyn std::error::Error>> {
    let config = TestLdapServerConfig::default();
    let data_dir = tempfile::TempDir::new()?;

    // Create slapd configuration
    let slapd_conf = Self::create_slapd_config(&config, &data_dir)?;

    // Start slapd process (slapd should be on PATH via nix shell)
    let process = Command::new("slapd")
      .arg("-h")
      .arg(&config.url())
      .arg("-f")
      .arg(&slapd_conf)
      .arg("-d")
      .arg("0") // Daemon mode with no debug output
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .spawn()?;

    let mut server = Self {
      process: Some(process),
      config,
      data_dir,
    };

    // Wait for server to be ready
    server.wait_for_ready()?;

    Ok(server)
  }

  /// Finds the OpenLDAP schema directory by locating slapd on PATH
  fn find_schema_dir() -> Result<String, Box<dyn std::error::Error>> {
    // Find slapd (which is now on PATH via nix shell) and derive schema path
    if let Ok(output) = Command::new("which").arg("slapd").output() {
      if output.status.success() {
        let slapd_path =
          String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !slapd_path.is_empty() {
          // slapd is at: /nix/store/xxx-openldap-x.x.x/libexec/slapd
          // schemas are at: /nix/store/xxx-openldap-x.x.x/etc/schema/
          let openldap_root = std::path::Path::new(&slapd_path)
            .parent() // Remove 'slapd'
            .and_then(|p| p.parent()) // Remove 'libexec'
            .ok_or("Failed to derive OpenLDAP root from slapd path")?;

          let schema_dir = openldap_root.join("etc").join("schema");
          if schema_dir.exists() {
            return Ok(schema_dir.to_string_lossy().to_string());
          }
        }
      }
    }

    // Fallback to common system paths
    for path in &["/etc/openldap/schema", "/etc/ldap/schema"] {
      if std::path::Path::new(path).exists() {
        return Ok(path.to_string());
      }
    }

    Err(
      "Could not find OpenLDAP schema directory. Make sure slapd is on PATH."
        .into(),
    )
  }

  /// Creates a minimal slapd.conf configuration file
  fn create_slapd_config(
    config: &TestLdapServerConfig,
    data_dir: &tempfile::TempDir,
  ) -> Result<String, Box<dyn std::error::Error>> {
    let conf_path = data_dir.path().join("slapd.conf");
    let db_path = data_dir.path().join("db");
    std::fs::create_dir_all(&db_path)?;

    let schema_dir = Self::find_schema_dir()?;

    let conf_content = format!(
      r#"
include {}/core.schema
include {}/cosine.schema
include {}/inetorgperson.schema

pidfile {}/slapd.pid
argsfile {}/slapd.args

database mdb
suffix "{}"
rootdn "{}"
rootpw {}
directory {}
maxsize 1073741824
"#,
      schema_dir,
      schema_dir,
      schema_dir,
      data_dir.path().display(),
      data_dir.path().display(),
      config.base_dn,
      config.admin_dn,
      config.admin_password,
      db_path.display(),
    );

    std::fs::write(&conf_path, conf_content)?;
    Ok(conf_path.to_string_lossy().to_string())
  }

  /// Waits for the LDAP server to be ready to accept connections
  fn wait_for_ready(&mut self) -> Result<(), Box<dyn std::error::Error>> {
    let max_attempts = 50;
    let delay = Duration::from_millis(100);

    for attempt in 0..max_attempts {
      // Check if process is still running
      if let Some(ref mut process) = self.process {
        if let Ok(Some(status)) = process.try_wait() {
          return Err(
            format!("slapd process exited with status: {}", status).into(),
          );
        }
      }

      // Try to connect
      match ldap3::LdapConn::new(&self.config.url()) {
        Ok(_) => return Ok(()),
        Err(_) if attempt < max_attempts - 1 => {
          thread::sleep(delay);
        }
        Err(e) => {
          return Err(
            format!(
              "Failed to connect to LDAP server after {} attempts: {}",
              max_attempts, e
            )
            .into(),
          );
        }
      }
    }

    Ok(())
  }

  /// Returns the server configuration
  pub fn config(&self) -> &TestLdapServerConfig {
    &self.config
  }

  /// Initializes the base LDAP structure (base DN and organizational units)
  pub fn initialize_base_structure(
    &self,
    ldap: &mut ldap3::LdapConn,
  ) -> Result<(), Box<dyn std::error::Error>> {
    // Add base DN entry
    let base_attrs = vec![
      ("objectClass", HashSet::from(["dcObject", "organization", "top"])),
      ("dc", HashSet::from(["test"])),
      ("o", HashSet::from(["Test Organization"])),
    ];

    ldap.add(&self.config.base_dn, base_attrs)?.success()?;

    // Add ou=users
    let users_dn = format!("ou=users,{}", self.config.base_dn);
    let users_attrs = vec![
      ("objectClass", HashSet::from(["organizationalUnit", "top"])),
      ("ou", HashSet::from(["users"])),
    ];

    ldap.add(&users_dn, users_attrs)?.success()?;

    // Add ou=groups
    let groups_dn = format!("ou=groups,{}", self.config.base_dn);
    let groups_attrs = vec![
      ("objectClass", HashSet::from(["organizationalUnit", "top"])),
      ("ou", HashSet::from(["groups"])),
    ];

    ldap.add(&groups_dn, groups_attrs)?.success()?;

    Ok(())
  }
}

impl Drop for TestLdapServer {
  fn drop(&mut self) {
    if let Some(mut process) = self.process.take() {
      let _ = process.kill();
      let _ = process.wait();
    }
  }
}
