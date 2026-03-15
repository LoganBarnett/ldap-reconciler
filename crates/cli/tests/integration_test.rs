use std::{path::PathBuf, process::Command};

fn get_binary_path() -> PathBuf {
  let mut path =
    std::env::current_exe().expect("Failed to get current executable path");

  // Navigate from the test executable to the binary
  path.pop(); // remove test executable name
  path.pop(); // remove deps dir
  path.push("ldap-reconciler");

  // If the binary doesn't exist in release, try debug
  if !path.exists() {
    path.pop();
    path.pop();
    path.push("debug");
    path.push("ldap-reconciler");
  }

  path
}

#[test]
fn test_help_flag() {
  let output = Command::new(get_binary_path()).arg("--help").output();

  match output {
    Ok(output) => {
      assert!(
        output.status.success(),
        "Expected success exit code, got: {:?}",
        output.status.code()
      );
      let stdout = String::from_utf8_lossy(&output.stdout);
      assert!(
        stdout.contains("Usage:"),
        "Expected help text to contain 'Usage:', got: {}",
        stdout
      );
    }
    Err(e) => {
      if e.kind() == std::io::ErrorKind::NotFound {
        eprintln!(
          "Binary not found. Please build the project first with: cargo build -p rust-template-cli"
        );
      }
      panic!("Failed to execute binary: {}", e);
    }
  }
}

#[test]
fn test_version_flag() {
  let output = Command::new(get_binary_path()).arg("--version").output();

  match output {
    Ok(output) => {
      assert!(
        output.status.success(),
        "Expected success exit code, got: {:?}",
        output.status.code()
      );
      let stdout = String::from_utf8_lossy(&output.stdout);
      assert!(
        stdout.contains("ldap-reconciler"),
        "Expected version text to contain 'ldap-reconciler', got: {}",
        stdout
      );
    }
    Err(e) => {
      if e.kind() == std::io::ErrorKind::NotFound {
        eprintln!(
          "Binary not found. Please build the project first with: cargo build -p rust-template-cli"
        );
      }
      panic!("Failed to execute binary: {}", e);
    }
  }
}

#[test]
fn test_missing_required_arguments() {
  // Running without any arguments should fail with validation error
  let output = Command::new(get_binary_path()).output();

  match output {
    Ok(output) => {
      assert!(
        !output.status.success(),
        "Expected failure exit code when missing required arguments"
      );
      let stderr = String::from_utf8_lossy(&output.stderr);
      assert!(
        stderr.contains("LDAP URL is required")
          || stderr.contains("LDAP bind DN is required")
          || stderr.contains("LDAP password is required")
          || stderr.contains("State file is required"),
        "Expected error about missing required arguments, got: {}",
        stderr
      );
    }
    Err(e) => {
      if e.kind() == std::io::ErrorKind::NotFound {
        eprintln!(
          "Binary not found. Please build the project first with: cargo build -p ldap-reconciler"
        );
      }
      panic!("Failed to execute binary: {}", e);
    }
  }
}

#[test]
fn test_dry_run_with_invalid_state_file() {
  // Test that dry-run mode still validates the state file
  let output = Command::new(get_binary_path())
    .arg("--ldap-url")
    .arg("ldap://localhost:389")
    .arg("--ldap-bind-dn")
    .arg("cn=admin,dc=test,dc=local")
    .arg("--ldap-password")
    .arg("password")
    .arg("--state-file")
    .arg("/nonexistent/path/to/state.json5")
    .arg("--dry-run")
    .output();

  match output {
    Ok(output) => {
      assert!(
        !output.status.success(),
        "Expected failure when state file doesn't exist"
      );
      let stderr = String::from_utf8_lossy(&output.stderr);
      assert!(
        stderr.contains("Failed to read state file")
          || stderr.contains("No such file"),
        "Expected error about state file, got: {}",
        stderr
      );
    }
    Err(e) => {
      if e.kind() == std::io::ErrorKind::NotFound {
        eprintln!(
          "Binary not found. Please build the project first with: cargo build -p ldap-reconciler"
        );
      }
      panic!("Failed to execute binary: {}", e);
    }
  }
}

#[test]
fn test_dry_run_with_valid_state_file() {
  // Create a temporary state file
  let temp_dir = std::env::temp_dir();
  let state_file = temp_dir.join("test_state.json5");

  let state_content = r#"{
    baseDn: "dc=test,dc=local",
    entries: {
      "dc=test,dc=local": {
        objectClass: ["dcObject", "organization", "top"],
        dc: "test",
        o: "Test Organization"
      }
    }
  }"#;

  std::fs::write(&state_file, state_content)
    .expect("Failed to write test state file");

  let output = Command::new(get_binary_path())
    .arg("--ldap-url")
    .arg("ldap://localhost:389")
    .arg("--ldap-bind-dn")
    .arg("cn=admin,dc=test,dc=local")
    .arg("--ldap-password")
    .arg("password")
    .arg("--state-file")
    .arg(&state_file)
    .arg("--dry-run")
    .output();

  // Clean up
  let _ = std::fs::remove_file(&state_file);

  match output {
    Ok(output) => {
      assert!(
        output.status.success(),
        "Expected success in dry-run mode with valid state file, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
      );
      let stderr = String::from_utf8_lossy(&output.stderr);
      let stdout = String::from_utf8_lossy(&output.stdout);
      let combined = format!("{}{}", stdout, stderr);
      assert!(
        combined.contains("DRY RUN MODE")
          || combined.contains("dry")
          || combined.contains("Would reconcile"),
        "Expected dry-run message in output, got stdout: {}, stderr: {}",
        stdout,
        stderr
      );
    }
    Err(e) => {
      if e.kind() == std::io::ErrorKind::NotFound {
        eprintln!(
          "Binary not found. Please build the project first with: cargo build -p ldap-reconciler"
        );
      }
      panic!("Failed to execute binary: {}", e);
    }
  }
}
