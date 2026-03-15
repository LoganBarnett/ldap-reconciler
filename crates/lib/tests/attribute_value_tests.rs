/// Comprehensive tests for all valid and invalid attribute value variants
use ldap_reconciler_lib::ReconciledState;

// ============================================================================
// VALID VARIANTS - These should all parse successfully
// ============================================================================

#[test]
fn valid_shorthand_single_string() {
    let json5 = r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { cn: "Alice" } } }"#;
    let state = ReconciledState::from_json5(json5).unwrap();
    let resolved = state.resolve().unwrap();

    let entry = resolved.get("cn=test").unwrap();
    let cn = entry.get("cn").unwrap();
    assert_eq!(cn.values, vec!["Alice"]);
    assert!(cn.managed);
}

#[test]
fn valid_shorthand_array() {
    let json5 = r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { objectClass: ["person", "top"] } } }"#;
    let state = ReconciledState::from_json5(json5).unwrap();
    let resolved = state.resolve().unwrap();

    let entry = resolved.get("cn=test").unwrap();
    let oc = entry.get("objectClass").unwrap();
    assert_eq!(oc.values, vec!["person", "top"]);
    assert!(oc.managed);
}

#[test]
fn valid_managed_true_with_value_single() {
    let json5 = r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { cn: { managed: true, value: "Alice" } } } }"#;
    let state = ReconciledState::from_json5(json5).unwrap();
    let resolved = state.resolve().unwrap();

    let entry = resolved.get("cn=test").unwrap();
    let cn = entry.get("cn").unwrap();
    assert_eq!(cn.values, vec!["Alice"]);
    assert!(cn.managed);
}

#[test]
fn valid_managed_true_with_value_array() {
    let json5 = r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { mail: { managed: true, value: ["a@example.org", "b@example.org"] } } } }"#;
    let state = ReconciledState::from_json5(json5).unwrap();
    let resolved = state.resolve().unwrap();

    let entry = resolved.get("cn=test").unwrap();
    let mail = entry.get("mail").unwrap();
    assert_eq!(mail.values, vec!["a@example.org", "b@example.org"]);
    assert!(mail.managed);
}

#[test]
fn valid_managed_true_with_path() {
    // Create a temp file for testing
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), "secret-value\n").unwrap();

    let json5 = format!(
        r#"{{ baseDn: "dc=test,dc=local", entries: {{ "cn=test": {{ key: {{ managed: true, path: "{}" }} }} }} }}"#,
        temp_file.path().display()
    );

    let state = ReconciledState::from_json5(&json5).unwrap();
    let resolved = state.resolve().unwrap();

    let entry = resolved.get("cn=test").unwrap();
    let key = entry.get("key").unwrap();
    assert_eq!(key.values, vec!["secret-value"]);
    assert!(key.managed);
}

#[test]
fn valid_managed_false_with_initial_value_single() {
    let json5 = r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { userPassword: { managed: false, initialValue: "changeme" } } } }"#;
    let state = ReconciledState::from_json5(json5).unwrap();
    let resolved = state.resolve().unwrap();

    let entry = resolved.get("cn=test").unwrap();
    let pw = entry.get("userPassword").unwrap();
    assert_eq!(pw.values, vec!["changeme"]);
    assert!(!pw.managed);
}

#[test]
fn valid_managed_false_with_initial_value_array() {
    let json5 = r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { mail: { managed: false, initialValue: ["a@example.org", "b@example.org"] } } } }"#;
    let state = ReconciledState::from_json5(json5).unwrap();
    let resolved = state.resolve().unwrap();

    let entry = resolved.get("cn=test").unwrap();
    let mail = entry.get("mail").unwrap();
    assert_eq!(mail.values, vec!["a@example.org", "b@example.org"]);
    assert!(!mail.managed);
}

#[test]
fn valid_managed_false_with_initial_path() {
    // Create a temp file for testing
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), "initial-password\n").unwrap();

    let json5 = format!(
        r#"{{ baseDn: "dc=test,dc=local", entries: {{ "cn=test": {{ userPassword: {{ managed: false, initialPath: "{}" }} }} }} }}"#,
        temp_file.path().display()
    );

    let state = ReconciledState::from_json5(&json5).unwrap();
    let resolved = state.resolve().unwrap();

    let entry = resolved.get("cn=test").unwrap();
    let pw = entry.get("userPassword").unwrap();
    assert_eq!(pw.values, vec!["initial-password"]);
    assert!(!pw.managed);
}

// ============================================================================
// INVALID VARIANTS - These should all fail to parse
// ============================================================================

#[test]
fn invalid_managed_true_with_initial_value() {
    let json5 = r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { cn: { managed: true, initialValue: "wrong" } } } }"#;
    let result = ReconciledState::from_json5(json5);
    assert!(result.is_err(), "Should reject managed: true with initialValue");
}

#[test]
fn invalid_managed_true_with_initial_path() {
    let json5 = r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { cn: { managed: true, initialPath: "/foo" } } } }"#;
    let result = ReconciledState::from_json5(json5);
    assert!(result.is_err(), "Should reject managed: true with initialPath");
}

#[test]
fn invalid_managed_false_with_value() {
    let json5 = r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { cn: { managed: false, value: "wrong" } } } }"#;
    let result = ReconciledState::from_json5(json5);
    assert!(result.is_err(), "Should reject managed: false with value");
}

#[test]
fn invalid_managed_false_with_path() {
    let json5 = r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { cn: { managed: false, path: "/foo" } } } }"#;
    let result = ReconciledState::from_json5(json5);
    assert!(result.is_err(), "Should reject managed: false with path");
}

#[test]
fn invalid_managed_true_with_both_value_and_path() {
    let json5 = r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { cn: { managed: true, value: "wrong", path: "/foo" } } } }"#;
    let result = ReconciledState::from_json5(json5);
    assert!(result.is_err(), "Should reject both value and path");
}

#[test]
fn invalid_managed_false_with_both_initial_value_and_initial_path() {
    let json5 = r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { cn: { managed: false, initialValue: "wrong", initialPath: "/foo" } } } }"#;
    let result = ReconciledState::from_json5(json5);
    assert!(result.is_err(), "Should reject both initialValue and initialPath");
}

#[test]
fn invalid_managed_true_with_no_value_or_path() {
    let json5 =
        r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { cn: { managed: true } } } }"#;
    let result = ReconciledState::from_json5(json5);
    assert!(result.is_err(), "Should reject managed: true without value or path");
}

#[test]
fn invalid_managed_false_with_no_initial_value_or_path() {
    let json5 =
        r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { cn: { managed: false } } } }"#;
    let result = ReconciledState::from_json5(json5);
    assert!(
        result.is_err(),
        "Should reject managed: false without initialValue or initialPath"
    );
}

#[test]
fn invalid_missing_managed_field() {
    let json5 =
        r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { cn: { value: "wrong" } } } }"#;
    let result = ReconciledState::from_json5(json5);
    assert!(result.is_err(), "Should reject object without managed field");
}

#[test]
fn invalid_mixed_all_fields() {
    let json5 = r#"{ baseDn: "dc=test,dc=local", entries: { "cn=test": { cn: { managed: true, value: "a", path: "/b", initialValue: "c", initialPath: "/d" } } } }"#;
    let result = ReconciledState::from_json5(json5);
    assert!(result.is_err(), "Should reject all fields mixed together");
}
