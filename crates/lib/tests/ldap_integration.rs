mod common;

use common::{generate_test_id, test_record_name, TestLdapServer};
use ldap_reconciler_lib::{
  connect, entry_add, entry_exists, entry_get, entry_modify, entry_remove,
  reconcile, LdapConnectionConfig, Mod, ReconciledState,
};
use std::collections::HashSet;

/// Canary test that verifies we can:
/// 1. Start an OpenLDAP server
/// 2. Connect to it
/// 3. Authenticate
/// 4. Shut it down cleanly
#[test]
fn canary_ldap_connection() {
  // Start test OpenLDAP server
  let server =
    TestLdapServer::start().expect("Failed to start test LDAP server");

  let test_id = generate_test_id("canary");
  println!("Running canary test with ID: {}", test_id);

  // Create connection configuration
  let config = LdapConnectionConfig::new(
    server.config().url(),
    server.config().admin_dn.clone(),
    server.config().admin_password.clone(),
  );

  // Attempt to connect and authenticate
  let result = connect(&config);

  match result {
    Ok(_conn) => {
      println!("✓ Successfully connected to LDAP server");
      println!("✓ Successfully authenticated with admin credentials");
    }
    Err(e) => {
      panic!("Failed to connect to LDAP server: {}", e);
    }
  }

  // Server will be automatically shut down when dropped
  drop(server);
  println!("✓ LDAP server shut down cleanly");
}

/// Test that demonstrates how to use test record naming with prefixes
#[test]
fn test_record_naming() {
  let test_id = generate_test_id("record-naming");

  // Generate test record names with proper prefixes
  let user_name = test_record_name(&test_id, "user-foo");
  let group_name = test_record_name(&test_id, "group-bar");

  println!("Test ID: {}", test_id);
  println!("User name: {}", user_name);
  println!("Group name: {}", group_name);

  // Verify the naming pattern
  assert!(user_name.starts_with("test-"));
  assert!(user_name.contains("user-foo"));
  assert!(group_name.starts_with("test-"));
  assert!(group_name.contains("group-bar"));
}

/// Test that adds an entry to LDAP and verifies it exists.
/// This test happens to add a person-like entry, but the library
/// doesn't enforce any schema - it just adds whatever attributes we specify.
#[test]
fn test_entry_add() {
  // Start test OpenLDAP server
  let server =
    TestLdapServer::start().expect("Failed to start test LDAP server");

  let test_id = generate_test_id("add-entry");
  println!("Running entry_add test with ID: {}", test_id);

  // Connect to LDAP server
  let config = LdapConnectionConfig::new(
    server.config().url(),
    server.config().admin_dn.clone(),
    server.config().admin_password.clone(),
  );

  let mut ldap = connect(&config).expect("Failed to connect to LDAP server");

  // Initialize base structure (base DN and ou=users, ou=groups)
  server
    .initialize_base_structure(&mut ldap)
    .expect("Failed to initialize base structure");

  // Create a test entry with test-prefixed name
  let uid = test_record_name(&test_id, "alice");
  let dn = format!("uid={},ou=users,{}", uid, server.config().base_dn);

  // Build attributes manually - this is just one example schema,
  // the library doesn't care what attributes/objectClasses we use
  let attrs = vec![
    (
      "objectClass",
      HashSet::from(["inetOrgPerson", "organizationalPerson", "person", "top"]),
    ),
    ("uid", HashSet::from([uid.as_str()])),
    ("cn", HashSet::from(["Alice Smith"])),
    ("sn", HashSet::from(["Smith"])),
    ("mail", HashSet::from(["alice@example.org"])),
    ("userPassword", HashSet::from(["initial-password"])),
    ("description", HashSet::from(["Test entry for integration tests"])),
  ];

  // Add the entry using the generic entry_add function
  let result_dn =
    entry_add(&mut ldap, &dn, attrs).expect("Failed to add entry");

  println!("✓ Entry added with DN: {}", result_dn);

  // Verify the entry exists
  let exists =
    entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");

  assert!(exists, "Entry should exist after being added");
  println!("✓ Entry verified to exist");

  // Verify DN matches what we requested
  assert_eq!(result_dn, dn, "Returned DN should match requested DN");
  println!("✓ DN is correct");
}

/// Test that adding an entry that already exists is idempotent.
/// The entry should already be present, and the operation should succeed.
#[test]
fn test_entry_add_already_exists() {
  // Start test OpenLDAP server
  let server =
    TestLdapServer::start().expect("Failed to start test LDAP server");

  let test_id = generate_test_id("add-exists");
  println!("Running entry_add_already_exists test with ID: {}", test_id);

  // Connect to LDAP server
  let config = LdapConnectionConfig::new(
    server.config().url(),
    server.config().admin_dn.clone(),
    server.config().admin_password.clone(),
  );

  let mut ldap = connect(&config).expect("Failed to connect to LDAP server");

  // Initialize base structure
  server
    .initialize_base_structure(&mut ldap)
    .expect("Failed to initialize base structure");

  // Create a test entry
  let uid = test_record_name(&test_id, "bob");
  let dn = format!("uid={},ou=users,{}", uid, server.config().base_dn);

  let attrs = vec![
    (
      "objectClass",
      HashSet::from(["inetOrgPerson", "organizationalPerson", "person", "top"]),
    ),
    ("uid", HashSet::from([uid.as_str()])),
    ("cn", HashSet::from(["Bob Jones"])),
    ("sn", HashSet::from(["Jones"])),
    ("mail", HashSet::from(["bob@example.org"])),
    ("userPassword", HashSet::from(["password123"])),
  ];

  // Add the entry the first time
  let result_dn = entry_add(&mut ldap, &dn, attrs.clone())
    .expect("Failed to add entry the first time");

  println!("✓ Entry added with DN: {}", result_dn);

  // Verify it exists
  let exists =
    entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
  assert!(exists, "Entry should exist after first add");
  println!("✓ Entry verified to exist after first add");

  // Try to add the same entry again - this should be idempotent (succeed without error)
  let result_dn2 = entry_add(&mut ldap, &dn, attrs)
    .expect("Second add should succeed (idempotent)");

  println!("✓ Second add succeeded (idempotent): {}", result_dn2);
  assert_eq!(result_dn2, dn, "DN should match on second add");

  // Verify the entry still exists
  let still_exists =
    entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
  assert!(still_exists, "Entry should still exist after second add");
  println!("✓ Entry still exists and operation was idempotent");
}

/// Test that removes an existing entry from LDAP.
#[test]
fn test_entry_remove() {
  // Start test OpenLDAP server
  let server =
    TestLdapServer::start().expect("Failed to start test LDAP server");

  let test_id = generate_test_id("remove-entry");
  println!("Running entry_remove test with ID: {}", test_id);

  // Connect to LDAP server
  let config = LdapConnectionConfig::new(
    server.config().url(),
    server.config().admin_dn.clone(),
    server.config().admin_password.clone(),
  );

  let mut ldap = connect(&config).expect("Failed to connect to LDAP server");

  // Initialize base structure
  server
    .initialize_base_structure(&mut ldap)
    .expect("Failed to initialize base structure");

  // Create a test entry to remove
  let uid = test_record_name(&test_id, "charlie");
  let dn = format!("uid={},ou=users,{}", uid, server.config().base_dn);

  let attrs = vec![
    (
      "objectClass",
      HashSet::from(["inetOrgPerson", "organizationalPerson", "person", "top"]),
    ),
    ("uid", HashSet::from([uid.as_str()])),
    ("cn", HashSet::from(["Charlie Brown"])),
    ("sn", HashSet::from(["Brown"])),
    ("mail", HashSet::from(["charlie@example.org"])),
    ("userPassword", HashSet::from(["password456"])),
  ];

  // Add the entry first
  entry_add(&mut ldap, &dn, attrs).expect("Failed to add entry");

  println!("✓ Entry added with DN: {}", dn);

  // Verify it exists
  let exists =
    entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
  assert!(exists, "Entry should exist before removal");
  println!("✓ Entry verified to exist before removal");

  // Remove the entry
  let result_dn = entry_remove(&mut ldap, &dn).expect("Failed to remove entry");

  println!("✓ Entry removed with DN: {}", result_dn);
  assert_eq!(result_dn, dn, "DN should match");

  // Verify it no longer exists
  let still_exists =
    entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
  assert!(!still_exists, "Entry should not exist after removal");
  println!("✓ Entry verified to be removed");
}

/// Test that removing an entry that doesn't exist is idempotent.
#[test]
fn test_entry_remove_not_exists() {
  // Start test OpenLDAP server
  let server =
    TestLdapServer::start().expect("Failed to start test LDAP server");

  let test_id = generate_test_id("remove-noexist");
  println!("Running entry_remove_not_exists test with ID: {}", test_id);

  // Connect to LDAP server
  let config = LdapConnectionConfig::new(
    server.config().url(),
    server.config().admin_dn.clone(),
    server.config().admin_password.clone(),
  );

  let mut ldap = connect(&config).expect("Failed to connect to LDAP server");

  // Initialize base structure
  server
    .initialize_base_structure(&mut ldap)
    .expect("Failed to initialize base structure");

  // Create a DN for an entry that doesn't exist
  let uid = test_record_name(&test_id, "nonexistent");
  let dn = format!("uid={},ou=users,{}", uid, server.config().base_dn);

  // Verify it doesn't exist
  let exists =
    entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
  assert!(!exists, "Entry should not exist initially");
  println!("✓ Verified entry does not exist");

  // Try to remove the non-existent entry - should be idempotent (succeed)
  let result_dn = entry_remove(&mut ldap, &dn)
    .expect("Remove should succeed even if entry doesn't exist (idempotent)");

  println!("✓ Remove succeeded (idempotent): {}", result_dn);
  assert_eq!(result_dn, dn, "DN should match");

  // Verify it still doesn't exist
  let still_not_exists =
    entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
  assert!(!still_not_exists, "Entry should still not exist");
  println!("✓ Entry still does not exist and operation was idempotent");
}

/// Test that retrieves an existing entry's attributes from LDAP.
#[test]
fn test_entry_get_existing() {
  // Start test OpenLDAP server
  let server =
    TestLdapServer::start().expect("Failed to start test LDAP server");

  let test_id = generate_test_id("get-existing");
  println!("Running entry_get test with ID: {}", test_id);

  // Connect to LDAP server
  let config = LdapConnectionConfig::new(
    server.config().url(),
    server.config().admin_dn.clone(),
    server.config().admin_password.clone(),
  );

  let mut ldap = connect(&config).expect("Failed to connect to LDAP server");

  // Initialize base structure
  server
    .initialize_base_structure(&mut ldap)
    .expect("Failed to initialize base structure");

  // Create a test entry
  let uid = test_record_name(&test_id, "dave");
  let dn = format!("uid={},ou=users,{}", uid, server.config().base_dn);

  let attrs = vec![
    (
      "objectClass",
      HashSet::from(["inetOrgPerson", "organizationalPerson", "person", "top"]),
    ),
    ("uid", HashSet::from([uid.as_str()])),
    ("cn", HashSet::from(["Dave Wilson"])),
    ("sn", HashSet::from(["Wilson"])),
    ("mail", HashSet::from(["dave@example.org"])),
    ("userPassword", HashSet::from(["secret123"])),
    ("description", HashSet::from(["Test user for entry_get"])),
  ];

  // Add the entry
  entry_add(&mut ldap, &dn, attrs).expect("Failed to add entry");
  println!("✓ Entry added with DN: {}", dn);

  // Retrieve the entry
  let result = entry_get(&mut ldap, &dn).expect("Failed to get entry");

  match result {
    Some(retrieved_attrs) => {
      println!("✓ Entry retrieved with {} attributes", retrieved_attrs.len());

      // Verify some key attributes exist
      assert!(retrieved_attrs.contains_key("uid"), "Should have uid attribute");
      assert!(retrieved_attrs.contains_key("cn"), "Should have cn attribute");
      assert!(retrieved_attrs.contains_key("sn"), "Should have sn attribute");
      assert!(
        retrieved_attrs.contains_key("mail"),
        "Should have mail attribute"
      );

      // Verify attribute values
      assert_eq!(
        retrieved_attrs.get("uid").map(|v| &v[0]),
        Some(&uid),
        "uid should match"
      );
      assert_eq!(
        retrieved_attrs.get("cn").map(|v| &v[0]),
        Some(&"Dave Wilson".to_string()),
        "cn should match"
      );
      assert_eq!(
        retrieved_attrs.get("sn").map(|v| &v[0]),
        Some(&"Wilson".to_string()),
        "sn should match"
      );
      assert_eq!(
        retrieved_attrs.get("mail").map(|v| &v[0]),
        Some(&"dave@example.org".to_string()),
        "mail should match"
      );

      println!("✓ All attributes verified");
    }
    None => {
      panic!("Entry should exist but entry_get returned None");
    }
  }
}

/// Test that entry_get returns None for non-existent entries.
#[test]
fn test_entry_get_not_exists() {
  // Start test OpenLDAP server
  let server =
    TestLdapServer::start().expect("Failed to start test LDAP server");

  let test_id = generate_test_id("get-noexist");
  println!("Running entry_get_not_exists test with ID: {}", test_id);

  // Connect to LDAP server
  let config = LdapConnectionConfig::new(
    server.config().url(),
    server.config().admin_dn.clone(),
    server.config().admin_password.clone(),
  );

  let mut ldap = connect(&config).expect("Failed to connect to LDAP server");

  // Initialize base structure
  server
    .initialize_base_structure(&mut ldap)
    .expect("Failed to initialize base structure");

  // Create a DN for an entry that doesn't exist
  let uid = test_record_name(&test_id, "nonexistent");
  let dn = format!("uid={},ou=users,{}", uid, server.config().base_dn);

  // Verify it doesn't exist
  let exists =
    entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
  assert!(!exists, "Entry should not exist initially");
  println!("✓ Verified entry does not exist");

  // Try to get the non-existent entry - should return None
  let result = entry_get(&mut ldap, &dn)
    .expect("entry_get should not error on missing entry");

  match result {
    Some(_) => {
      panic!("Entry should not exist but entry_get returned Some");
    }
    None => {
      println!("✓ entry_get correctly returned None for non-existent entry");
    }
  }
}

/// Test that modifies an existing entry's attributes.
#[test]
fn test_entry_modify() {
  // Start test OpenLDAP server
  let server =
    TestLdapServer::start().expect("Failed to start test LDAP server");

  let test_id = generate_test_id("modify-entry");
  println!("Running entry_modify test with ID: {}", test_id);

  // Connect to LDAP server
  let config = LdapConnectionConfig::new(
    server.config().url(),
    server.config().admin_dn.clone(),
    server.config().admin_password.clone(),
  );

  let mut ldap = connect(&config).expect("Failed to connect to LDAP server");

  // Initialize base structure
  server
    .initialize_base_structure(&mut ldap)
    .expect("Failed to initialize base structure");

  // Create a test entry
  let uid = test_record_name(&test_id, "eve");
  let dn = format!("uid={},ou=users,{}", uid, server.config().base_dn);

  let attrs = vec![
    (
      "objectClass",
      HashSet::from(["inetOrgPerson", "organizationalPerson", "person", "top"]),
    ),
    ("uid", HashSet::from([uid.as_str()])),
    ("cn", HashSet::from(["Eve Adams"])),
    ("sn", HashSet::from(["Adams"])),
    ("mail", HashSet::from(["eve@example.org"])),
    ("userPassword", HashSet::from(["oldpassword"])),
    ("description", HashSet::from(["Original description"])),
  ];

  // Add the entry
  entry_add(&mut ldap, &dn, attrs).expect("Failed to add entry");
  println!("✓ Entry added with DN: {}", dn);

  // Get the original entry to verify initial state
  let original = entry_get(&mut ldap, &dn)
    .expect("Failed to get entry")
    .expect("Entry should exist");

  assert_eq!(
    original.get("mail").map(|v| &v[0]),
    Some(&"eve@example.org".to_string()),
    "Original mail should be eve@example.org"
  );
  assert_eq!(
    original.get("description").map(|v| &v[0]),
    Some(&"Original description".to_string()),
    "Original description should match"
  );
  println!("✓ Original entry verified");

  // Modify the entry - replace mail and description, add a new mail value
  let mods = vec![
    Mod::Replace(
      "mail",
      HashSet::from(["eve.adams@example.org", "eve@company.com"]),
    ),
    Mod::Replace("description", HashSet::from(["Updated description"])),
  ];

  let result_dn =
    entry_modify(&mut ldap, &dn, mods).expect("Failed to modify entry");
  println!("✓ Entry modified: {}", result_dn);
  assert_eq!(result_dn, dn, "DN should match");

  // Get the modified entry and verify changes
  let modified = entry_get(&mut ldap, &dn)
    .expect("Failed to get modified entry")
    .expect("Entry should still exist");

  // Verify mail was updated (may be in any order)
  let mail_values = modified.get("mail").expect("Should have mail attribute");
  assert_eq!(mail_values.len(), 2, "Should have 2 mail values");
  assert!(
    mail_values.contains(&"eve.adams@example.org".to_string()),
    "Should have new mail eve.adams@example.org"
  );
  assert!(
    mail_values.contains(&"eve@company.com".to_string()),
    "Should have new mail eve@company.com"
  );

  // Verify description was updated
  assert_eq!(
    modified.get("description").map(|v| &v[0]),
    Some(&"Updated description".to_string()),
    "Description should be updated"
  );

  // Verify other attributes are unchanged
  assert_eq!(
    modified.get("cn").map(|v| &v[0]),
    Some(&"Eve Adams".to_string()),
    "cn should be unchanged"
  );
  assert_eq!(
    modified.get("sn").map(|v| &v[0]),
    Some(&"Adams".to_string()),
    "sn should be unchanged"
  );

  println!("✓ All modifications verified");
}

/// Test that reconciles entries from JSON5 configuration.
/// This tests the full reconciliation flow: create, update, and unchanged entries.
#[test]
fn test_reconcile() {
  // Start test OpenLDAP server
  let server =
    TestLdapServer::start().expect("Failed to start test LDAP server");

  let test_id = generate_test_id("reconcile");
  println!("Running reconcile test with ID: {}", test_id);

  // Connect to LDAP server
  let config = LdapConnectionConfig::new(
    server.config().url(),
    server.config().admin_dn.clone(),
    server.config().admin_password.clone(),
  );

  let mut ldap = connect(&config).expect("Failed to connect to LDAP server");

  // Initialize base structure
  server
    .initialize_base_structure(&mut ldap)
    .expect("Failed to initialize base structure");

  // Create test DNs
  let uid1 = test_record_name(&test_id, "frank");
  let uid2 = test_record_name(&test_id, "grace");
  let dn1 = format!("uid={},ou=users,{}", uid1, server.config().base_dn);
  let dn2 = format!("uid={},ou=users,{}", uid2, server.config().base_dn);

  // Manually create first entry that needs updating
  let attrs1 = vec![
    (
      "objectClass",
      HashSet::from(["inetOrgPerson", "organizationalPerson", "person", "top"]),
    ),
    ("uid", HashSet::from([uid1.as_str()])),
    ("cn", HashSet::from(["Frank Old"])),
    ("sn", HashSet::from(["Old"])),
    ("mail", HashSet::from(["frank.old@example.org"])),
  ];
  entry_add(&mut ldap, &dn1, attrs1).expect("Failed to add initial entry");
  println!("✓ Pre-created entry for update test: {}", dn1);

  // Create JSON5 configuration with desired state
  let json5 = format!(
    r#"{{
            baseDn: "{}",
            entries: {{
                "{}": {{
                    objectClass: ["inetOrgPerson", "organizationalPerson", "person", "top"],
                    uid: "{}",
                    cn: "Frank New",
                    sn: "New",
                    mail: "frank.new@example.org",
                    description: "Updated description"
                }},
                "{}": {{
                    objectClass: ["inetOrgPerson", "organizationalPerson", "person", "top"],
                    uid: "{}",
                    cn: "Grace Harper",
                    sn: "Harper",
                    mail: "grace@example.org",
                    userPassword: {{
                        managed: false,
                        initialValue: "changeme"
                    }}
                }}
            }}
        }}"#,
    server.config().base_dn,
    dn1,
    uid1,
    dn2,
    uid2
  );

  // Parse and reconcile
  let state =
    ReconciledState::from_json5(&json5).expect("Failed to parse JSON5");
  let report = reconcile(&mut ldap, &state).expect("Failed to reconcile");

  println!("Reconciliation report:");
  println!("  Created: {:?}", report.created);
  println!("  Modified: {:?}", report.modified);
  println!("  Unchanged: {:?}", report.unchanged);

  // Verify results
  assert_eq!(report.created.len(), 1, "Should have created 1 entry");
  assert!(report.created.contains(&dn2), "Should have created dn2");

  assert_eq!(report.modified.len(), 1, "Should have modified 1 entry");
  assert!(report.modified.contains_key(&dn1), "Should have modified dn1");

  assert_eq!(report.unchanged.len(), 0, "Should have 0 unchanged entries");

  // Verify the modified entry has new values
  let entry1 = entry_get(&mut ldap, &dn1)
    .expect("Failed to get entry1")
    .expect("Entry1 should exist");

  assert_eq!(
    entry1.get("cn").map(|v| &v[0]),
    Some(&"Frank New".to_string()),
    "cn should be updated"
  );
  assert_eq!(
    entry1.get("mail").map(|v| &v[0]),
    Some(&"frank.new@example.org".to_string()),
    "mail should be updated"
  );
  assert_eq!(
    entry1.get("description").map(|v| &v[0]),
    Some(&"Updated description".to_string()),
    "description should be added"
  );

  // Verify the created entry exists with correct values
  let entry2 = entry_get(&mut ldap, &dn2)
    .expect("Failed to get entry2")
    .expect("Entry2 should exist");

  assert_eq!(
    entry2.get("cn").map(|v| &v[0]),
    Some(&"Grace Harper".to_string()),
    "cn should match"
  );
  assert_eq!(
    entry2.get("mail").map(|v| &v[0]),
    Some(&"grace@example.org".to_string()),
    "mail should match"
  );

  // Run reconcile again - should report everything as unchanged
  let report2 =
    reconcile(&mut ldap, &state).expect("Failed to reconcile second time");
  assert_eq!(
    report2.created.len(),
    0,
    "Should have created 0 entries on second run"
  );
  assert_eq!(
    report2.modified.len(),
    0,
    "Should have modified 0 entries on second run"
  );
  assert_eq!(
    report2.unchanged.len(),
    2,
    "Should have 2 unchanged entries on second run"
  );

  println!("✓ Reconciliation completed successfully");
  println!("✓ Idempotent reconciliation verified");
}

/// Test that DN ordering works: parents are created before children.
/// This test intentionally puts entries in the wrong order in JSON5
/// to verify that reconciliation reorders them correctly.
#[test]
fn test_reconcile_dn_ordering() {
  // Start test OpenLDAP server
  let server =
    TestLdapServer::start().expect("Failed to start test LDAP server");

  let test_id = generate_test_id("dn-ordering");
  println!("Running DN ordering test with ID: {}", test_id);

  // Connect to LDAP server
  let config = LdapConnectionConfig::new(
    server.config().url(),
    server.config().admin_dn.clone(),
    server.config().admin_password.clone(),
  );

  let mut ldap = connect(&config).expect("Failed to connect to LDAP server");

  // Note: We're NOT calling initialize_base_structure here
  // We want to test that reconciliation creates parent entries automatically

  let base_dn = &server.config().base_dn;
  let test_ou = format!("ou=testorg-{}", test_id);
  let test_ou_dn = format!("{},{}", test_ou, base_dn);

  let uid = test_record_name(&test_id, "henry");
  let user_dn = format!("uid={},{}", uid, test_ou_dn);

  // Create JSON5 with entries in WRONG order (child before parent)
  // The reconciliation should handle this automatically
  // Note: We include the base DN itself in the config
  let json5 = format!(
    r#"{{
            baseDn: "{}",
            entries: {{
                // Child entry listed FIRST (wrong order)
                "{}": {{
                    objectClass: ["inetOrgPerson", "organizationalPerson", "person", "top"],
                    uid: "{}",
                    cn: "Henry Taylor",
                    sn: "Taylor",
                    mail: "henry@example.org"
                }},
                // Parent OU listed SECOND (should be created first)
                "{}": {{
                    objectClass: ["organizationalUnit", "top"],
                    ou: "testorg-{}"
                }},
                // Base DN listed LAST (should be created first of all)
                "{}": {{
                    objectClass: ["dcObject", "organization", "top"],
                    dc: "test",
                    o: "Test Organization"
                }}
            }}
        }}"#,
    base_dn, user_dn, uid, test_ou_dn, test_id, base_dn
  );

  println!("JSON5 entry order (intentionally wrong):");
  println!(
    "  1. {} (child - depth {})",
    user_dn,
    user_dn.matches(',').count() + 1
  );
  println!(
    "  2. {} (parent - depth {})",
    test_ou_dn,
    test_ou_dn.matches(',').count() + 1
  );
  println!(
    "  3. {} (base - depth {})",
    base_dn,
    base_dn.matches(',').count() + 1
  );

  // Parse and reconcile - should handle ordering automatically
  let state =
    ReconciledState::from_json5(&json5).expect("Failed to parse JSON5");
  let report = reconcile(&mut ldap, &state).expect("Failed to reconcile");

  println!("\nReconciliation report:");
  println!("  Created: {:?}", report.created);

  // Verify all three entries were created
  assert_eq!(report.created.len(), 3, "Should have created 3 entries");
  assert!(report.created.contains(base_dn), "Should have created base DN");
  assert!(
    report.created.contains(&test_ou_dn),
    "Should have created parent OU"
  );
  assert!(report.created.contains(&user_dn), "Should have created child user");

  // Verify they were created in the correct order by checking the report
  // The created list should have base DN first (shallowest)
  let base_idx = report.created.iter().position(|dn| dn == base_dn).unwrap();
  let ou_idx = report
    .created
    .iter()
    .position(|dn| dn == &test_ou_dn)
    .unwrap();
  let user_idx = report.created.iter().position(|dn| dn == &user_dn).unwrap();

  assert!(base_idx < ou_idx, "Base DN should be created before OU");
  assert!(ou_idx < user_idx, "OU should be created before user");

  println!(
    "✓ Creation order verified: base ({}) -> OU ({}) -> user ({})",
    base_idx, ou_idx, user_idx
  );

  // Verify all entries exist
  let base_exists =
    entry_exists(&mut ldap, base_dn).expect("Failed to check base existence");
  let parent_exists = entry_exists(&mut ldap, &test_ou_dn)
    .expect("Failed to check parent existence");
  let child_exists =
    entry_exists(&mut ldap, &user_dn).expect("Failed to check child existence");

  assert!(base_exists, "Base DN should exist");
  assert!(parent_exists, "Parent OU should exist");
  assert!(child_exists, "Child user should exist");

  // Verify we can retrieve both entries
  let parent_entry = entry_get(&mut ldap, &test_ou_dn)
    .expect("Failed to get parent")
    .expect("Parent should exist");
  assert_eq!(
    parent_entry.get("ou").map(|v| &v[0]),
    Some(&format!("testorg-{}", test_id)),
    "Parent OU attribute should match"
  );

  let child_entry = entry_get(&mut ldap, &user_dn)
    .expect("Failed to get child")
    .expect("Child should exist");
  assert_eq!(
    child_entry.get("cn").map(|v| &v[0]),
    Some(&"Henry Taylor".to_string()),
    "Child cn should match"
  );

  println!("✓ DN ordering verified: parent created before child");
  println!("✓ Both entries created successfully despite wrong JSON5 order");
}
