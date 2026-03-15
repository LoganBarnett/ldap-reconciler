mod common;

use common::{generate_test_id, test_record_name, TestLdapServer};
use ldap_reconciler_lib::{connect, entry_add, entry_exists, entry_get, entry_modify, entry_remove, LdapConnectionConfig, Mod};
use std::collections::HashSet;

/// Canary test that verifies we can:
/// 1. Start an OpenLDAP server
/// 2. Connect to it
/// 3. Authenticate
/// 4. Shut it down cleanly
#[test]
fn canary_ldap_connection() {
    // Start test OpenLDAP server
    let server = TestLdapServer::start().expect("Failed to start test LDAP server");

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
    let server = TestLdapServer::start().expect("Failed to start test LDAP server");

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
    let result_dn = entry_add(&mut ldap, &dn, attrs).expect("Failed to add entry");

    println!("✓ Entry added with DN: {}", result_dn);

    // Verify the entry exists
    let exists = entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");

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
    let server = TestLdapServer::start().expect("Failed to start test LDAP server");

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
    let result_dn =
        entry_add(&mut ldap, &dn, attrs.clone()).expect("Failed to add entry the first time");

    println!("✓ Entry added with DN: {}", result_dn);

    // Verify it exists
    let exists = entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
    assert!(exists, "Entry should exist after first add");
    println!("✓ Entry verified to exist after first add");

    // Try to add the same entry again - this should be idempotent (succeed without error)
    let result_dn2 =
        entry_add(&mut ldap, &dn, attrs).expect("Second add should succeed (idempotent)");

    println!("✓ Second add succeeded (idempotent): {}", result_dn2);
    assert_eq!(result_dn2, dn, "DN should match on second add");

    // Verify the entry still exists
    let still_exists = entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
    assert!(still_exists, "Entry should still exist after second add");
    println!("✓ Entry still exists and operation was idempotent");
}

/// Test that removes an existing entry from LDAP.
#[test]
fn test_entry_remove() {
    // Start test OpenLDAP server
    let server = TestLdapServer::start().expect("Failed to start test LDAP server");

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
    let exists = entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
    assert!(exists, "Entry should exist before removal");
    println!("✓ Entry verified to exist before removal");

    // Remove the entry
    let result_dn = entry_remove(&mut ldap, &dn).expect("Failed to remove entry");

    println!("✓ Entry removed with DN: {}", result_dn);
    assert_eq!(result_dn, dn, "DN should match");

    // Verify it no longer exists
    let still_exists = entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
    assert!(!still_exists, "Entry should not exist after removal");
    println!("✓ Entry verified to be removed");
}

/// Test that removing an entry that doesn't exist is idempotent.
#[test]
fn test_entry_remove_not_exists() {
    // Start test OpenLDAP server
    let server = TestLdapServer::start().expect("Failed to start test LDAP server");

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
    let exists = entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
    assert!(!exists, "Entry should not exist initially");
    println!("✓ Verified entry does not exist");

    // Try to remove the non-existent entry - should be idempotent (succeed)
    let result_dn = entry_remove(&mut ldap, &dn)
        .expect("Remove should succeed even if entry doesn't exist (idempotent)");

    println!("✓ Remove succeeded (idempotent): {}", result_dn);
    assert_eq!(result_dn, dn, "DN should match");

    // Verify it still doesn't exist
    let still_not_exists = entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
    assert!(!still_not_exists, "Entry should still not exist");
    println!("✓ Entry still does not exist and operation was idempotent");
}

/// Test that retrieves an existing entry's attributes from LDAP.
#[test]
fn test_entry_get_existing() {
    // Start test OpenLDAP server
    let server = TestLdapServer::start().expect("Failed to start test LDAP server");

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
            assert!(retrieved_attrs.contains_key("mail"), "Should have mail attribute");

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
    let server = TestLdapServer::start().expect("Failed to start test LDAP server");

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
    let exists = entry_exists(&mut ldap, &dn).expect("Failed to check if entry exists");
    assert!(!exists, "Entry should not exist initially");
    println!("✓ Verified entry does not exist");

    // Try to get the non-existent entry - should return None
    let result = entry_get(&mut ldap, &dn).expect("entry_get should not error on missing entry");

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
    let server = TestLdapServer::start().expect("Failed to start test LDAP server");

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
        Mod::Replace("mail", HashSet::from(["eve.adams@example.org", "eve@company.com"])),
        Mod::Replace("description", HashSet::from(["Updated description"])),
    ];

    let result_dn = entry_modify(&mut ldap, &dn, mods).expect("Failed to modify entry");
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
