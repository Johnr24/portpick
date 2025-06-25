use assert_cmd::prelude::*; // Add methods on commands
use predicates::prelude::*; // Used for writing assertions
use std::process::Command; // Used to run the binary
use std::collections::HashSet;
use portpick::{parse_services_content, find_available_ports}; // Import functions from your crate

// --- Start of moved unit tests ---
#[test]
fn test_parse_services_content_empty() {
    let content = "";
    let ports = parse_services_content(content, "test_empty", false).unwrap();
    assert!(ports.is_empty());
}

#[test]
fn test_parse_services_content_comments_and_blank_lines() {
    let content = "# This is a comment\n\n  # Another comment\n  \n";
    let ports = parse_services_content(content, "test_comments", false).unwrap();
    assert!(ports.is_empty());
}

#[test]
fn test_parse_services_content_valid_tcp() {
    let content = "service1\t80/tcp\nservice2   100/tcp # comment\nservice3 200/tcp";
    let ports = parse_services_content(content, "test_valid_tcp", false).unwrap();
    assert_eq!(ports.len(), 3);
    assert!(ports.contains(&80));
    assert!(ports.contains(&100));
    assert!(ports.contains(&200));
}

#[test]
fn test_parse_services_content_ignore_udp_and_unknown() {
    let content = "service_tcp\t80/tcp\nservice_udp\t53/udp\nunknown\t123/tcp\nvalid_service 443/tcp";
    let ports = parse_services_content(content, "test_ignore_udp_unknown", false).unwrap();
    assert_eq!(ports.len(), 2);
    assert!(ports.contains(&80));
    assert!(ports.contains(&443));
    assert!(!ports.contains(&53));
    assert!(!ports.contains(&123));
}

#[test]
fn test_parse_services_content_mixed_delimiters() {
    let content = "http\t80/tcp\nhttps  443/tcp\nssh 22/tcp # Secure Shell";
    let ports = parse_services_content(content, "test_mixed_delimiters", false).unwrap();
    assert_eq!(ports.len(), 3);
    assert!(ports.contains(&80));
    assert!(ports.contains(&443));
    assert!(ports.contains(&22));
}

#[test]
fn test_find_available_ports_single() {
    let mut forbidden = HashSet::new();
    forbidden.insert(1024);
    forbidden.insert(1025);
    let available = find_available_ports(&forbidden, 1, false);
    assert_eq!(available.len(), 1);
    assert_eq!(available[0], 1026);
}

#[test]
fn test_find_available_ports_multiple_non_continuous() {
    let mut forbidden = HashSet::new();
    forbidden.insert(1024);
    forbidden.insert(1026);
    let available = find_available_ports(&forbidden, 2, false);
    assert_eq!(available.len(), 2);
    assert_eq!(available[0], 1025);
    assert_eq!(available[1], 1027);
}

#[test]
fn test_find_available_ports_continuous() {
    let mut forbidden = HashSet::new();
    forbidden.insert(1024);
    forbidden.insert(1027); // Gap between 1026 and 1028
    let available = find_available_ports(&forbidden, 3, true);
    assert_eq!(available.len(), 3);
    assert_eq!(available, vec![1028, 1029, 1030]);
}

#[test]
fn test_find_available_ports_continuous_at_range_boundary() {
    let mut forbidden = HashSet::new();
    // Forbid all but the last 3 ports in the first range
    for p in 1024..(49151 - 2) {
        forbidden.insert(p);
    }
    let available = find_available_ports(&forbidden, 3, true);
    assert_eq!(available.len(), 3);
    assert_eq!(available, vec![49149, 49150, 49151]);
}

#[test]
fn test_find_available_ports_none_available_in_range() {
    let mut forbidden = HashSet::new();
    for port in 1024..=65535 { // Forbid all possible ports
        forbidden.insert(port);
    }
    let available = find_available_ports(&forbidden, 1, false);
    assert!(available.is_empty());
}

#[test]
fn test_find_available_ports_num_ports_zero() {
    let forbidden = HashSet::new();
    let available = find_available_ports(&forbidden, 0, false);
    assert!(available.is_empty());
    let available_continuous = find_available_ports(&forbidden, 0, true);
    assert!(available_continuous.is_empty());
}

#[test]
fn test_find_available_ports_prefer_registered_range() {
    let forbidden = HashSet::new(); // No ports forbidden initially
    let available = find_available_ports(&forbidden, 1, false);
    assert_eq!(available.len(), 1);
    assert!(available[0] >= 1024 && available[0] <= 49151);
    assert_eq!(available[0], 1024); // Specifically, the first one
}

#[test]
fn test_find_available_ports_fallback_to_dynamic_range() {
    let mut forbidden = HashSet::new();
    for port in 1024..=49151 { // Forbid all registered ports
        forbidden.insert(port);
    }
    let available = find_available_ports(&forbidden, 1, false);
    assert_eq!(available.len(), 1);
    assert!(available[0] >= 49152); // The check for <= 65535 is redundant for u16
    assert_eq!(available[0], 49152); // Specifically, the first one in this range
}
 #[test]
fn test_find_available_ports_continuous_block_too_large() {
    let forbidden = HashSet::new();
    // Request more ports than available in any single continuous block in the ranges
    let num_ports_too_large = (49151 - 1024 + 1) + (65535 - 49152 + 1) + 100; // Larger than total
    let available = find_available_ports(&forbidden, num_ports_too_large, true);
    assert!(available.is_empty(), "Should not find a block larger than total available ports");
}
// --- End of moved unit tests ---


// --- Start of CLI integration tests ---
#[test]
fn test_cli_help() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("portpick")?;
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("portpick [OPTIONS]"))
        .stdout(predicate::str::contains("--universal"))
        .stdout(predicate::str::contains("--local"))
        .stdout(predicate::str::contains("--number-of-ports"))
        .stdout(predicate::str::contains("--force"))
        .stdout(predicate::str::contains("--help"));
    Ok(())
}

#[test]
fn test_cli_default_one_port() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("portpick")?;
    cmd.arg("--force");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Suggested available port(s):"))
        .stdout(predicate::str::is_match(r"- \s*\d{4,5}\s*").unwrap()); // Matches "- 1234" or "- 12345"
    Ok(())
}

#[test]
fn test_cli_number_of_ports_3() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("portpick")?;
    cmd.args(["-n", "3", "--force"]);
    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone())?;
    assert!(stdout.contains("Suggested available port(s):"));
    // Check for 3 lines starting with "- " followed by a port
    let port_lines = stdout.lines().filter(|line| line.trim().starts_with("- ")).count();
    assert_eq!(port_lines, 3, "Expected 3 ports to be suggested, found {}", port_lines);
    Ok(())
}

#[test]
fn test_cli_continuous_2_ports() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("portpick")?;
    cmd.args(["-n", "2", "-c", "--force"]);
    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone())?;
    assert!(stdout.contains("Suggested available port(s):"));
    
    let ports: Vec<u16> = stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- "))
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    assert_eq!(ports.len(), 2, "Expected 2 ports, found {}", ports.len());
    if ports.len() == 2 {
        assert_eq!(ports[1], ports[0] + 1, "Ports are not continuous: {:?}", ports);
    }
    Ok(())
}

#[test]
fn test_cli_docker_format() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("portpick")?;
    cmd.args(["-n", "1", "-d", "--force"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Suggested available port(s):"))
        .stdout(predicate::str::is_match(r"\d{4,5}:\s*").unwrap()); // Matches "12345:"
    Ok(())
}

#[test]
fn test_cli_verbose_output() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("portpick")?;
    cmd.args(["-v", "--force"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Total")) // A string typical of verbose output
        .stdout(predicate::str::contains("forbidden ports collected."));
    Ok(())
}

#[test]
fn test_cli_local_flag() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("portpick")?;
    cmd.args(["--local", "-v", "--force"]); // Use verbose to check which path it attempts
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Default mode: Attempting to use system services file: /etc/services"));
    Ok(())
}

// Test for --universal. This test will attempt a network request.
// It also creates/modifies src/nmap-services.cache
// Ensure this is acceptable in your test environment.
#[test]
#[ignore] // Ignored by default as it performs network I/O and file system I/O
fn test_cli_universal_flag_network_and_cache() -> Result<(), Box<dyn std::error::Error>> {
    let cache_file = "src/nmap-services.cache";
    // Clean up cache file before test if it exists
    let _ = std::fs::remove_file(cache_file);

    let mut cmd = Command::cargo_bin("portpick")?;
    cmd.args(["--universal", "-v"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Universal Nmap services flag set"))
        .stdout(predicate::str::contains("Fetching Nmap services data"))
        .stdout(predicate::str::contains("Successfully cached Nmap services to src/nmap-services.cache"));
    
    // Verify cache file was created
    assert!(std::path::Path::new(cache_file).exists(), "Cache file was not created");

    // Run again, should use cache if --universal is not specified
    let mut cmd2 = Command::cargo_bin("portpick")?;
    cmd2.arg("-v"); // No --universal
    cmd2.assert()
        .success()
        .stdout(predicate::str::contains("Using cached Nmap services from src/nmap-services.cache"));

    // Clean up cache file after test
    let _ = std::fs::remove_file(cache_file);
    Ok(())
}

#[test]
fn test_cli_universal_and_local_warning() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("portpick")?;
    cmd.args(["-u", "--local", "-v", "--force"]);
    cmd.assert()
        .success() // Command should still succeed
        .stderr(predicate::str::contains("Warning: --universal and --local flags were both specified. --universal takes precedence."));
    Ok(())
}

#[test]
fn test_cli_no_ports_found_message() -> Result<(), Box<dyn std::error::Error>> {
    // This test is tricky because it depends on all ports being actually in use or forbidden.
    // We can't easily simulate this for a CLI test without mocking lsof and /etc/services.
    // For now, we'll test the "number_of_ports: 0" case which has a specific message.
    let mut cmd = Command::cargo_bin("portpick")?;
    cmd.args(["-n", "0"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Number of ports requested is 0. No ports to find."));
    Ok(())
}

// Note: Testing the --force flag's behavior when lsof *actually* fails is hard
// because we can't easily make lsof fail in a controlled way in a test.
// This test primarily checks that the flag is accepted and the program
// attempts to run, rather than verifying the lsof bypass directly.
// A more robust test would involve mocking the lsof command.
#[test]
fn test_cli_force_flag_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("portpick")?;
    cmd.args(["-f", "-n", "1"]); // Request one port with force
    cmd.assert()
        .success() // Expect success even if lsof *were* to fail (though it probably won't here)
        .stdout(predicate::str::contains("Suggested available port(s):"));
    Ok(())
}
// --- End of CLI integration tests ---
