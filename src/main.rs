use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::process::Command;
use std::str::FromStr;

const IANA_CSV_URL: &str = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv";

// Regex to capture port numbers and ranges from CSV "Port Number" column
// Handles single ports like "80" and ranges like "1024-1028"
static PORT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*(\d{1,5})\s*-\s*(\d{1,5})\s*$|^\s*(\d{1,5})\s*$").unwrap());

// Regex to capture listening ports from lsof output (e.g., *:80, 127.0.0.1:8080)
static LSOF_PORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r":(\d{1,5})\s*\(LISTEN\)$").unwrap());

fn fetch_iana_ports() -> Result<HashSet<u16>> {
    println!("Fetching port data from IANA CSV...");
    let response = reqwest::blocking::get(IANA_CSV_URL)?;
    let csv_content = response.text()?;
    println!("Parsing IANA CSV port data...");

    let mut ports = HashSet::new();
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(csv_content.as_bytes());

    // Get header positions
    let headers = rdr.headers()?.clone();
    let port_number_idx = headers.iter().position(|h| h == "Port Number");

    if port_number_idx.is_none() {
        return Err(anyhow::anyhow!("Could not find 'Port Number' column in IANA CSV."));
    }
    let port_number_idx = port_number_idx.unwrap();

    for result in rdr.records() {
        let record = result?;
        if let Some(port_str) = record.get(port_number_idx) {
            if port_str.trim().is_empty() {
                continue;
            }
            if let Some(captures) = PORT_RE.captures(port_str.trim()) {
                if let Some(single_port_match) = captures.get(3) {
                    if let Ok(port) = u16::from_str(single_port_match.as_str()) {
                        ports.insert(port);
                    }
                } else if let (Some(start_port_match), Some(end_port_match)) =
                    (captures.get(1), captures.get(2))
                {
                    if let (Ok(start_port), Ok(end_port)) = (
                        u16::from_str(start_port_match.as_str()),
                        u16::from_str(end_port_match.as_str()),
                    ) {
                        if start_port <= end_port { // Ensure valid range
                            for port in start_port..=end_port {
                                ports.insert(port);
                            }
                        }
                    }
                }
            }
        }
    }
    println!("Found {} distinct ports/port ranges from IANA CSV.", ports.len());
    Ok(ports)
}

fn get_locally_used_ports() -> Result<HashSet<u16>> {
    println!("Fetching locally used TCP ports...");
    let output = Command::new("lsof")
        .args(["-iTCP", "-sTCP:LISTEN", "-P", "-n"])
        .output()
        .context("Failed to execute lsof command. Make sure lsof is installed and in PATH.")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "lsof command failed with status: {}\nStderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut ports = HashSet::new();

    for line in output_str.lines() {
        if let Some(captures) = LSOF_PORT_RE.captures(line) {
            if let Some(port_match) = captures.get(1) {
                if let Ok(port) = u16::from_str(port_match.as_str()) {
                    ports.insert(port);
                }
            }
        }
    }
    println!("Found {} locally listening TCP ports.", ports.len());
    Ok(ports)
}

fn find_available_port(forbidden_ports: &HashSet<u16>) -> Option<u16> {
    // Prefer dynamic/private ports first (49152-65535)
    for port in 49152..=65535 {
        if !forbidden_ports.contains(&port) {
            return Some(port);
        }
    }

    // Then try registered ports (1024-49151)
    // Avoiding well-known ports (0-1023)
    for port in 1024..=49151 {
        if !forbidden_ports.contains(&port) {
            return Some(port);
        }
    }
    None
}

fn main() -> Result<()> {
    let mut forbidden_ports = HashSet::new();

    match fetch_iana_ports() {
        Ok(iana_ports) => {
            forbidden_ports.extend(iana_ports);
        }
        Err(e) => {
            eprintln!("Warning: Could not fetch or parse IANA CSV ports: {}", e);
            eprintln!("Proceeding with local ports only, but results might be less reliable.");
        }
    }

    match get_locally_used_ports() {
        Ok(local_ports) => {
            forbidden_ports.extend(local_ports);
        }
        Err(e) => {
            // If lsof fails, we can't reliably check local ports.
            // It's safer to error out or provide a strong warning.
            return Err(e.context("Failed to get locally used ports. Cannot reliably find an available port."));
        }
    }
    
    println!("Total {} forbidden ports collected.", forbidden_ports.len());

    if let Some(available_port) = find_available_port(&forbidden_ports) {
        println!("\nSuggested available port: {}", available_port);
    } else {
        println!("\nCould not find an available port in the checked ranges.");
    }

    Ok(())
}
