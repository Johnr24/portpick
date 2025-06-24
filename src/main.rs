use anyhow::{Context, Result, anyhow};
use clap::Parser;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::process::Command;
use std::str::FromStr;

const LOCAL_IANA_CSV_PATH: &str = "src/service-names-port-numbers.csv";
const REMOTE_IANA_CSV_URL: &str = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Update the local IANA port assignments CSV from the remote source
    #[clap(short, long)]
    update: bool,
}

// Regex to capture port numbers and ranges from CSV "Port Number" column
// Handles single ports like "80" and ranges like "1024-1028"
static PORT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*(\d{1,5})\s*-\s*(\d{1,5})\s*$|^\s*(\d{1,5})\s*$").unwrap());

// Regex to capture listening ports from lsof output (e.g., *:80, 127.0.0.1:8080)
static LSOF_PORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r":(\d{1,5})\s*\(LISTEN\)$").unwrap());

fn read_local_iana_ports() -> Result<HashSet<u16>> {
    println!("Reading port data from local IANA CSV: {}", LOCAL_IANA_CSV_PATH);
    let csv_content = fs::read_to_string(LOCAL_IANA_CSV_PATH)
        .with_context(|| format!("Failed to read local IANA CSV file at '{}'", LOCAL_IANA_CSV_PATH))?;
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

fn fetch_remote_iana_csv() -> Result<String> {
    println!("Fetching IANA port data from: {}", REMOTE_IANA_CSV_URL);
    let response = reqwest::blocking::get(REMOTE_IANA_CSV_URL)
        .context("Failed to send request to IANA URL")?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to download IANA CSV. Status: {}",
            response.status()
        ));
    }
    response
        .text()
        .context("Failed to read response text from IANA URL")
}

fn save_iana_csv(content: &str) -> Result<()> {
    println!("Saving IANA port data to: {}", LOCAL_IANA_CSV_PATH);
    fs::write(LOCAL_IANA_CSV_PATH, content)
        .with_context(|| format!("Failed to write IANA CSV to '{}'", LOCAL_IANA_CSV_PATH))
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
    let cli = Cli::parse();
    let mut forbidden_ports = HashSet::new();

    if cli.update {
        println!("Update flag set. Attempting to update IANA port assignments...");
        match fetch_remote_iana_csv() {
            Ok(csv_content) => {
                match save_iana_csv(&csv_content) {
                    Ok(_) => println!("Successfully updated local IANA CSV: {}", LOCAL_IANA_CSV_PATH),
                    Err(e) => {
                        eprintln!("Error saving updated IANA CSV: {}. Proceeding with existing local data if available.", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error fetching remote IANA CSV: {}. Proceeding with existing local data if available.", e);
            }
        }
    }

    match read_local_iana_ports() {
        Ok(iana_ports) => {
            forbidden_ports.extend(iana_ports);
        }
        Err(e) => {
            // If update was requested and failed, this error might be more critical.
            // However, the original behavior was to warn and proceed.
            eprintln!("Warning: Could not read or parse local IANA CSV: {}", e);
            eprintln!("Proceeding with local ports only, but results might be less reliable.");
            // If cli.update was true, we might want to be stricter here,
            // but for now, we'll keep the original fallback behavior.
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
