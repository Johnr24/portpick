use anyhow::{Context, Result, anyhow};
use clap::Parser;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::process::Command;
use std::str::FromStr;

const LOCAL_NMAP_SERVICES_PATH: &str = "src/nmap-services";
const REMOTE_NMAP_SERVICES_URL: &str = "https://svn.nmap.org/nmap/nmap-services";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Update the local IANA port assignments CSV from the remote source
    #[clap(short, long)]
    update: bool,
}

// Regex to capture listening ports from lsof output (e.g., *:80, 127.0.0.1:8080)
static LSOF_PORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r":(\d{1,5})\s*\(LISTEN\)$").unwrap());

fn read_local_nmap_services() -> Result<HashSet<u16>> {
    println!("Reading port data from local nmap-services file: {}", LOCAL_NMAP_SERVICES_PATH);
    let file_content = fs::read_to_string(LOCAL_NMAP_SERVICES_PATH)
        .with_context(|| format!("Failed to read local nmap-services file at '{}'", LOCAL_NMAP_SERVICES_PATH))?;
    println!("Parsing nmap-services data...");

    let mut ports = HashSet::new();
    for line in file_content.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.starts_with('#') || trimmed_line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed_line.split('\t').collect();
        if parts.len() < 2 {
            continue; // Not enough parts for service name and port/protocol
        }

        let service_name = parts[0];
        if service_name.to_lowercase() == "unknown" {
            continue;
        }

        let port_protocol_pair: Vec<&str> = parts[1].split('/').collect();
        if port_protocol_pair.len() == 2 {
            let port_str = port_protocol_pair[0];
            let protocol_str = port_protocol_pair[1];

            if protocol_str.to_lowercase() == "tcp" {
                if let Ok(port) = u16::from_str(port_str) {
                    ports.insert(port);
                }
            }
        }
    }
    println!("Found {} distinct TCP ports from nmap-services file.", ports.len());
    Ok(ports)
}

fn fetch_remote_nmap_services() -> Result<String> {
    println!("Fetching nmap-services data from: {}", REMOTE_NMAP_SERVICES_URL);
    
    let client = reqwest::blocking::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        .build()
        .context("Failed to build reqwest client")?;

    let response = client.get(REMOTE_NMAP_SERVICES_URL)
        .send()
        .context("Failed to send request to nmap-services URL")?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to download nmap-services file. Status: {}",
            response.status()
        ));
    }
    response
        .text()
        .context("Failed to read response text from nmap-services URL")
}

fn save_nmap_services_file(content: &str) -> Result<()> {
    println!("Saving nmap-services data to: {}", LOCAL_NMAP_SERVICES_PATH);
    fs::write(LOCAL_NMAP_SERVICES_PATH, content)
        .with_context(|| format!("Failed to write nmap-services file to '{}'", LOCAL_NMAP_SERVICES_PATH))
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
    // Prefer registered ports first (1024-49151)
    // Avoiding well-known ports (0-1023)
    for port in 1024..=49151 {
        if !forbidden_ports.contains(&port) {
            return Some(port);
        }
    }

    // Then try dynamic/private ports (49152-65535)
    for port in 49152..=65535 {
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
        println!("Update flag set. Attempting to update nmap-services file...");
        match fetch_remote_nmap_services() {
            Ok(file_content) => {
                match save_nmap_services_file(&file_content) {
                    Ok(_) => println!("Successfully updated local nmap-services file: {}", LOCAL_NMAP_SERVICES_PATH),
                    Err(e) => {
                        eprintln!("Error saving updated nmap-services file: {}. Proceeding with existing local data if available.", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error fetching remote nmap-services file: {}. Proceeding with existing local data if available.", e);
            }
        }
    }

    match read_local_nmap_services() {
        Ok(nmap_ports) => {
            forbidden_ports.extend(nmap_ports);
        }
        Err(e) => {
            eprintln!("Warning: Could not read or parse local nmap-services file: {}", e);
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
