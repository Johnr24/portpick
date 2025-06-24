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
    /// Update the local nmap-services file from the remote source
    #[clap(short, long)]
    update: bool,

    /// Number of ports to find
    #[clap(short, long, default_value_t = 1)]
    number_of_ports: u16,

    /// Require the found ports to be a continuous block
    #[clap(short, long)]
    continuous: bool,

    /// Output ports in Docker-compose format (e.g., 8080:)
    #[clap(short, long)]
    docker_format: bool,
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

fn find_available_ports(
    forbidden_ports: &HashSet<u16>,
    num_ports: u16,
    continuous: bool,
) -> Vec<u16> {
    let mut found_ports = Vec::new();
    if num_ports == 0 {
        return found_ports;
    }

    let port_ranges = [(1024u16, 49151u16), (49152u16, 65535u16)];

    if continuous {
        for &(start_range, end_range) in &port_ranges {
            // Ensure the block search doesn't go out of u16 bounds or range
            // end_range.saturating_sub(num_ports -1) prevents underflow if num_ports is large
            let effective_end_search = if num_ports > 0 {
                end_range.saturating_sub(num_ports -1)
            } else {
                end_range // Should not happen due to num_ports == 0 check, but defensive
            };

            for p_start in start_range..=effective_end_search {
                let mut block_available = true;
                let mut current_block = Vec::new();
                for i in 0..num_ports {
                    let current_port = p_start + i;
                    // Check if current_port is within the overall valid port range (0-65535)
                    // and not forbidden. p_start + i could exceed u16::MAX if not careful,
                    // but since p_start <= effective_end_search and effective_end_search + num_ports -1 <= end_range <= u16::MAX,
                    // this check is mostly for forbidden_ports.
                    if forbidden_ports.contains(&current_port) {
                        block_available = false;
                        break;
                    }
                    current_block.push(current_port);
                }
                if block_available {
                    return current_block; // Found a continuous block
                }
            }
        }
    } else {
        for &(start_range, end_range) in &port_ranges {
            for port in start_range..=end_range {
                if !forbidden_ports.contains(&port) {
                    found_ports.push(port);
                    if found_ports.len() == num_ports as usize {
                        return found_ports;
                    }
                }
            }
        }
    }
    found_ports // Return what was found, even if less than num_ports
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

    if cli.number_of_ports == 0 {
        println!("\nNumber of ports requested is 0. No ports to find.");
        return Ok(());
    }
    
    // Calculate total number of ports in the search ranges to check against requested number of continuous ports.
    // (1024..=49151) -> 49151 - 1024 + 1 = 48128 ports
    // (49152..=65535) -> 65535 - 49152 + 1 = 16384 ports
    // Total = 48128 + 16384 = 64512 ports. This fits in u16.
    const TOTAL_SEARCHABLE_PORTS: u16 = (49151u16 - 1024u16 + 1u16) + (65535u16 - 49152u16 + 1u16);
    if cli.continuous && cli.number_of_ports > 1 && TOTAL_SEARCHABLE_PORTS < cli.number_of_ports {
        // Basic check if requested number of continuous ports can even exist in the searched ranges
        println!("\nWarning: Requested number of continuous ports ({}) is very large and might not be possible to find as it exceeds the total number of searchable ports ({}).", cli.number_of_ports, TOTAL_SEARCHABLE_PORTS);
    }


    let available_ports = find_available_ports(&forbidden_ports, cli.number_of_ports, cli.continuous);

    if available_ports.is_empty() {
        println!("\nCould not find {} {}available port(s) in the checked ranges.", 
            cli.number_of_ports, 
            if cli.continuous {"continuous "} else {""});
    } else if cli.continuous && available_ports.len() < cli.number_of_ports as usize {
        // This case implies we couldn't find the full continuous block requested.
        // The message should reflect that.
        // If docker_format is true, we still print what was found in that format.
        println!("\nCould not find a continuous block of {} ports. Found {} available port(s) instead:", cli.number_of_ports, available_ports.len());
        for port in available_ports {
            if cli.docker_format {
                println!("{}:", port);
            } else {
                println!("- {}", port);
            }
        }
    } 
    else if !cli.continuous && available_ports.len() < cli.number_of_ports as usize {
        println!("\nFound {} out of {} requested available port(s):", available_ports.len(), cli.number_of_ports);
        for port in available_ports {
            if cli.docker_format {
                println!("{}:", port);
            } else {
                println!("- {}", port);
            }
        }
    }
    else { // Found all requested ports
        println!("\nSuggested available port(s):");
        for port in available_ports {
            if cli.docker_format {
                println!("{}:", port);
            } else {
                println!("- {}", port);
            }
        }
    }

    Ok(())
}
