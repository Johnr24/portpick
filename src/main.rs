use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom; // For randomly selecting a color
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::process::Command;
use std::str::FromStr;

const SYSTEM_SERVICES_PATH: &str = "/etc/services"; // Standard path for system services file
const REMOTE_NMAP_SERVICES_URL: &str = "https://svn.nmap.org/nmap/nmap-services"; // URL for official Nmap services
const LOCAL_NMAP_CACHE_PATH: &str = "src/nmap-services.cache"; // Path for the local Nmap services cache

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Use the universal Nmap services list (fetches from internet, updates local cache)
    #[clap(short, long)]
    universal: bool,

    /// Number of ports to find
    #[clap(short, long, default_value_t = 1)]
    number_of_ports: u16,

    /// Require the found ports to be a continuous block
    #[clap(short, long)]
    continuous: bool,

    /// Output ports in Docker-compose format (e.g., 8080:)
    #[clap(short, long)]
    docker_format: bool,

    /// Enable verbose output
    #[clap(short, long)]
    verbose: bool,
}

// Regex to capture listening ports from lsof output (e.g., *:80, 127.0.0.1:8080)
static LSOF_PORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r":(\d{1,5})\s*\(LISTEN\)$").unwrap());

fn parse_services_content(content: &str, source_description: &str, verbose: bool) -> Result<HashSet<u16>> {
    if verbose {
        println!("{}", format!("Parsing services data from {}...", source_description).cyan());
    }
    let mut ports = HashSet::new();
    for line in content.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.starts_with('#') || trimmed_line.is_empty() {
            continue;
        }

        // Use split_whitespace() for flexibility with /etc/services and nmap-services
        let parts: Vec<&str> = trimmed_line.split_whitespace().collect();
        if parts.len() < 2 { // Need at least service_name and port/protocol
            continue;
        }

        let service_name = parts[0];
        if service_name.to_lowercase() == "unknown" { // Ignore "unknown" services
            continue;
        }

        let port_protocol_str = parts[1]; // This should be "port/protocol"
        let port_protocol_pair: Vec<&str> = port_protocol_str.split('/').collect();
        if port_protocol_pair.len() == 2 {
            let port_str = port_protocol_pair[0];
            let protocol_str = port_protocol_pair[1];

            if protocol_str.to_lowercase() == "tcp" { // Only interested in TCP ports
                if let Ok(port) = u16::from_str(port_str) {
                    ports.insert(port);
                }
            }
        }
    }
    if verbose {
        println!("{}", format!("Found {} distinct TCP ports from {}.", ports.len(), source_description).cyan());
    }
    Ok(ports)
}

fn read_system_services_ports(verbose: bool) -> Result<HashSet<u16>> {
    if verbose {
        println!("{}", format!("Reading port data from system services file: {}", SYSTEM_SERVICES_PATH).cyan());
    }
    let file_content = fs::read_to_string(SYSTEM_SERVICES_PATH)
        .with_context(|| format!("Failed to read system services file at '{}'", SYSTEM_SERVICES_PATH))?;
    parse_services_content(&file_content, "system services file", verbose)
}

fn save_nmap_cache(content: &str, verbose: bool) -> Result<()> {
    if verbose {
        println!("{}", format!("Caching Nmap services data to: {}", LOCAL_NMAP_CACHE_PATH).cyan());
    }
    fs::write(LOCAL_NMAP_CACHE_PATH, content)
        .with_context(|| format!("Failed to write Nmap services cache to '{}'", LOCAL_NMAP_CACHE_PATH))
}

fn fetch_remote_nmap_services(verbose: bool) -> Result<String> {
    if verbose {
        println!("{}", format!("Fetching Nmap services data from: {}", REMOTE_NMAP_SERVICES_URL).cyan());
    }
    
    let client = reqwest::blocking::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        .build()
        .context("Failed to build reqwest client")?;

    let response = client.get(REMOTE_NMAP_SERVICES_URL)
        .send()
        .context("Failed to send request to nmap-services URL")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to download nmap-services file. Status: {}",
            response.status()
        ));
    }
    response
        .text()
        .context("Failed to read response text from nmap-services URL")
}

fn get_locally_used_ports(verbose: bool) -> Result<HashSet<u16>> {
    if verbose {
        println!("{}", "Fetching locally used TCP ports...".cyan());
    }
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
    if verbose {
        println!("{}", format!("Found {} locally listening TCP ports.", ports.len()).cyan());
    }
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

    if cli.universal {
        if cli.verbose {
            println!("{}", format!("Universal Nmap services flag set. Attempting to fetch, cache, and parse Nmap services list from {}...", REMOTE_NMAP_SERVICES_URL).cyan());
        }
        match fetch_remote_nmap_services(cli.verbose) {
            Ok(nmap_content) => {
                // Attempt to save to cache, issue warning on failure but proceed
                if let Err(e) = save_nmap_cache(&nmap_content, cli.verbose) {
                    eprintln!("{}", format!("Warning: Failed to save fetched Nmap services to cache at {}: {}", LOCAL_NMAP_CACHE_PATH, e).yellow());
                } else {
                    if cli.verbose {
                        println!("{}", format!("Successfully cached Nmap services to {}", LOCAL_NMAP_CACHE_PATH).green());
                    }
                }
                // Parse the fetched content
                match parse_services_content(&nmap_content, "fetched Nmap services list", cli.verbose) {
                    Ok(nmap_ports) => forbidden_ports.extend(nmap_ports),
                    Err(e) => return Err(e.context("Failed to parse fetched Nmap services content.")),
                }
            }
            Err(e) => return Err(e.context("Failed to fetch remote Nmap services as requested by --universal flag.")),
        }
    } else {
        // Default: Try local cache first, then system services file
        match fs::read_to_string(LOCAL_NMAP_CACHE_PATH) {
            Ok(cached_content) => {
                if cli.verbose {
                    println!("{}", format!("Using cached Nmap services from {}", LOCAL_NMAP_CACHE_PATH).cyan());
                }
                match parse_services_content(&cached_content, "cached Nmap services list", cli.verbose) {
                    Ok(cached_ports) => forbidden_ports.extend(cached_ports),
                    Err(e) => {
                        eprintln!("{}", format!("Warning: Failed to parse cached Nmap services from {}: {}. Falling back to system services file.", LOCAL_NMAP_CACHE_PATH, e).yellow());
                        // Fallback to system services
                        match read_system_services_ports(cli.verbose) {
                            Ok(system_ports) => forbidden_ports.extend(system_ports),
                            Err(e_sys) => {
                                eprintln!("{}", format!("Warning: Could not read or parse system services file ({}): {}", SYSTEM_SERVICES_PATH, e_sys).yellow());
                                eprintln!("{}", "Proceeding with locally used ports only. Port suggestions might be less reliable.".yellow());
                            }
                        }
                    }
                }
            }
            Err(_) => { // Cache not found or unreadable, try system services
                if cli.verbose {
                    println!("{}", format!("Local Nmap cache not found or unreadable at {}. Attempting to use system services file: {}", LOCAL_NMAP_CACHE_PATH, SYSTEM_SERVICES_PATH).cyan());
                }
                match read_system_services_ports(cli.verbose) {
                    Ok(system_ports) => forbidden_ports.extend(system_ports),
                    Err(e_sys) => {
                        eprintln!("{}", format!("Warning: Could not read or parse system services file ({}): {}", SYSTEM_SERVICES_PATH, e_sys).yellow());
                        eprintln!("{}", "Proceeding with locally used ports only. Port suggestions might be less reliable.".yellow());
                    }
                }
            }
        }
    }

    match get_locally_used_ports(cli.verbose) {
        Ok(local_ports) => {
            forbidden_ports.extend(local_ports);
        }
        Err(e) => {
            // If lsof fails, we can't reliably check local ports.
            // It's safer to error out or provide a strong warning.
            return Err(e.context("Failed to get locally used ports. Cannot reliably find an available port."));
        }
    }
    
    if cli.verbose {
        println!("{}", format!("Total {} forbidden ports collected.", forbidden_ports.len()).cyan());
    }

    if cli.number_of_ports == 0 {
        println!("{}", "\nNumber of ports requested is 0. No ports to find.".yellow());
        return Ok(());
    }
    
    // Calculate total number of ports in the search ranges to check against requested number of continuous ports.
    // (1024..=49151) -> 49151 - 1024 + 1 = 48128 ports
    // (49152..=65535) -> 65535 - 49152 + 1 = 16384 ports
    // Total = 48128 + 16384 = 64512 ports. This fits in u16.
    const TOTAL_SEARCHABLE_PORTS: u16 = (49151u16 - 1024u16 + 1u16) + (65535u16 - 49152u16 + 1u16);
    if cli.continuous && cli.number_of_ports > 1 && TOTAL_SEARCHABLE_PORTS < cli.number_of_ports {
        // Basic check if requested number of continuous ports can even exist in the searched ranges
        println!("{}", format!("\nWarning: Requested number of continuous ports ({}) is very large and might not be possible to find as it exceeds the total number of searchable ports ({}).", cli.number_of_ports, TOTAL_SEARCHABLE_PORTS).yellow());
    }

    let available_ports = find_available_ports(&forbidden_ports, cli.number_of_ports, cli.continuous);

    const PORT_COLORS: [Color; 6] = [
        Color::Red,
        Color::Yellow,
        Color::Green,
        Color::Cyan,
        Color::Blue,
        Color::Magenta,
    ];
    let mut rng = rand::thread_rng();
    let selected_port_color = PORT_COLORS.choose(&mut rng).unwrap_or(&Color::White); // Default to white if selection fails

    if available_ports.is_empty() {
        println!("{}", format!("\nCould not find {} {}available port(s) in the checked ranges.", 
            cli.number_of_ports, 
            if cli.continuous {"continuous "} else {""}).red());
    } else if cli.continuous && available_ports.len() < cli.number_of_ports as usize {
        println!("{}", format!("\nCould not find a continuous block of {} ports. Found {} available port(s) instead:", cli.number_of_ports, available_ports.len()).yellow());
        for port in available_ports {
            let port_str = format!("{}", port);
            let colored_port = port_str.color(*selected_port_color);
            if cli.docker_format {
                println!("{}:", colored_port);
            } else {
                println!("- {}", colored_port);
            }
        }
    } 
    else if !cli.continuous && available_ports.len() < cli.number_of_ports as usize {
        println!("{}", format!("\nFound {} out of {} requested available port(s):", available_ports.len(), cli.number_of_ports).yellow());
        for port in available_ports {
            let port_str = format!("{}", port);
            let colored_port = port_str.color(*selected_port_color);
            if cli.docker_format {
                println!("{}:", colored_port);
            } else {
                println!("- {}", colored_port);
            }
        }
    }
    else { // Found all requested ports
        println!("{}", "\nSuggested available port(s):".green());
        for port in available_ports {
            let port_str = format!("{}", port);
            let colored_port = port_str.color(*selected_port_color);
            if cli.docker_format {
                println!("{}:", colored_port);
            } else {
                println!("- {}", colored_port);
            }
        }
    }

    Ok(())
}
