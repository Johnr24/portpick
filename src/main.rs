use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use once_cell::sync::Lazy;
use rand::prelude::IndexedRandom; // For the .choose() method on slices
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::process::Command;
use std::str::FromStr;

// Import functions from the library crate
use portpick::{find_available_ports, parse_services_content};


const SYSTEM_SERVICES_PATH: &str = "/etc/services"; // Standard path for system services file
const REMOTE_NMAP_SERVICES_URL: &str = "https://svn.nmap.org/nmap/nmap-services"; // URL for official Nmap services
const LOCAL_NMAP_CACHE_PATH: &str = "src/nmap-services.cache"; // Path for the local Nmap services cache

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)] // -h will now default to help
struct Cli {
    /// Use the universal Nmap services list (fetches from internet, updates local cache)
    #[clap(short, long)]
    universal: bool,

    /// Explicitly use the local host's system services file (e.g., /etc/services). This is the default if --universal is not used.
    #[clap(short = 'l', long)]
    local: bool,

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

    /// Force port suggestion even if local port checking (e.g., lsof) fails.
    /// This may result in less accurate suggestions.
    #[clap(short, long)]
    force: bool,
}

// Regex to capture listening ports from lsof output (e.g., *:80, 127.0.0.1:8080)
static LSOF_PORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r":(\d{1,5})\s*\(LISTEN\)$").unwrap());

// parse_services_content moved to lib.rs

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

// find_available_ports moved to lib.rs

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut forbidden_ports = HashSet::new();

    if cli.universal {
        if cli.verbose {
            println!("{}", format!("Universal Nmap services flag set. Attempting to fetch, cache, and parse Nmap services list from {}...", REMOTE_NMAP_SERVICES_URL).cyan());
            if cli.local { // --local is specified along with --universal
                eprintln!("{}", "Warning: --universal and --local flags were both specified. --universal takes precedence.".yellow());
            }
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
        // Default: use system services file directly
        if cli.verbose {
            println!("{}", format!("Default mode: Attempting to use system services file: {}", SYSTEM_SERVICES_PATH).cyan());
        }
        match read_system_services_ports(cli.verbose) {
            Ok(system_ports) => {
                forbidden_ports.extend(system_ports);
            }
            Err(e_sys) => {
                eprintln!("{}", format!("Warning: Could not read or parse system services file ({}): {}", SYSTEM_SERVICES_PATH, e_sys).yellow());
                eprintln!("{}", "Proceeding with locally used ports only. Port suggestions might be less reliable.".yellow());
                // Not returning an error here, just proceeding with fewer forbidden ports.
            }
        }
    }

    match get_locally_used_ports(cli.verbose) {
        Ok(local_ports) => {
            forbidden_ports.extend(local_ports);
        }
        Err(e) => {
            if cli.force {
                eprintln!("{}", format!("Warning: Failed to get locally used ports: {}. Proceeding with --force, but suggestions may be inaccurate.", e).yellow());
                // Proceed with an empty set of local ports, relying only on service data
            } else {
                // If lsof fails and --force is not used, it's safer to error out.
                return Err(e.context("Failed to get locally used ports. Cannot reliably find an available port. Use --force to attempt suggestion anyway."));
            }
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
    let mut rng = rand::rngs::std::thread_rng();
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
