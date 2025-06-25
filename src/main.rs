use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use rand::prelude::IndexedRandom; // For the .choose() method on slices
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
    /// Target address for RustScan to scan (e.g., 127.0.0.1, localhost, example.com)
    #[clap(short = 'a', long)]
    address: Option<String>,

    /// Source for the list of known service ports [possible values: system, nmap, cache]
    #[clap(short = 's', long, default_value = "system")]
    source: String,

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

// parse_services_content moved to lib.rs

fn read_system_services_ports(verbose: bool) -> Result<HashSet<u16>> {
    if verbose {
        println!(
            "{}",
            format!(
                "Reading port data from system services file: {}",
                SYSTEM_SERVICES_PATH
            )
            .cyan()
        );
    }
    let file_content = fs::read_to_string(SYSTEM_SERVICES_PATH).with_context(|| {
        format!(
            "Failed to read system services file at '{}'",
            SYSTEM_SERVICES_PATH
        )
    })?;
    parse_services_content(&file_content, "system services file", verbose)
}

fn save_nmap_cache(content: &str, verbose: bool) -> Result<()> {
    if verbose {
        println!(
            "{}",
            format!("Caching Nmap services data to: {}", LOCAL_NMAP_CACHE_PATH).cyan()
        );
    }
    fs::write(LOCAL_NMAP_CACHE_PATH, content).with_context(|| {
        format!(
            "Failed to write Nmap services cache to '{}'",
            LOCAL_NMAP_CACHE_PATH
        )
    })
}

fn fetch_remote_nmap_services(verbose: bool) -> Result<String> {
    if verbose {
        println!(
            "{}",
            format!(
                "Fetching Nmap services data from: {}",
                REMOTE_NMAP_SERVICES_URL
            )
            .cyan()
        );
    }

    let client = reqwest::blocking::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        .build()
        .context("Failed to build reqwest client")?;

    let response = client
        .get(REMOTE_NMAP_SERVICES_URL)
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

fn get_locally_used_ports(cli: &Cli) -> Result<HashSet<u16>> {
    if cli.verbose {
        println!(
            "{}",
            "Scanning for locally used TCP ports using RustScan...".cyan()
        );
    }
    // Consider making port range, batch size, and timeout configurable if needed.
    let target_address = cli.address.as_deref().unwrap_or("127.0.0.1");
    let rustscan_args = [
        "-a", target_address, // Target address from --address flag or default
        "--range",
        "1-65535",      // Scan all standard port ranges
        "--accessible", // Output only open ports, one port per line
        "-b",
        "1000", // Batch size for scanning
        "-t",
        "1500", // Timeout per port in milliseconds
        "--",           // Separator: arguments after this are for the command
        "/bin/true",    // Command to run instead of Nmap (does nothing)
    ];

    if cli.verbose {
        println!(
            "{}",
            format!("Executing: rustscan {}", rustscan_args.join(" ")).dimmed()
        );
    }

    let output = Command::new("rustscan")
        .args(&rustscan_args)
        .output()
        .context(
            "Failed to execute rustscan command. Make sure rustscan is installed and in PATH.",
        )?;

    if !output.status.success() {
        // RustScan might provide partial results or specific error info.
        // For now, we treat any non-zero exit status as a failure.
        return Err(anyhow::anyhow!(
            "rustscan command failed with status: {}.\nStdout: {}\nStderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut ports = HashSet::new();

    for line in output_str.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.is_empty() {
            continue; // Skip empty lines
        }
        match u16::from_str(trimmed_line) {
            Ok(port) => {
                ports.insert(port);
            }
            Err(_) => {
                if cli.verbose {
                    // Log if a line from rustscan output couldn't be parsed as a port.
                    eprintln!(
                        "{}",
                        format!(
                            "Warning: Could not parse line from rustscan output as port: '{}'",
                            trimmed_line
                        )
                        .yellow()
                    );
                }
            }
        }
    }

    if cli.verbose {
        println!(
            "{}",
            format!("RustScan found {} locally open TCP ports.", ports.len()).cyan()
        );
    }
    Ok(ports)
}

// find_available_ports moved to lib.rs

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut forbidden_ports = HashSet::new();

    if cli.number_of_ports == 0 {
        println!(
            "{}",
            "\nNumber of ports requested is 0. No ports to find.".yellow()
        );
        return Ok(());
    }

    // Determine the source of service port information
    match cli.source.to_lowercase().as_str() {
        "nmap" => {
            if cli.verbose {
                println!("{}", format!("Source 'nmap': Attempting to fetch, cache, and parse Nmap services list from {}...", REMOTE_NMAP_SERVICES_URL).cyan());
            }
            match fetch_remote_nmap_services(cli.verbose) {
                Ok(nmap_content) => {
                    if let Err(e) = save_nmap_cache(&nmap_content, cli.verbose) {
                        eprintln!("{}", format!("Warning: Failed to save fetched Nmap services to cache at {}: {}", LOCAL_NMAP_CACHE_PATH, e).yellow());
                    } else if cli.verbose {
                        println!("{}", format!("Successfully cached Nmap services to {}", LOCAL_NMAP_CACHE_PATH).green());
                    }
                    match parse_services_content(&nmap_content, "fetched Nmap services list", cli.verbose) {
                        Ok(nmap_ports) => forbidden_ports.extend(nmap_ports),
                        Err(e) => return Err(e.context("Failed to parse fetched Nmap services content.")),
                    }
                }
                Err(e) => return Err(e.context("Failed to fetch remote Nmap services for source 'nmap'.")),
            }
        }
        "cache" => {
            if cli.verbose {
                println!("{}", format!("Source 'cache': Attempting to use cached Nmap services from {}...", LOCAL_NMAP_CACHE_PATH).cyan());
            }
            match fs::read_to_string(LOCAL_NMAP_CACHE_PATH) {
                Ok(cached_content) => {
                    match parse_services_content(&cached_content, "cached Nmap services list", cli.verbose) {
                        Ok(cached_ports) => forbidden_ports.extend(cached_ports),
                        Err(e) => return Err(e.context(format!("Failed to parse cached Nmap services content from {}.", LOCAL_NMAP_CACHE_PATH))),
                    }
                }
                Err(_) => {
                    eprintln!("{}", format!("Warning: Nmap services cache file not found or unreadable at {}. Falling back to system services.", LOCAL_NMAP_CACHE_PATH).yellow());
                    // Fallback to system services
                    match read_system_services_ports(cli.verbose) {
                        Ok(system_ports) => forbidden_ports.extend(system_ports),
                        Err(e_sys) => eprintln!("{}", format!("Warning: Could not read or parse system services file ({}): {}. Proceeding with minimal forbidden ports.", SYSTEM_SERVICES_PATH, e_sys).yellow()),
                    }
                }
            }
        }
        "system" | _ => { // Default to "system" if an unknown value is provided or if it's explicitly "system"
            if cli.source.to_lowercase() != "system" && cli.verbose { // Warn if it's an unknown value
                eprintln!("{}", format!("Warning: Unknown source '{}'. Defaulting to 'system' services.", cli.source).yellow());
            }
            if cli.verbose {
                println!("{}", format!("Source 'system': Attempting to use system services file: {}", SYSTEM_SERVICES_PATH).cyan());
            }
            match read_system_services_ports(cli.verbose) {
                Ok(system_ports) => forbidden_ports.extend(system_ports),
                Err(e_sys) => {
                    eprintln!("{}", format!("Warning: Could not read or parse system services file ({}): {}. Proceeding with minimal forbidden ports.", SYSTEM_SERVICES_PATH, e_sys).yellow());
                }
            }
        }
    }

    // Pass the Cli struct to get_locally_used_ports to access cli.address and cli.verbose
    match get_locally_used_ports(&cli) {
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
        println!(
            "{}",
            format!("Total {} forbidden ports collected.", forbidden_ports.len()).cyan()
        );
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

    let available_ports =
        find_available_ports(&forbidden_ports, cli.number_of_ports, cli.continuous);

    const PORT_COLORS: [Color; 6] = [
        Color::Red,
        Color::Yellow,
        Color::Green,
        Color::Cyan,
        Color::Blue,
        Color::Magenta,
    ];
    let mut rng = rand::rng();
    let selected_port_color = PORT_COLORS.choose(&mut rng).unwrap_or(&Color::White); // Default to white if selection fails

    if available_ports.is_empty() {
        println!(
            "{}",
            format!(
                "\nCould not find {} {}available port(s) in the checked ranges.",
                cli.number_of_ports,
                if cli.continuous { "continuous " } else { "" }
            )
            .red()
        );
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
    } else if !cli.continuous && available_ports.len() < cli.number_of_ports as usize {
        println!(
            "{}",
            format!(
                "\nFound {} out of {} requested available port(s):",
                available_ports.len(),
                cli.number_of_ports
            )
            .yellow()
        );
        for port in available_ports {
            let port_str = format!("{}", port);
            let colored_port = port_str.color(*selected_port_color);
            if cli.docker_format {
                println!("{}:", colored_port);
            } else {
                println!("- {}", colored_port);
            }
        }
    } else {
        // Found all requested ports
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
