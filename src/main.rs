use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::process::Command;
use std::str::FromStr;

const WIKIPEDIA_URL: &str = "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers";

// Regex to capture port numbers and ranges from table cells
// Handles single ports like "80" and ranges like "71--74" or "6881–6887" (en-dash)
static PORT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*(\d{1,5})\s*(?:--|–)\s*(\d{1,5})\s*$|^\s*(\d{1,5})\s*$").unwrap());

// Regex to capture listening ports from lsof output (e.g., *:80, 127.0.0.1:8080)
static LSOF_PORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r":(\d{1,5})\s*\(LISTEN\)$").unwrap());

fn fetch_wikipedia_ports() -> Result<HashSet<u16>> {
    println!("Fetching port data from Wikipedia...");
    let response = reqwest::blocking::get(WIKIPEDIA_URL)?;
    let html_content = response.text()?;
    println!("Parsing Wikipedia port data...");

    let document = Html::parse_document(&html_content);
    let table_cell_selector = Selector::parse("td").unwrap();

    let mut ports = HashSet::new();

    for element in document.select(&table_cell_selector) {
        let text = element.text().collect::<String>();
        if let Some(captures) = PORT_RE.captures(text.trim()) {
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
                    for port in start_port..=end_port {
                        ports.insert(port);
                    }
                }
            }
        }
    }
    println!("Found {} ports/ranges from Wikipedia.", ports.len());
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

    match fetch_wikipedia_ports() {
        Ok(wiki_ports) => {
            forbidden_ports.extend(wiki_ports);
        }
        Err(e) => {
            eprintln!("Warning: Could not fetch or parse Wikipedia ports: {}", e);
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
