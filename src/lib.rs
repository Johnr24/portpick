use anyhow::{Context, Result};
use colored::*;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::str::FromStr;
// Note: reqwest is used by fetch_remote_nmap_services, which is called by main,
// but not directly by the functions being moved here for unit testing.
// If fetch_remote_nmap_services were also moved to lib.rs, reqwest would be needed here.

// These constants are used by functions that might be tested or used by the library.
// If they are only used by main, they can stay in main.rs.
// For now, assuming parse_services_content might be tested with specific content,
// and find_available_ports is a core logic.
// LSOF_PORT_RE is used by get_locally_used_ports, which is still in main.rs.
// So LSOF_PORT_RE should stay in main.rs or get_locally_used_ports moved to lib.rs.
// For this step, we focus on parse_services_content and find_available_ports.

pub fn parse_services_content(content: &str, source_description: &str, verbose: bool) -> Result<HashSet<u16>> {
    if verbose {
        println!("{}", format!("Parsing services data from {}...", source_description).cyan());
    }
    let mut ports = HashSet::new();
    for line in content.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.starts_with('#') || trimmed_line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed_line.split_whitespace().collect();
        if parts.len() < 2 { 
            continue;
        }

        let service_name = parts[0];
        if service_name.to_lowercase() == "unknown" { 
            continue;
        }

        let port_protocol_str = parts[1]; 
        let port_protocol_pair: Vec<&str> = port_protocol_str.split('/').collect();
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
    if verbose {
        println!("{}", format!("Found {} distinct TCP ports from {}.", ports.len(), source_description).cyan());
    }
    Ok(ports)
}

pub fn find_available_ports(
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
            let effective_end_search = if num_ports > 0 {
                end_range.saturating_sub(num_ports -1)
            } else {
                end_range 
            };

            for p_start in start_range..=effective_end_search {
                let mut block_available = true;
                let mut current_block = Vec::new();
                for i in 0..num_ports {
                    let current_port = p_start + i;
                    if forbidden_ports.contains(&current_port) {
                        block_available = false;
                        break;
                    }
                    current_block.push(current_port);
                }
                if block_available {
                    return current_block; 
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
    found_ports
}
