# portpick

`portpick` is a command-line utility to help you find available network ports on your system. It can suggest one or more ports, optionally in a continuous block, and can format the output for Docker-compose.

By default, `portpick` uses a local cache of Nmap's services list if available, falling back to the system's `/etc/services` file. It also checks for locally listening ports using `lsof`.

## Usage

```bash
portpick [OPTIONS]
```

## Options

| Flag                      | Short | Description                                                                                     | Default |
|---------------------------|-------|-------------------------------------------------------------------------------------------------|---------|
| `--fetch-nmap`            |       | Fetch the official Nmap services list, use it for this run, and update the local cache.         |         |
| `--number-of-ports <NUM>` | `-n`  | Number of ports to find.                                                                        | `1`     |
| `--continuous`            | `-c`  | Require the found ports to be a continuous block.                                               |         |
| `--docker-format`         | `-d`  | Output ports in Docker-compose format (e.g., `8080:`).                                          |         |
| `--verbose`               | `-v`  | Enable verbose output, showing steps taken to find ports.                                       |         |
| `--help`                  | `-h`  | Print help information.                                                                         |         |
| `--version`               | `-V`  | Print version information.                                                                      |         |

## Examples

Find a single available port:
```bash
portpick
```

Find 3 available ports:
```bash
portpick -n 3
```

Find 2 continuous ports and output in Docker format:
```bash
portpick -n 2 -c -d
```

Find a port using the latest Nmap services list (fetches and caches it) with verbose output:
```bash
portpick --fetch-nmap -v
```

## Installation

If you have Rust installed, you can install `portpick` using cargo.

**From a local clone:**
```bash
# Clone the repository (if you haven't already)
# git clone <your-repo-url>
# cd portpick
cargo install --path .
```

**Directly from GitHub:**
Once the repository is public on GitHub, you can install it directly using:
```bash
cargo install --git https://github.com/your-username/portpick.git
```
Replace `https://github.com/your-username/portpick.git` with the actual URL of your GitHub repository.

This will place the `portpick` binary in your cargo binary directory (usually `~/.cargo/bin/`), which should be in your `PATH`.

## How it Works

1.  **Port Data Source Priority:**
    *   If `--fetch-nmap` is used: Fetches from `https://svn.nmap.org/nmap/nmap-services`, uses this data, and caches it to `src/nmap-services.cache`.
    *   If `--fetch-nmap` is NOT used:
        1.  Tries to read from `src/nmap-services.cache`.
        2.  If cache is not found or fails to parse, falls back to `/etc/services`.
        3.  If `/etc/services` also fails, issues a warning.
2.  **Locally Used Ports:** Uses `lsof -iTCP -sTCP:LISTEN -P -n` to find currently listening TCP ports on the local machine.
3.  **Forbidden Ports:** Combines ports from the chosen data source (Nmap/system services) and locally used ports. Services named "unknown" are ignored.
4.  **Port Suggestion:**
    *   Searches for available ports, prioritizing the registered port range (1024-49151) before the dynamic/private port range (49152-65535).
    *   Well-known ports (0-1023) are avoided.
    *   If `-c` or `--continuous` is specified, it looks for a continuous block of ports.
5.  **Output:**
    *   Prints suggested ports.
    *   If `-d` or `--docker-format` is used, ports are printed as `PORT:`.
    *   Output is colored for readability. Verbose messages are cyan, warnings yellow, errors red, and suggested ports are green with a randomly selected color for the port numbers themselves (consistent per run).

## Building from Source

1.  Clone the repository.
2.  Navigate to the project directory.
3.  Build the project:
    ```bash
    cargo build --release
    ```
    The binary will be located at `target/release/portpick`.
```
