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
| `--universal`             | `-u`  | Use the universal Nmap services list (fetches from internet, updates local cache).              |         |
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

Find a port using the universal Nmap services list (fetches and caches it) with verbose output:
```bash
portpick -u -v
```
Alternatively:
```bash
portpick --universal -v
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
 you can install it directly from github using:
```bash
cargo install --git https://github.com/Johnr24/portpick.git
```

This will place the `portpick` binary in your cargo binary directory (usually `~/.cargo/bin/`), which should be in your `PATH`.

## How it Works

1.  **Port Data Source Priority:**
    *   If `--universal` (or `-u`) is used: Fetches from `https://svn.nmap.org/nmap/nmap-services`, uses this data, and caches it to `src/nmap-services.cache`. The cache is primarily for future reference or if Nmap site is down, but this command always attempts a fresh fetch.
    *   If `--universal` (or `-u`) is NOT used (default behavior):
        1.  Directly uses the system's `/etc/services` file.
        2.  If reading or parsing `/etc/services` fails, issues a warning and proceeds with only locally listening ports.
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
