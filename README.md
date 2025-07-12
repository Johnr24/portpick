# portpick
`portpick` is a command-line utility to help you find available network ports on your system. It can suggest one or more ports, optionally in a continuous block, and can format the output for Docker-compose.

## Special Thanks, 

https://github.com/bee-san/RustScan

## Usage

```bash
portpick [OPTIONS]
```

By default, `portpick` uses the system's `/etc/services` file (equivalent to `--source system`) to gather information about known ports. It also checks for locally listening ports on `127.0.0.1` (equivalent to `--address 127.0.0.1`) using `rustscan`.

## Options

| Flag                      | Short | Description                                                                                     | Default    |
|---------------------------|-------|-------------------------------------------------------------------------------------------------|------------|
| `--address <ADDRESS>`     | `-a`  | Target address for RustScan (e.g., `127.0.0.1`, `localhost`, `example.com`).                    | `127.0.0.1`|
| `--source <SOURCE>`       | `-s`  | Source for known service ports.<ul><li>`system` (default): Uses local system's services file (e.g., `/etc/services`); fast, no network, may be less current.</li><li>`nmap`: Fetches latest services list from Nmap's site; most current, requires internet, caches locally.</li><li>`cache`: Uses locally cached Nmap services list; fast, comprehensive if cache is fresh, can be outdated.</li></ul> | `system`   |
| `--number-of-ports <NUM>` | `-n`  | Number of ports to find.                                                                        | `1`        |
| `--continuous`            | `-c`  | Require the found ports to be a continuous block.                                               | `false`    |
| `--docker-format`         | `-d`  | Output ports in Docker-compose format (e.g., `8080:`).                                          | `false`    |
| `--verbose`               | `-v`  | Enable verbose output, showing steps taken to find ports.                                       | `false`    |
| `--force`                 | `-f`  | Force port suggestion even if local port checking (e.g., `rustscan`) fails. May be less accurate. | `false`    |
| `--help`                  | `-h`  | Print help information.                                                                         |            |
| `--version`               | `-V`  | Print version information.                                                                      |            |

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

Find a port using the Nmap services list (fetches and caches it) with verbose output, scanning localhost:
```bash
portpick --source nmap -v
```

Find a port on a remote host `example.com` using universal nmap services for known port definitions:
```bash
portpick -a example.com -s nmap
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

1.  **Port Data Source (`--source` flag):** This flag determines where `portpick` gets its initial list of known TCP services and their associated port numbers. (See table above for details on `system`, `nmap`, and `cache` options).
2.  **Locally Used Ports (`--address` flag):** Uses `rustscan` to find currently listening TCP ports on the target specified by `--address` (defaults to `127.0.0.1`). A command similar to `rustscan -a <target_address> --range 1-65535 --accessible -b 1000 -t 1500 -- /bin/true` is executed. `rustscan` must be installed and in the system's PATH. If this command fails:
    *   Without `--force` (or `-f`): The program will exit with an error.
    *   With `--force` (or `-f`): A warning is printed, and `portpick` proceeds without information about locally used ports (suggestions will be based only on service data).
3.  **Forbidden Ports:** Combines ports from the chosen data source (Nmap/system services) and, if successful, locally used ports. Services named "unknown" are ignored.
4.  **Port Suggestion:**
    *   Searches for available ports, prioritizing the registered port range (1024-49151) before the dynamic/private port range (49152-65535).
    *   Privileged ports (0-1023) are avoided.
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
