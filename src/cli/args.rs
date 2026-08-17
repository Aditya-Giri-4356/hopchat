// =============================================================================
// HOPCHAT — CLI Module: Argument Parser
// =============================================================================
//
// Manual argument parser — no external dependencies (no clap).
// Supports: -p/--port, -u/--username, -h/--help, --version

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Runtime configuration derived from command-line arguments.
pub struct Config {
    /// The preferred chat port (default: 9878)
    pub port: u16,
    /// Optional username to skip the interactive prompt
    pub username: Option<String>,
}

/// Parses command-line arguments into a Config.
/// Exits the process on --help or --version.
pub fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let mut config = Config {
        port: crate::PREFERRED_CHAT_PORT,
        username: None,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--port" => {
                if i + 1 < args.len() {
                    config.port = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("Invalid port: '{}'. Using default {}.", args[i + 1], crate::PREFERRED_CHAT_PORT);
                        crate::PREFERRED_CHAT_PORT
                    });
                    i += 1;
                } else {
                    eprintln!("--port requires a value. Using default {}.", crate::PREFERRED_CHAT_PORT);
                }
            }
            "-u" | "--username" => {
                if i + 1 < args.len() {
                    let raw = &args[i + 1];
                    let sanitized: String = raw
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .take(32)
                        .collect();
                    if sanitized.is_empty() {
                        eprintln!("Invalid username: '{}'. Will prompt interactively.", raw);
                    } else {
                        config.username = Some(sanitized);
                    }
                    i += 1;
                } else {
                    eprintln!("--username requires a value. Will prompt interactively.");
                }
            }
            "-h" | "--help" => {
                println!("HOPCHAT v{} — Encrypted P2P LAN Chat", VERSION);
                println!();
                println!("Usage: hopchat [OPTIONS]");
                println!();
                println!("Options:");
                println!("  -p, --port <PORT>        Chat port (default: {})", crate::PREFERRED_CHAT_PORT);
                println!("  -u, --username <NAME>    Username (skips interactive prompt)");
                println!("  -h, --help               Show this help message");
                println!("      --version            Show version information");
                std::process::exit(0);
            }
            "--version" => {
                println!("hopchat v{}", VERSION);
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: '{}'. Use --help for usage.", other);
            }
        }
        i += 1;
    }

    config
}
