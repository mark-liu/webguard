mod audit;
mod classify;
mod config;
mod fetch;
mod server;

use clap::Parser;
use rmcp::ServiceExt;
use std::path::PathBuf;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "webguard", about = "Secure MCP server for prompt injection scanning")]
struct Cli {
    /// Path to config.yaml
    #[arg(long, short)]
    config: Option<PathBuf>,

    /// Print version and exit
    #[arg(long, short = 'V')]
    version: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.version {
        println!("webguard {VERSION}");
        return Ok(());
    }

    // Load config
    let config_path = cli
        .config
        .unwrap_or_else(|| {
            std::env::var("WEBGUARD_CONFIG_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| config::Config::default_path())
        });
    let cfg = config::Config::load(&config_path).unwrap_or_else(|e| {
        eprintln!("warning: failed to load config from {}: {e}", config_path.display());
        config::Config::default()
    });

    // Load external patterns
    let external_patterns = if !cfg.patterns_dir.is_empty() {
        let path = PathBuf::from(&cfg.patterns_dir);
        match classify::external::load_external_patterns(&path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: failed to load external patterns: {e}");
                None
            }
        }
    } else {
        None
    };

    // Initialize audit logger
    let audit_path = if cfg.audit.path.is_empty() {
        audit::default_path().to_string_lossy().to_string()
    } else {
        cfg.audit.path.clone()
    };
    let audit_logger = audit::Logger::new(&audit_path, cfg.audit.enabled)?;

    // Create server
    let server = server::WebGuardServer::new(cfg, audit_logger, VERSION.to_string(), external_patterns);

    // Run MCP over stdio
    let service = server.serve(rmcp::transport::io::stdio()).await?;
    service.waiting().await?;

    Ok(())
}
