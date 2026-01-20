use clap::Parser;
use ssh_vaultvarden::cli::{App, Cli};

fn main() {
    env_logger::init();
    let cli = Cli::parse();
    let app = App::new().unwrap_or_else(|e| {
        eprintln!("Error initializing app: {}", e);
        std::process::exit(1);
    });

    if let Err(e) = app.run(cli.command, cli.connect_pattern) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
