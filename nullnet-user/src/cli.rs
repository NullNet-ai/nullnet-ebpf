use clap::Parser;

/// TUN-based networking in Rust
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Bind address of the TAP interface
    #[arg(long)]
    pub bind: String,
    // /// Peer address to connect to
    // #[arg(long)]
    // pub peer: String,
}
