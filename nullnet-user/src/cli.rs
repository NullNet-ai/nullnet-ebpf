use clap::Parser;

/// TUN-based networking in Rust
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Name of the TUN interface
    #[arg(long)]
    pub tun_name: String,
    /// Name of the ethernet interface
    #[arg(long)]
    pub eth_name: String,
}
