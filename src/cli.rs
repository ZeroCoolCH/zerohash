use clap::Parser;

// Mantida a estrutura original, mas agora em seu próprio módulo.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Target Bitcoin address (P2PKH)
    #[arg(short, long, default_value = "1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ")]
    pub address: String,

    /// Start of the private key range (hex)
    #[arg(long, default_value = "80000000000000000")] // Default para range 68 bits
    pub range_start: String,

    /// End of the private key range (hex)
    #[arg(long, default_value = "FFFFFFFFFFFFFFFFF")] // Default para range 68 bits
    pub range_end: String,

    /// Number of threads to use (0 means use all available cores)
    #[arg(short, long, default_value_t = 0)]
    pub threads: usize,

    /// Enable random sampling mode instead of sequential search
    #[arg(long, default_value_t = false)]
    pub random: bool,
} 