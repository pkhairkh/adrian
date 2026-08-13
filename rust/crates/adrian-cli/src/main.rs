//! adrian-cli binary entry point.
#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    adrian_cli::run().await
}
