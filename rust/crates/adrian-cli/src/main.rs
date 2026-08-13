//! adrian-cli binary entry point.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    adrian_cli::run().await
}
