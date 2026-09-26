use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match trusty_cli::run().await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("trusty: {error:#}");
            ExitCode::from(2)
        }
    }
}
