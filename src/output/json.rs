use std::io::{self, Write};

use serde_json::Value;

pub(super) fn print(value: &Value) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    writeln!(output)?;
    Ok(())
}
