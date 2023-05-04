use anyhow::Result;
use std::process::Command;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=sol/Schnorr.sol");
    let status = Command::new("solc")
        .arg("--bin")
        .arg("-o")
        .arg("sol")
        .arg("sol/Schnorr.sol")
        .arg("--overwrite")
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to run solc");
    }
    Ok(())
}
