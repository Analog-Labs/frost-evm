use anyhow::Result;
use std::process::Command;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=sol/SchnorrSECP256K1.sol");
    let status = Command::new("solc")
        .arg("--bin")
        .arg("-o")
        .arg("sol")
        .arg("sol/SchnorrSECP256K1.sol")
        .arg("--overwrite")
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to run solc");
    }
    Ok(())
}
