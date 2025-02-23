use std::io::Result;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=proto/");
    tonic_build::configure()
    .compile_protos(
        &[
            "proto/device.proto",
            "proto/empty.proto",
            "proto/radio.proto",
        ],
        &["proto/"], // The directory containing your proto files
    )?;
    Ok(())
} 