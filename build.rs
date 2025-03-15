use std::io::Result;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=proto/");

    // Generate proto files for Kaonic
    tonic_build::configure().compile_protos(
        &[
            "proto/kaonic/device.proto",
            "proto/kaonic/empty.proto",
            "proto/kaonic/radio.proto",
        ],
        &["proto/kaonic"], // The directory containing your proto files
    )?;
    Ok(())
}

