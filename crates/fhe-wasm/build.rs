use bincode;
use fhe::bfv::BfvParametersBuilder;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Create directory for pre-built parameters
    let out_dir = Path::new("src/prebuilt");
    std::fs::create_dir_all(out_dir).unwrap();

    // Build default parameters
    let default_params = BfvParametersBuilder::new()
        .set_degree(2048)
        .set_moduli(&[0x3fffffff000001])
        .set_plaintext_modulus(1 << 10)
        .build_arc()
        .expect("Failed to build default parameters");

    // Build secure parameters
    let secure_params = BfvParametersBuilder::new()
        .set_degree(4096)
        .set_moduli(&[0x3fffffff000001])
        .set_plaintext_modulus(1 << 10)
        .build_arc()
        .expect("Failed to build secure parameters");

    // Serialize and save default parameters
    let serialized_default = bincode::serialize(&default_params).unwrap();
    let mut file = File::create(out_dir.join("default_params.bin")).unwrap();
    file.write_all(&serialized_default).unwrap();

    // Serialize and save secure parameters
    let serialized_secure = bincode::serialize(&secure_params).unwrap();
    let mut file = File::create(out_dir.join("secure_params.bin")).unwrap();
    file.write_all(&serialized_secure).unwrap();

    println!("cargo:warning=Pre-built parameters generated successfully");
}
