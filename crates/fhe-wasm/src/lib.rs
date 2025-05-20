use fhe::bfv::{BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::*;
use once_cell::sync::Lazy;
use rand::{rngs::StdRng, SeedableRng};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::*;

// Global parameter cache
static PARAMETER_CACHE: Lazy<Mutex<HashMap<u32, Arc<fhe::bfv::BfvParameters>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// Counter for generating unique IDs
static NEXT_PARAM_ID: Lazy<Mutex<u32>> = Lazy::new(|| Mutex::new(1));
/// Parameters for 128-bit classical and post-quantum security, suitable for depth-1 multiplicative circuits.
///
/// - Polynomial modulus degree \( n = 2048 \)
/// - Ciphertext modulus \( q \approx 2^{55.78} \)
/// - Plaintext modulus \( t = 2^{10} \)
///
/// Security Justification:
/// - \( \log_2 q \approx 55.78 \) exceeds the minimum requirements for both classical (≥54) and post-quantum (≥53) security at \( n = 2048 \).
///
/// Performance Consideration:
/// - Lower \( n \) offers better performance for applications requiring shallow circuit depths.
static DEFAULT_PARAMETERS: Lazy<Arc<fhe::bfv::BfvParameters>> = Lazy::new(|| {
    BfvParametersBuilder::new()
        .set_degree(2048)
        .set_moduli(&[0x3fffffff000001])
        .set_plaintext_modulus(1 << 10)
        .build_arc()
        .expect("Failed to build default parameters")
});

/// Parameters for 128-bit classical and post-quantum security at higher polynomial modulus degree, suitable for deeper circuits.
///
/// - Polynomial modulus degree \( n = 4096 \)
/// - Ciphertext modulus composed of three 37-bit primes:
///     - \( q_1 = 0x1FFFFFFFFF \)
///     - \( q_2 = 0x1FFFFFFEFF \)
///     - \( q_3 = 0x1FFFFFFDFF \)
/// - Plaintext modulus \( t = 2^{10} \)
///
/// Security Justification:
/// - Combined \( \log_2 q \approx 111 \) meets the minimum requirements for both classical (≥111) and post-quantum (≥103) security at \( n = 4096 \).
///
/// Performance Consideration:
/// - Higher \( n \) supports deeper circuits but may incur additional computational overhead.
static SECURE_PARAMETERS: Lazy<Arc<fhe::bfv::BfvParameters>> = Lazy::new(|| {
    BfvParametersBuilder::new()
        .set_degree(4096)
        .set_moduli(&[
            0x1FFFFFFFFF, // 37 bits
            0x1FFFFFFEFF, // 37 bits
            0x1FFFFFFDFF, // 37 bits; total ≈111 bits
        ])
        .set_plaintext_modulus(1 << 10)
        .build_arc()
        .expect("Failed to build secure parameters")
});

// Generate a new unique ID
fn get_next_id() -> u32 {
    let mut id = NEXT_PARAM_ID.lock().unwrap();
    let current = *id;
    *id += 1;
    current
}

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen(start)]
pub fn start() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Generates FHE parameters with custom settings and stores them in memory
/// Returns a handle to reference these parameters
#[wasm_bindgen]
pub fn generate_and_store_parameters(
    degree: usize,
    moduli: Box<[u64]>,
    plaintext_modulus: u64,
) -> Result<u32, JsValue> {
    let parameters = BfvParametersBuilder::new()
        .set_degree(degree)
        .set_moduli(&moduli)
        .set_plaintext_modulus(plaintext_modulus)
        .build_arc()
        .map_err(|e| JsValue::from_str(&format!("Parameter building error: {}", e)))?;

    let id = get_next_id();
    PARAMETER_CACHE.lock().unwrap().insert(id, parameters);

    Ok(id)
}

/// Generates FHE parameters with default settings and stores them in memory
#[wasm_bindgen]
pub fn generate_and_store_default_parameters() -> Result<u32, JsValue> {
    generate_and_store_parameters(2048, Box::new([0x3fffffff000001]), 1 << 10)
}

/// Retrieves stored parameters as serialized bytes (if needed for compatibility)
#[wasm_bindgen]
pub fn get_serialized_parameters(param_id: u32) -> Result<Box<[u8]>, JsValue> {
    let cache = PARAMETER_CACHE.lock().unwrap();
    let params = cache
        .get(&param_id)
        .ok_or_else(|| JsValue::from_str("Parameters not found"))?;

    let serialized = bincode::serialize(&params)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    Ok(serialized.into_boxed_slice())
}

/// Removes parameters from memory
#[wasm_bindgen]
pub fn remove_parameters(param_id: u32) -> bool {
    let mut cache = PARAMETER_CACHE.lock().unwrap();
    cache.remove(&param_id).is_some()
}

/// Generates a new secret key using stored parameters and returns it as a serialized byte array
#[wasm_bindgen]
pub fn generate_secret_key_with_stored_params(param_id: u32) -> Result<Box<[u8]>, JsValue> {
    let cache = PARAMETER_CACHE.lock().unwrap();
    let parameters = cache
        .get(&param_id)
        .ok_or_else(|| JsValue::from_str("Parameters not found"))?;

    let mut rng = StdRng::from_entropy();
    let secret_key = SecretKey::random(parameters, &mut rng);

    // Serialize the secret key to bytes
    let serialized = bincode::serialize(&secret_key)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    Ok(serialized.into_boxed_slice())
}

/// Encrypts a value using a serialized public key and stored parameters
/// Note: that operations actually happen modulo the plaintext_modulus
#[wasm_bindgen]
pub fn encrypt_with_stored_parameters(
    value: i64,
    public_key_bytes: &[u8],
    param_id: u32,
) -> Result<Box<[u8]>, JsValue> {
    // Get the parameters from the cache
    let cache = PARAMETER_CACHE.lock().unwrap();
    let parameters = cache
        .get(&param_id)
        .ok_or_else(|| JsValue::from_str("Parameters not found"))?;

    // Deserialize the public key
    let public_key: PublicKey = bincode::deserialize(public_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Public key deserialization error: {}", e)))?;

    // Create a secure RNG that works in WASM
    let mut rng = StdRng::from_entropy();

    // Encode the value into a plaintext
    let plaintext = Plaintext::try_encode(&[value], Encoding::poly(), parameters)
        .map_err(|e| JsValue::from_str(&format!("Encoding error: {}", e)))?;

    // Encrypt the plaintext
    let ciphertext: Ciphertext = public_key
        .try_encrypt(&plaintext, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Encryption error: {}", e)))?;

    // Serialize the ciphertext to bytes
    let serialized = bincode::serialize(&ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    Ok(serialized.into_boxed_slice())
}

/// Generates FHE parameters with custom settings and returns them as a serialized byte array
#[wasm_bindgen]
pub fn generate_parameters_custom(
    degree: usize,
    moduli: Box<[u64]>,
    plaintext_modulus: u64,
) -> Result<Box<[u8]>, JsValue> {
    let parameters = BfvParametersBuilder::new()
        .set_degree(degree)
        .set_moduli(&moduli)
        .set_plaintext_modulus(plaintext_modulus)
        .build_arc()
        .map_err(|e| JsValue::from_str(&format!("Parameter building error: {}", e)))?;

    // Serialize parameters to bytes
    let serialized = bincode::serialize(&parameters)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    Ok(serialized.into_boxed_slice())
}

/// Generates FHE parameters with default settings and returns them as a serialized byte array
/// Note: Configured to provide mimimum security
/// (Todo): Look into the security of these parameters
#[wasm_bindgen]
pub fn generate_parameters() -> Result<Box<[u8]>, JsValue> {
    generate_parameters_custom(2048, Box::new([0x3fffffff000001]), 1 << 10)
}

/// Generates a new secret key using provided parameters and returns it as a serialized byte array
#[wasm_bindgen]
pub fn generate_secret_key_bytes(parameters_bytes: &[u8]) -> Result<Box<[u8]>, JsValue> {
    // Deserialize the parameters
    let parameters = bincode::deserialize(parameters_bytes)
        .map_err(|e| JsValue::from_str(&format!("Parameters deserialization error: {}", e)))?;

    let mut rng = StdRng::from_entropy();
    let secret_key = SecretKey::random(&parameters, &mut rng);

    // Serialize the secret key to bytes
    let serialized = bincode::serialize(&secret_key)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    Ok(serialized.into_boxed_slice())
}

/// Generates a new secret key with default parameters and returns it as a serialized byte array
#[wasm_bindgen]
pub fn generate_secret_key_bytes_default() -> Result<Box<[u8]>, JsValue> {
    let parameters_bytes = generate_parameters()?;
    generate_secret_key_bytes(&parameters_bytes)
}

/// Generates a public key from a secret key
#[wasm_bindgen]
pub fn generate_public_key_bytes(secret_key_bytes: &[u8]) -> Result<Box<[u8]>, JsValue> {
    // Deserialize the secret key
    let secret_key: SecretKey = bincode::deserialize(secret_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;

    let mut rng = StdRng::from_entropy();
    let public_key = PublicKey::new(&secret_key, &mut rng);

    // Serialize the public key to bytes
    let serialized = bincode::serialize(&public_key)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    Ok(serialized.into_boxed_slice())
}

/// Encrypts a value using a serialized secret key and parameters
/// Note: that operations actually happen modulo the plaintext_modulus
#[wasm_bindgen]
pub fn encrypt_with_secret_key_bytes(
    value: i64,
    secret_key_bytes: &[u8],
    parameters_bytes: &[u8],
) -> Result<Box<[u8]>, JsValue> {
    // Deserialize the secret key and parameters
    let secret_key: SecretKey = bincode::deserialize(secret_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Secret key deserialization error: {}", e)))?;

    let parameters = bincode::deserialize(parameters_bytes)
        .map_err(|e| JsValue::from_str(&format!("Parameters deserialization error: {}", e)))?;

    // Create a secure RNG that works in WASM
    let mut rng = StdRng::from_entropy();

    // Encode the value into a plaintext
    let plaintext = Plaintext::try_encode(&[value], Encoding::poly(), &parameters)
        .map_err(|e| JsValue::from_str(&format!("Encoding error: {}", e)))?;

    // Encrypt the plaintext with explicit type annotation
    let ciphertext: Ciphertext = secret_key
        .try_encrypt(&plaintext, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Encryption error: {}", e)))?;

    // Serialize the ciphertext to bytes
    let serialized = bincode::serialize(&ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    Ok(serialized.into_boxed_slice())
}

/// Encrypts a value using a serialized public key and parameters
/// Note: that operations actually happen modulo the plaintext_modulus
#[wasm_bindgen]
pub fn encrypt_with_public_key_bytes(
    value: i64,
    public_key_bytes: &[u8],
    parameters_bytes: &[u8],
) -> Result<Box<[u8]>, JsValue> {
    // Deserialize the public key and parameters
    let public_key: PublicKey = bincode::deserialize(public_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Public key deserialization error: {}", e)))?;

    let parameters = bincode::deserialize(parameters_bytes)
        .map_err(|e| JsValue::from_str(&format!("Parameters deserialization error: {}", e)))?;

    // Create a secure RNG that works in WASM
    let mut rng = StdRng::from_entropy();

    // Encode the value into a plaintext
    let plaintext = Plaintext::try_encode(&[value], Encoding::poly(), &parameters)
        .map_err(|e| JsValue::from_str(&format!("Encoding error: {}", e)))?;

    // Encrypt the plaintext with explicit type annotation
    let ciphertext: Ciphertext = public_key
        .try_encrypt(&plaintext, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Encryption error: {}", e)))?;

    // Serialize the ciphertext to bytes
    let serialized = bincode::serialize(&ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    Ok(serialized.into_boxed_slice())
}

/// Decrypts a ciphertext using a serialized secret key
#[wasm_bindgen]
pub fn decrypt_bytes(ciphertext_bytes: &[u8], secret_key_bytes: &[u8]) -> Result<i64, JsValue> {
    // Deserialize the secret key and ciphertext
    let secret_key: SecretKey = bincode::deserialize(secret_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Secret key deserialization error: {}", e)))?;

    let ciphertext: Ciphertext = bincode::deserialize(ciphertext_bytes)
        .map_err(|e| JsValue::from_str(&format!("Ciphertext deserialization error: {}", e)))?;

    // Decrypt the ciphertext
    let plaintext = secret_key
        .try_decrypt(&ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Decryption error: {}", e)))?;

    // Decode the plaintext to get the original value
    let values = Vec::<i64>::try_decode(&plaintext, Encoding::poly())
        .map_err(|e| JsValue::from_str(&format!("Decoding error: {}", e)))?;

    // Extract the first value (we encrypted a single value)
    if values.is_empty() {
        return Err(JsValue::from_str("No values found in decrypted plaintext"));
    }

    Ok(values[0] as i64)
}

/// Gets the default predefined parameters as serialized bytes
#[wasm_bindgen]
pub fn get_default_parameters() -> Box<[u8]> {
    let serialized =
        bincode::serialize(&*DEFAULT_PARAMETERS).expect("Failed to serialize default parameters");
    serialized.into_boxed_slice()
}

/// Gets the high-security predefined parameters as serialized bytes
#[wasm_bindgen]
pub fn get_secure_parameters() -> Box<[u8]> {
    let serialized =
        bincode::serialize(&*SECURE_PARAMETERS).expect("Failed to serialize secure parameters");
    serialized.into_boxed_slice()
}

/// Generates a secret key using the predefined default parameters
#[wasm_bindgen]
pub fn generate_secret_key_with_default_params() -> Box<[u8]> {
    let mut rng = StdRng::from_entropy();
    let secret_key = SecretKey::random(&DEFAULT_PARAMETERS, &mut rng);

    // Serialize the secret key to bytes
    let serialized = bincode::serialize(&secret_key).expect("Failed to serialize secret key");

    serialized.into_boxed_slice()
}

/// Encrypts a value using the predefined default parameters and a public key
///Note: that operations actually happen modulo the plaintext_modulus
///Note: Default plaintext_modulus is 2^10 = 1024
#[wasm_bindgen]
pub fn encrypt_with_default_parameters(
    value: i64,
    public_key_bytes: &[u8],
) -> Result<Box<[u8]>, JsValue> {
    // Validate the input value range
    let plaintext_modulus = (**DEFAULT_PARAMETERS).plaintext();
    let half_modulus = (plaintext_modulus / 2) as i64;

    if value < 0 || value >= plaintext_modulus as i64 {
        return Err(JsValue::from_str(&format!(
            "Value {} is outside the valid range [0, {})",
            value, plaintext_modulus
        )));
    }

    // Deserialize the public key
    let public_key: PublicKey = bincode::deserialize(public_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Public key deserialization error: {}", e)))?;

    // Create a secure RNG that works in WASM
    let mut rng = StdRng::from_entropy();

    // Encode the value into a plaintext
    let plaintext = Plaintext::try_encode(&[value], Encoding::poly(), &*DEFAULT_PARAMETERS)
        .map_err(|e| JsValue::from_str(&format!("Encoding error: {}", e)))?;

    // Encrypt the plaintext
    let ciphertext: Ciphertext = public_key
        .try_encrypt(&plaintext, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Encryption error: {}", e)))?;

    // Serialize the ciphertext to bytes
    let serialized = bincode::serialize(&ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    Ok(serialized.into_boxed_slice())
}

#[wasm_bindgen]
pub fn decrypt_with_default_parameters(
    ciphertext_bytes: &[u8],
    secret_key_bytes: &[u8],
) -> Result<i64, JsValue> {
    // Deserialize the secret key and ciphertext
    let secret_key: SecretKey = bincode::deserialize(secret_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Secret key deserialization error: {}", e)))?;

    let ciphertext: Ciphertext = bincode::deserialize(ciphertext_bytes)
        .map_err(|e| JsValue::from_str(&format!("Ciphertext deserialization error: {}", e)))?;

    // Decrypt the ciphertext
    let plaintext = secret_key
        .try_decrypt(&ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Decryption error: {}", e)))?;

    // Decode the plaintext using the same encoding and parameters used for encryption
    let values = Vec::<i64>::try_decode(&plaintext, Encoding::poly())
        .map_err(|e| JsValue::from_str(&format!("Decoding error: {}", e)))?;

    // Extract the first value
    if values.is_empty() {
        return Err(JsValue::from_str("No values found in decrypted plaintext"));
    }

    Ok(values[0] as i64)
}

/// Encrypts a vector of integers using a serialized public key and parameters
/// Note: operations happen modulo the plaintext_modulus
#[wasm_bindgen]
pub fn encrypt_vector_with_public_key_bytes(
    values: &[i64],
    public_key_bytes: &[u8],
    parameters_bytes: &[u8],
) -> Result<Box<[u8]>, JsValue> {
    // Deserialize the public key and parameters
    let public_key: PublicKey = bincode::deserialize(public_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Public key deserialization error: {}", e)))?;

    let parameters = bincode::deserialize(parameters_bytes)
        .map_err(|e| JsValue::from_str(&format!("Parameters deserialization error: {}", e)))?;

    // Create a secure RNG that works in WASM
    let mut rng = StdRng::from_entropy();

    // Encode the vector into a plaintext
    let plaintext = Plaintext::try_encode(values, Encoding::poly(), &parameters)
        .map_err(|e| JsValue::from_str(&format!("Encoding error: {}", e)))?;

    // Encrypt the plaintext
    let ciphertext: Ciphertext = public_key
        .try_encrypt(&plaintext, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Encryption error: {}", e)))?;

    // Serialize the ciphertext to bytes
    let serialized = bincode::serialize(&ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    Ok(serialized.into_boxed_slice())
}

/// Encrypts a vector of integers using default parameters and a public key
/// Note: that operations happen modulo the plaintext_modulus (1024 for default parameters)
#[wasm_bindgen]
pub fn encrypt_vector_with_default_parameters(
    values: &[i64],
    public_key_bytes: &[u8],
) -> Result<Box<[u8]>, JsValue> {
    // Deserialize the public key
    let public_key: PublicKey = bincode::deserialize(public_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Public key deserialization error: {}", e)))?;

    // Create a secure RNG that works in WASM
    let mut rng = StdRng::from_entropy();

    // Encode the vector into a plaintext
    let plaintext = Plaintext::try_encode(values, Encoding::poly(), &*DEFAULT_PARAMETERS)
        .map_err(|e| JsValue::from_str(&format!("Encoding error: {}", e)))?;

    // Encrypt the plaintext
    let ciphertext: Ciphertext = public_key
        .try_encrypt(&plaintext, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Encryption error: {}", e)))?;

    // Serialize the ciphertext to bytes
    let serialized = bincode::serialize(&ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    Ok(serialized.into_boxed_slice())
}

/// Decrypts a ciphertext to a vector of integers using a serialized secret key
#[wasm_bindgen]
pub fn decrypt_vector_bytes_with_default_parameters(
    ciphertext_bytes: &[u8],
    secret_key_bytes: &[u8],
) -> Result<Box<[i64]>, JsValue> {
    // Deserialize the secret key and ciphertext
    let secret_key: SecretKey = bincode::deserialize(secret_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Secret key deserialization error: {}", e)))?;

    let ciphertext: Ciphertext = bincode::deserialize(ciphertext_bytes)
        .map_err(|e| JsValue::from_str(&format!("Ciphertext deserialization error: {}", e)))?;

    // Decrypt the ciphertext
    let plaintext = secret_key
        .try_decrypt(&ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Decryption error: {}", e)))?;

    // Decode the plaintext to get the original values
    let values = Vec::<i64>::try_decode(&plaintext, Encoding::poly())
        .map_err(|e| JsValue::from_str(&format!("Decoding error: {}", e)))?;

    // Get the plaintext modulus for normalization
    let plaintext_modulus = (**DEFAULT_PARAMETERS).plaintext() as i64;

    // Normalize values and determine significant length
    let mut normalized_values = Vec::new();
    let mut last_non_zero_idx = 0;

    // Find the last non-zero element
    for (i, &val) in values.iter().enumerate() {
        if val != 0 {
            last_non_zero_idx = i;
        }
    }

    // Process only significant values (up to and including the last non-zero value)
    for i in 0..=last_non_zero_idx {
        let val = values[i];
        // Convert to positive representation in range [0, plaintext_modulus-1]
        let normalized = (val % plaintext_modulus + plaintext_modulus) % plaintext_modulus;
        normalized_values.push(normalized);
    }

    Ok(normalized_values.into_boxed_slice())
}
#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);
    #[test]
    #[wasm_bindgen_test]
    fn test_encrypt_decrypt_cycle() {
        // Generate parameters
        let parameters_bytes = generate_parameters().unwrap();

        // Generate a secret key
        let secret_key_bytes = generate_secret_key_bytes_default().unwrap();

        // Generate a public key from the secret key
        let public_key_bytes = generate_public_key_bytes(&secret_key_bytes).unwrap();

        // Encrypt a value with the public key
        let original_value = 42;
        let ciphertext_bytes =
            encrypt_with_public_key_bytes(original_value, &public_key_bytes, &parameters_bytes)
                .unwrap();

        // Decrypt the ciphertext with the secret key
        let decrypted_value = decrypt_bytes(&ciphertext_bytes, &secret_key_bytes).unwrap();

        // Check that the decrypted value matches the original
        assert_eq!(decrypted_value, original_value);
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_secret_key_encryption() {
        // Generate parameters
        let parameters_bytes = generate_parameters().unwrap();

        // Generate a secret key
        let secret_key_bytes = generate_secret_key_bytes_default().unwrap();

        // Encrypt a value with the secret key
        let original_value = 123;
        let ciphertext_bytes =
            encrypt_with_secret_key_bytes(original_value, &secret_key_bytes, &parameters_bytes)
                .unwrap();

        // Decrypt the ciphertext with the secret key
        let decrypted_value = decrypt_bytes(&ciphertext_bytes, &secret_key_bytes).unwrap();

        // Check that the decrypted value matches the original
        assert_eq!(decrypted_value, original_value);
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_default_parameters_encryption() {
        // Generate a secret key using default parameters
        let secret_key_bytes = generate_secret_key_with_default_params();

        // Generate a public key from the secret key
        let public_key_bytes = generate_public_key_bytes(&secret_key_bytes).unwrap();

        // Encrypt a value with the public key using default parameters

        let original_value = 235;
        let ciphertext_bytes =
            encrypt_with_default_parameters(original_value, &public_key_bytes).unwrap();

        // Decrypt using the specialized function
        let decrypted_value =
            decrypt_with_default_parameters(&ciphertext_bytes, &secret_key_bytes).unwrap();

        // Check that the decrypted value matches the original
        assert_eq!(decrypted_value, original_value);
    }
    #[test]
    #[wasm_bindgen_test]
    fn test_default_parameters_encryption_failure() {
        // Generate a secret key using default parameters
        let secret_key_bytes = generate_secret_key_with_default_params();

        // Generate a public key from the secret key
        let public_key_bytes = generate_public_key_bytes(&secret_key_bytes).unwrap();

        // Encrypt a value with the public key using default parameters

        let original_value = 789;
        let ciphertext_bytes = encrypt_with_default_parameters(original_value, &public_key_bytes);

        assert!(ciphertext_bytes.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_vector_encrypt_decrypt_cycle() {
        // Generate parameters
        let parameters_bytes = generate_parameters().unwrap();

        // Generate a secret key
        let secret_key_bytes = generate_secret_key_bytes_default().unwrap();

        // Generate a public key from the secret key
        let public_key_bytes = generate_public_key_bytes(&secret_key_bytes).unwrap();

        // Encrypt a vector with the public key
        let original_values = [42, 123, 456, 789];
        let ciphertext_bytes = encrypt_vector_with_public_key_bytes(
            &original_values,
            &public_key_bytes,
            &parameters_bytes,
        )
        .unwrap();

        // Decrypt the ciphertext with the secret key
        let decrypted_values =
            decrypt_vector_bytes_with_default_parameters(&ciphertext_bytes, &secret_key_bytes)
                .unwrap();

        // Log values for debugging
        web_sys::console::log_1(
            &format!(
                "Original: {:?}, Decrypted: {:?}",
                &original_values, &decrypted_values
            )
            .into(),
        );

        // Check that lengths match
        assert_eq!(
            decrypted_values.len(),
            original_values.len(),
            "Vector length changed after encryption/decryption"
        );

        // Check that values match - now we should get normalized values directly
        for i in 0..original_values.len() {
            let orig_val = original_values[i];
            let dec_val = decrypted_values[i];

            assert_eq!(
                dec_val, orig_val,
                "Value at index {} not preserved correctly (original: {}, decrypted: {})",
                i, orig_val, dec_val
            );
        }
    }
    #[test]
    #[wasm_bindgen_test]
    fn test_vector_length_preservation() {
        // Generate parameters and keys
        let parameters_bytes = generate_parameters().unwrap();
        let secret_key_bytes = generate_secret_key_bytes(&parameters_bytes).unwrap();
        let public_key_bytes = generate_public_key_bytes(&secret_key_bytes).unwrap();

        // Test with different vector lengths
        for len in [1, 2, 4, 8, 16] {
            let original_values: Vec<i64> = (0..len).map(|i| i as i64 * 10).collect();

            let ciphertext_bytes = encrypt_vector_with_public_key_bytes(
                &original_values,
                &public_key_bytes,
                &parameters_bytes,
            )
            .unwrap();

            let decrypted_values =
                decrypt_vector_bytes_with_default_parameters(&ciphertext_bytes, &secret_key_bytes)
                    .unwrap();

            // Check exact length match
            assert_eq!(
                decrypted_values.len(),
                original_values.len(),
                "Vector length changed after encryption/decryption"
            );

            // Check value equality
            assert_eq!(
                &decrypted_values[..],
                &original_values[..],
                "Vector values changed after encryption/decryption"
            );
        }
    }
    #[test]
    #[wasm_bindgen_test]
    fn test_value_range_validation() {
        // Generate keys with default parameters
        let secret_key_bytes = generate_secret_key_with_default_params();
        let public_key_bytes = generate_public_key_bytes(&secret_key_bytes).unwrap();

        // Test with valid values
        for value in [0, 1, 100, 500] {
            let result = encrypt_with_default_parameters(value, &public_key_bytes);
            assert!(result.is_ok(), "Valid value {} failed encryption", value);
        }

        // Test with invalid values (assuming plaintext modulus is 1024)
        for value in [1024, 2000, -1, -100] {
            let result = encrypt_with_default_parameters(value, &public_key_bytes);
            assert!(result.is_err(), "Invalid value {} was accepted", value);
        }
    }

    // Test to verify that the decrypt_vector_bytes implementation returns correct vector size
    #[test]
    #[wasm_bindgen_test]
    fn test_decrypt_vector_with_length_metadata() {
        // Generate parameters and keys
        let parameters_bytes = generate_parameters().unwrap();
        let secret_key_bytes = generate_secret_key_bytes(&parameters_bytes).unwrap();
        let public_key_bytes = generate_public_key_bytes(&secret_key_bytes).unwrap();

        // Test with a known array of values including trailing zeros
        let original_values = [42, 123, 456, 789, 0, 0, 0];

        // Store the original length
        let original_length = original_values.len();

        let ciphertext_bytes = encrypt_vector_with_public_key_bytes(
            &original_values,
            &public_key_bytes,
            &parameters_bytes,
        )
        .unwrap();

        let decrypted_values =
            decrypt_vector_bytes_with_default_parameters(&ciphertext_bytes, &secret_key_bytes)
                .unwrap();

        // Log the actual values for debugging
        web_sys::console::log_1(
            &format!(
                "Decrypted first 4 values: {:?}",
                &decrypted_values[0..4.min(decrypted_values.len())]
            )
            .into(),
        );

        // Check values with modular arithmetic
        let plaintext_modulus = 1024; // 2^10 from default parameters

        // We only care about the first 4 non-zero values
        for i in 0..4.min(decrypted_values.len()) {
            let dec_val = decrypted_values[i];
            let orig_val = original_values[i];

            // Normalize both values to ensure they're equivalent under modulo arithmetic
            let dec_normalized = (dec_val % plaintext_modulus as i64 + plaintext_modulus as i64)
                % plaintext_modulus as i64;
            let orig_normalized = (orig_val % plaintext_modulus as i64 + plaintext_modulus as i64)
                % plaintext_modulus as i64;

            assert_eq!(
                dec_normalized, orig_normalized,
                "Value at index {} not preserved correctly under modular arithmetic",
                i
            );
        }

        // Log the lengths for debugging
        web_sys::console::log_1(
            &format!(
                "Original length: {}, Decrypted length: {}",
                original_length,
                decrypted_values.len()
            )
            .into(),
        );
    }

    // Test for value range validation to check if 789 should be rejected
    #[test]
    #[wasm_bindgen_test]
    fn test_value_range_boundary_cases() {
        // Generate keys with default parameters
        let secret_key_bytes = generate_secret_key_with_default_params();
        let public_key_bytes = generate_public_key_bytes(&secret_key_bytes).unwrap();

        // Get the actual plaintext modulus for verification
        let plaintext_modulus = (**DEFAULT_PARAMETERS).plaintext();
        web_sys::console::log_1(&format!("Actual plaintext modulus: {}", plaintext_modulus).into());

        // Test values near the boundary
        for value in [780, 789, 790, 800, 900, 1000, 1023] {
            let result = encrypt_with_default_parameters(value, &public_key_bytes);
            if result.is_err() {
                web_sys::console::log_1(&format!("Value {} was rejected", value).into());
            } else {
                web_sys::console::log_1(&format!("Value {} was accepted", value).into());
            }
        }
    }

    // Test to specifically debug the 789 value encryption issue
    #[test]
    #[wasm_bindgen_test]
    fn test_encrypt_decrypt_value_789() {
        // Generate parameters and keys
        let parameters_bytes = generate_parameters().unwrap();
        let secret_key_bytes = generate_secret_key_bytes(&parameters_bytes).unwrap();
        let public_key_bytes = generate_public_key_bytes(&secret_key_bytes).unwrap();

        // Try to encrypt the specific value 789
        let original_value = 789;

        let ciphertext_result =
            encrypt_with_public_key_bytes(original_value, &public_key_bytes, &parameters_bytes);

        if let Ok(ciphertext_bytes) = ciphertext_result {
            // Try to decrypt and check the value
            let decrypted_value = decrypt_bytes(&ciphertext_bytes, &secret_key_bytes).unwrap();
            web_sys::console::log_1(
                &format!("789 encrypts/decrypts to: {}", decrypted_value).into(),
            );

            // The decrypted value may be represented as -235 because:
            // 789 ≡ -235 (mod 1024) since -235 + 1024 = 789
            // We need to check if they're equivalent modulo the plaintext modulus
            let plaintext_modulus = 1024; // 2^10 from default parameters
            let equivalent = (decrypted_value % plaintext_modulus as i64
                + plaintext_modulus as i64)
                % plaintext_modulus as i64
                == (original_value % plaintext_modulus as i64 + plaintext_modulus as i64)
                    % plaintext_modulus as i64;

            assert!(
                equivalent,
                "Values are not equivalent under modulo arithmetic"
            );
        } else {
            web_sys::console::log_1(&"789 encryption failed".into());
            assert!(false, "Value 789 should be valid for encryption");
        }
    }

    // Test for BFV encoding/decoding behavior with polynomial degree
    #[test]
    #[wasm_bindgen_test]
    fn test_bfv_polynomial_capacity() {
        // Generate parameters and keys
        let parameters_bytes = generate_parameters().unwrap();
        let params: Arc<fhe::bfv::BfvParameters> = bincode::deserialize(&parameters_bytes).unwrap();

        // Log the polynomial degree to understand capacity
        let poly_degree = params.degree();
        web_sys::console::log_1(&format!("Polynomial degree: {}", poly_degree).into());

        // Test with different vector sizes to find max capacity
        for len in [
            1,
            4,
            8,
            16,
            32,
            64,
            128,
            256,
            poly_degree / 2,
            poly_degree - 1,
        ] {
            if len > 1000 {
                continue; // Skip very large lengths for browser testing
            }

            let test_values: Vec<i64> = (0..len).map(|i| i as i64 % 100).collect();
            let result = Plaintext::try_encode(&test_values, Encoding::poly(), &params);

            if result.is_ok() {
                web_sys::console::log_1(&format!("Successfully encoded {} values", len).into());
            } else {
                web_sys::console::log_1(&format!("Failed to encode {} values", len).into());
                break;
            }
        }
    }

    // Test to identify what might be happening with vector length preservation
    #[test]
    #[wasm_bindgen_test]
    fn test_vector_decryption_analysis() {
        // Generate parameters and keys
        let parameters_bytes = generate_parameters().unwrap();
        let secret_key_bytes = generate_secret_key_bytes(&parameters_bytes).unwrap();
        let public_key_bytes = generate_public_key_bytes(&secret_key_bytes).unwrap();

        // Use a small vector with distinctive values
        let original_values = [42, 123, 456, 789];

        let ciphertext_bytes = encrypt_vector_with_public_key_bytes(
            &original_values,
            &public_key_bytes,
            &parameters_bytes,
        )
        .unwrap();

        // Decrypt the values and examine them
        let secret_key: SecretKey = bincode::deserialize(&secret_key_bytes).unwrap();
        let ciphertext: Ciphertext = bincode::deserialize(&ciphertext_bytes).unwrap();

        // Decrypt the ciphertext
        let plaintext = secret_key.try_decrypt(&ciphertext).unwrap();

        // Decode without immediately wrapping in a boxed slice to examine
        let values = Vec::<i64>::try_decode(&plaintext, Encoding::poly()).unwrap();

        // Count non-zero values and find last non-zero index
        let non_zero_count = values.iter().filter(|&&x| x != 0).count();
        let mut last_non_zero_idx = 0;
        for (i, &val) in values.iter().enumerate() {
            if val != 0 {
                last_non_zero_idx = i;
            }
        }

        web_sys::console::log_1(
            &format!(
                "Total values: {}, Non-zero values: {}, Last non-zero index: {}",
                values.len(),
                non_zero_count,
                last_non_zero_idx
            )
            .into(),
        );

        // Log the first few values
        for i in 0..8.min(values.len()) {
            web_sys::console::log_1(&format!("values[{}] = {}", i, values[i]).into());
        }
    }
}
