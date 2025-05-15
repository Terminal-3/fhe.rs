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

// Predefined constant parameters for different security levels
static DEFAULT_PARAMETERS: Lazy<Arc<fhe::bfv::BfvParameters>> = Lazy::new(|| {
    BfvParametersBuilder::new()
        .set_degree(2048)
        .set_moduli(&[0x3fffffff000001])
        .set_plaintext_modulus(1 << 10)
        .build_arc()
        .expect("Failed to build default parameters")
});

// Higher security parameters (128-bit)
static SECURE_PARAMETERS: Lazy<Arc<fhe::bfv::BfvParameters>> = Lazy::new(|| {
    BfvParametersBuilder::new()
        .set_degree(4096)
        .set_moduli(&[0x3fffffff000001, 0x3ffffffef40001])
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
#[wasm_bindgen]
pub fn encrypt_with_default_parameters(
    value: i64,
    public_key_bytes: &[u8],
) -> Result<Box<[u8]>, JsValue> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

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
}
