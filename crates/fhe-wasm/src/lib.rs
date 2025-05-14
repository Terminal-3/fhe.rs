use fhe::bfv::{BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::*;
use rand::{SeedableRng, rngs::StdRng};
use std::convert::TryFrom;
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen(start)]
pub fn start() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Generates FHE parameters and returns them as a serialized byte array
#[wasm_bindgen]
pub fn generate_parameters() -> Result<Box<[u8]>, JsValue> {
    let parameters = BfvParametersBuilder::new()
        .set_degree(2048)
        .set_moduli(&[0x3fffffff000001])
        .set_plaintext_modulus(1 << 10)
        .build_arc()
        .map_err(|e| JsValue::from_str(&format!("Parameter building error: {}", e)))?;

    // Serialize parameters to bytes
    let serialized = bincode::serialize(&parameters)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    Ok(serialized.into_boxed_slice())
}

/// Generates a new secret key and returns it as a serialized byte array
#[wasm_bindgen]
pub fn generate_secret_key_bytes() -> Result<Box<[u8]>, JsValue> {
    let parameters = BfvParametersBuilder::new()
        .set_degree(2048)
        .set_moduli(&[0x3fffffff000001])
        .set_plaintext_modulus(1 << 10)
        .build_arc()
        .map_err(|e| JsValue::from_str(&format!("Parameter building error: {}", e)))?;

    let mut rng = StdRng::from_entropy();
    let secret_key = SecretKey::random(&parameters, &mut rng);

    // Serialize the secret key to bytes
    let serialized = bincode::serialize(&secret_key)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    Ok(serialized.into_boxed_slice())
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
        let secret_key_bytes = generate_secret_key_bytes().unwrap();

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
        let secret_key_bytes = generate_secret_key_bytes().unwrap();

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
