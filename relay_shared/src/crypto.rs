use secp256k1::ecdh::SharedSecret;
use secp256k1::Secp256k1;
use secp256k1::{PublicKey, SecretKey};
use sha2::Digest;

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

/**
 * Generate a new keypair
 */
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    Secp256k1::new().generate_keypair(&mut rand::thread_rng())
}

/**
 * Convert a public key to a byte array
 */
pub fn pubkey_to_bytes(pubkey: &PublicKey) -> Vec<u8> {
    pubkey.serialize().to_vec()
}

/**
 * Convert a byte array to a public key
 */
pub fn pubkey_from_bytes(bytes: &[u8]) -> PublicKey {
    PublicKey::from_slice(bytes).unwrap()
}

/**
 * Generate a shared secret from your secret key and their public key
 */
pub fn generate_shared_secret(
    their_public_key: &PublicKey,
    your_secret_key: &SecretKey,
) -> SharedSecret {
    SharedSecret::new(their_public_key, your_secret_key)
}

/**
 * Get a handle to chacha20 with the given key
 */
pub fn get_chacha20(key: &[u8]) -> chacha20::ChaCha20 {
    // Ensure the key is exactly 32 bytes
    let key: [u8; 32] = key.try_into().expect("Key must be exactly 32 bytes");

    // Provide a separate 12-byte nonce (e.g., using a constant or random value)
    let nonce: [u8; 12] = [0u8; 12]; // Example nonce; replace with your own logic

    chacha20::ChaCha20::new(&key.into(), &nonce.into())
}

// These enc/dec funcs are actually the same, but separated
// for readability:
/**
 * Encrypt with a chacha instance
 */
pub fn encrypt_with_chacha(chacha: &mut chacha20::ChaCha20, data: &mut [u8]) -> () {
    chacha.apply_keystream(data);
}

/**
 * Decrypt with a chacha instance
 */
pub fn decrypt_with_chacha(chacha: &mut chacha20::ChaCha20, data: &mut [u8]) -> () {
    chacha.apply_keystream(data);
}

/**
 * Generate Random UIUD (this
 * is a key for chacha20)
 */
pub fn generate_uuid() -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(rand::random::<[u8; 32]>());
    hasher.finalize().into()
}

/**
 * Encrypt with a chacha instance and return the new data
 */
pub fn apply_keystream_and_return_new(chacha: &mut chacha20::ChaCha20, data: &mut [u8]) -> Vec<u8> {
    let mut new_data = data.to_vec();
    chacha.apply_keystream(&mut new_data);
    new_data
}
