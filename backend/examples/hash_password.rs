//! Mint a bcrypt hash and verify a known one through the crypto facade
//! (`crate::crypto::password`), the only place bcrypt is used (#5579).

use artifact_keeper_backend::crypto::password::{hash_bcrypt, verify, BCRYPT_DEFAULT_COST};

fn main() {
    let password = "admin123";
    let hashed = hash_bcrypt(password, BCRYPT_DEFAULT_COST).unwrap();
    println!("New hash: {}", hashed);

    // Verify the old hash
    let old_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.TMANBAKhFvJU9K";
    match verify(password, old_hash) {
        Ok(true) => println!("Old hash verifies correctly!"),
        Ok(false) => println!("Old hash does NOT verify!"),
        Err(e) => println!("Error verifying old hash: {}", e),
    }
}
