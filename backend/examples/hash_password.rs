use bcrypt::{hash, verify, DEFAULT_COST};

fn main() {
    let password = "admin123";
    let hashed = hash(password, DEFAULT_COST).unwrap();
    println!("New hash: {}", hashed);

    // Verify the old hash
    let old_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.TMANBAKhFvJU9K";
    match verify(password, old_hash) {
        Ok(true) => println!("Old hash verifies correctly!"),
        Ok(false) => println!("Old hash does NOT verify!"),
        Err(e) => println!("Error verifying old hash: {}", e),
    }
}
