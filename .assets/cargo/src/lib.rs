//! Test crate for E2E native client testing

/// Returns a greeting message
pub fn hello() -> &'static str {
    "Hello from test-crate!"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello() {
        assert_eq!(hello(), "Hello from test-crate!");
    }
}
