//! Handler for the `version` subcommand.
//!
//! Displays version, target triple, and build date information.

/// Version string from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Package name from Cargo.toml.
pub const PKG_NAME: &str = env!("CARGO_PKG_NAME");

/// Target triple (set at compile time).
pub const TARGET: &str = env!("TARGET");

/// Prints version information to stdout.
pub fn handle_version() {
    println!("{} v{}", PKG_NAME, VERSION);
    println!("  target:  {}", TARGET);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_is_not_empty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_pkg_name() {
        assert_eq!(PKG_NAME, "marmosyn");
    }

    #[test]
    fn test_handle_version_does_not_panic() {
        handle_version();
    }
}
