//! A string that must never reach a log line.
//!
//! WiFi passphrases flow through the config, the portal and the
//! NetworkManager settings map. `Debug` is derived somewhere on nearly every
//! struct along that path, and NetworkManager itself occasionally echoes a
//! property value back inside an `InvalidProperty` error string. A newtype
//! whose `Debug` and `Display` both redact is the only reliable defence.

use std::fmt;

/// Wraps a secret so that formatting it cannot leak it.
///
/// The inner value is reachable only through [`Secret::expose`], which is
/// deliberately noisy to read at the call site.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The only way to read the secret. Named so that `grep expose` finds
    /// every place one escapes.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak() {
        let s = Secret::new("hunter2");
        assert!(!format!("{s:?}").contains("hunter2"));
        assert_eq!(format!("{s:?}"), "Secret(***)");
    }

    #[test]
    fn display_does_not_leak() {
        let s = Secret::new("hunter2");
        assert!(!format!("{s}").contains("hunter2"));
    }

    /// A `Secret` nested inside a derived-`Debug` struct is the realistic
    /// leak: nobody formats the secret directly, they format the config.
    #[test]
    fn nested_debug_does_not_leak() {
        #[derive(Debug)]
        struct Config {
            #[allow(dead_code)]
            passphrase: Secret,
        }
        let c = Config {
            passphrase: Secret::new("hunter2"),
        };
        assert!(!format!("{c:?}").contains("hunter2"));
    }

    #[test]
    fn expose_returns_the_value() {
        assert_eq!(Secret::new("hunter2").expose(), "hunter2");
    }
}
