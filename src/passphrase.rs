//! The setup access point's passphrase.
//!
//! The AP is always encrypted, so a passphrase always exists. When the
//! operator does not supply one we generate it, and it is shown to the user
//! as a QR code rather than typed — which frees us to pick an alphabet for
//! safety rather than for typing comfort.
//!
//! Two properties matter and both are tested:
//!
//! * The alphabet excludes every character that needs escaping in a `WIFI:`
//!   QR payload (`\ ; , : "`), so the payload can never be malformed by a
//!   generated value. Escaping is still implemented for *operator-supplied*
//!   passphrases, which can contain anything.
//! * The alphabet excludes visually ambiguous glyphs, so the fallback path —
//!   a human reading the passphrase off the screen and typing it — is not a
//!   coin toss between `0` and `O`.

use rand::{RngExt, rng};

use crate::secret::Secret;

/// Unambiguous alphanumerics: no `0`/`O`, `1`/`l`/`I`, `5`/`S`, `8`/`B`, and
/// nothing that needs QR escaping. 49 symbols => log2(49) ≈ 5.61 bits each.
const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzACDEFGHJKLMNPQRTUVWXYZ3467";

/// 14 symbols ≈ 78 bits. Comfortably inside WPA-PSK's 8..=63 character limit
/// with room for the operator to not think about it.
const DEFAULT_LEN: usize = 14;

/// WPA-PSK passphrases are 8..=63 ASCII characters (a 64-character value is
/// interpreted as a raw hex PMK instead, which is not what a portal wants).
pub const MIN_LEN: usize = 8;
pub const MAX_LEN: usize = 63;

/// Generate a fresh passphrase.
///
/// Call this **once per process run**, not once per AP activation. On a failed
/// join we re-raise the AP so the user's phone rejoins automatically as a
/// remembered network; that only works if the SSID and passphrase are
/// byte-identical to the ones the phone already stored.
pub fn generate() -> Secret {
    generate_with_len(DEFAULT_LEN)
}

fn generate_with_len(len: usize) -> Secret {
    let mut r = rng();
    let s: String = (0..len)
        .map(|_| ALPHABET[r.random_range(0..ALPHABET.len())] as char)
        .collect();
    Secret::new(s)
}

/// Why an operator-supplied passphrase was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PassphraseError {
    #[error(
        "WPA passphrase is too short: {0} characters, minimum is {min}",
        min = MIN_LEN
    )]
    TooShort(usize),
    #[error(
        "WPA passphrase is too long: {0} characters, maximum is {max}",
        max = MAX_LEN
    )]
    TooLong(usize),
    #[error("WPA passphrase must be printable ASCII")]
    NotAscii,
}

/// Validate a passphrase before it reaches NetworkManager.
///
/// NM would reject an out-of-range value too, but as an opaque
/// `InvalidProperty` D-Bus error. Checking here is what lets the portal say
/// "passwords must be at least 8 characters" instead.
pub fn validate(value: &str) -> Result<(), PassphraseError> {
    let len = value.chars().count();
    if len < MIN_LEN {
        return Err(PassphraseError::TooShort(len));
    }
    if len > MAX_LEN {
        return Err(PassphraseError::TooLong(len));
    }
    if !value.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return Err(PassphraseError::NotAscii);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_passphrase_is_valid_for_wpa() {
        for _ in 0..256 {
            let p = generate();
            assert!(validate(p.expose()).is_ok(), "rejected: {}", p.expose());
            assert_eq!(p.len(), DEFAULT_LEN);
        }
    }

    /// The property that keeps the QR payload well-formed by construction.
    #[test]
    fn generated_passphrase_never_needs_qr_escaping() {
        for _ in 0..256 {
            let p = generate();
            for c in p.expose().chars() {
                assert!(
                    !matches!(c, '\\' | ';' | ',' | ':' | '"'),
                    "generated a character needing QR escaping: {c:?}"
                );
            }
        }
    }

    #[test]
    fn alphabet_excludes_ambiguous_glyphs() {
        for c in b"0O1lI5S8B" {
            assert!(
                !ALPHABET.contains(c),
                "ambiguous glyph {:?} is in the alphabet",
                *c as char
            );
        }
    }

    #[test]
    fn generated_passphrases_differ() {
        let set: HashSet<String> = (0..64).map(|_| generate().expose().to_owned()).collect();
        assert_eq!(set.len(), 64, "generator produced a collision in 64 draws");
    }

    #[test]
    fn validate_enforces_wpa_bounds() {
        assert_eq!(validate("short").unwrap_err(), PassphraseError::TooShort(5));
        assert_eq!(validate("12345678"), Ok(()));
        assert_eq!(validate(&"a".repeat(63)), Ok(()));
        assert_eq!(
            validate(&"a".repeat(64)).unwrap_err(),
            PassphraseError::TooLong(64)
        );
        assert_eq!(
            validate("hunter2\u{1F600}").unwrap_err(),
            PassphraseError::NotAscii
        );
    }
}
