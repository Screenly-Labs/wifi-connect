//! SSID handling.
//!
//! An SSID is 0-32 arbitrary octets. It is *not* required to be UTF-8, and
//! NetworkManager hands it to us as `ay` on
//! `org.freedesktop.NetworkManager.AccessPoint.Ssid`. Round-tripping it
//! through a `String` is lossy: invalid sequences become U+FFFD and the
//! profile we then build will never match the network the user picked.
//!
//! So the raw bytes are the identity, carried through the portal as hex, and
//! the lossy string exists only for display.

use std::fmt;

use rand::{RngExt, rng};

/// Upper-case subset of the passphrase alphabet.
///
/// Same two properties, for the same reasons (see `passphrase`): nothing
/// here needs escaping inside a `WIFI:` QR payload, and no two glyphs are
/// easy to confuse. Upper case only because this one is *compared* rather
/// than typed — someone holds a phone showing a list of networks against a
/// screen showing the name, and `k3Qm` against `K3qM` is a worse job than
/// it needs to be.
pub const SUFFIX_ALPHABET: &[u8] = b"ACDEFGHJKLMNPQRTUVWXYZ3467";

/// The separator between the operator's prefix and the random part.
pub const SUFFIX_SEPARATOR: char = '-';

/// 802.11 caps the SSID information element at 32 octets.
pub const MAX_BYTES: usize = 32;

/// `prefix` with `len` random characters appended, or `prefix` unchanged
/// when `len` is 0.
///
/// Why this exists: five screens unboxed in the same room all broadcast
/// the same setup network. A phone shows one entry for all of them, joins
/// whichever is loudest, and the installer configures a device at random
/// while looking at a different one — and because each portal generates
/// its own passphrase, four of the five cannot even be joined with the
/// credentials on the screen in front of them.
///
/// Random per run rather than derived from the MAC: the passphrase and
/// the QR already change on every run, so a stable name would be the only
/// thing implying continuity it does not have. An integrator who wants a
/// fixed name sets the suffix length to 0 and takes the collision.
pub fn with_random_suffix(prefix: &str, len: usize) -> String {
    if len == 0 {
        return prefix.to_string();
    }

    let mut out = String::with_capacity(prefix.len() + 1 + len);
    out.push_str(prefix);
    out.push(SUFFIX_SEPARATOR);
    let mut r = rng();
    for _ in 0..len {
        out.push(SUFFIX_ALPHABET[r.random_range(0..SUFFIX_ALPHABET.len())] as char);
    }
    out
}

/// The byte length `with_random_suffix` will produce, without generating
/// it — so a too-long name is rejected at startup rather than at the radio.
pub fn suffixed_len(prefix: &str, len: usize) -> usize {
    if len == 0 {
        prefix.len()
    } else {
        // The alphabet is ASCII, so characters and bytes agree here even
        // though the prefix may be multi-byte.
        prefix.len() + 1 + len
    }
}

/// The raw bytes of an SSID, as NetworkManager reports them.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Ssid(Vec<u8>);

impl Ssid {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Hex, for carrying the exact bytes through JSON and form fields.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        hex::decode(s).map(Self)
    }

    /// Lossy UTF-8, for showing a human. Never feed this back into a
    /// settings map — use [`Ssid::as_bytes`].
    pub fn to_display_string(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }
}

impl fmt::Debug for Ssid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ssid({:?})", self.to_display_string())
    }
}

impl fmt::Display for Ssid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_display_string())
    }
}

impl From<&str> for Ssid {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    /// The bug this exists for: five screens, one room, one name.
    #[test]
    fn five_portals_in_one_room_get_five_names() {
        let names: std::collections::HashSet<String> = (0..5)
            .map(|_| with_random_suffix("Anthias Setup", 4))
            .collect();

        assert_eq!(names.len(), 5, "two of five collided: {names:?}");
        for n in &names {
            assert!(n.starts_with("Anthias Setup-"), "{n} lost its prefix");
            assert_eq!(n.len(), "Anthias Setup".len() + 1 + 4);
        }
    }

    /// An integrator who prints the name on a sticker turns this off.
    #[test]
    fn a_zero_length_suffix_leaves_the_name_alone() {
        assert_eq!(with_random_suffix("Anthias Setup", 0), "Anthias Setup");
        assert_eq!(suffixed_len("Anthias Setup", 0), "Anthias Setup".len());
    }

    /// The SSID goes into the `WIFI:S:...;` QR payload, where `\ ; , : "`
    /// all need escaping. The alphabet excludes them so a generated name
    /// can never be the thing that malforms the payload — the same
    /// property the passphrase alphabet carries, for the same reason.
    #[test]
    fn the_suffix_alphabet_cannot_malform_a_qr_payload() {
        for b in SUFFIX_ALPHABET {
            assert!(
                !matches!(*b, b'\\' | b';' | b',' | b':' | b'"'),
                "{} needs escaping in a WIFI: payload",
                *b as char
            );
            assert!(
                b.is_ascii_alphanumeric(),
                "{} is not plain ASCII",
                *b as char
            );
        }
    }

    /// Read off a screen and compared against a phone's network list.
    ///
    /// Pairwise, not a blocklist: a glyph is only confusable with another
    /// glyph that is also available. `Z` stays because `2` is absent, and
    /// banning it outright would shrink the alphabet for nothing.
    #[test]
    fn the_suffix_alphabet_has_no_confusable_pairs() {
        const CONFUSABLE: &[(u8, u8)] = &[
            (b'0', b'O'),
            (b'0', b'D'),
            (b'0', b'Q'),
            (b'1', b'I'),
            (b'1', b'L'),
            (b'I', b'L'),
            (b'2', b'Z'),
            (b'5', b'S'),
            (b'8', b'B'),
            // 6/G and U/V are deliberately absent: they are distinct in
            // any sans-serif face, and the passphrase alphabet this
            // derives from keeps all four. The list is for glyphs people
            // actually transcribe wrongly, not for every pair that
            // rhymes.
        ];

        for (a, b) in CONFUSABLE {
            assert!(
                !(SUFFIX_ALPHABET.contains(a) && SUFFIX_ALPHABET.contains(b)),
                "{} and {} are both available and easy to mix up",
                *a as char,
                *b as char
            );
        }

        // And one case to the alphabet itself: upper case only, so the
        // comparison is never between `k3Qm` and `K3qM`.
        for b in SUFFIX_ALPHABET {
            assert!(!b.is_ascii_lowercase(), "{} mixes case", *b as char);
        }
    }

    /// `suffixed_len` is what validation trusts, so it must agree with
    /// what the generator actually produces — including for a multi-byte
    /// prefix, where characters and bytes part company.
    #[test]
    fn the_predicted_length_matches_the_generated_one() {
        for (prefix, len) in [("Anthias Setup", 4), ("\u{1F600}\u{1F600}", 6), ("x", 1)] {
            assert_eq!(
                with_random_suffix(prefix, len).len(),
                suffixed_len(prefix, len),
                "prediction disagreed for {prefix:?}"
            );
        }
    }

    use super::*;

    #[test]
    fn hex_round_trip_preserves_bytes() {
        let ssid = Ssid::new(vec![0x48, 0x6f, 0x6d, 0x65]);
        assert_eq!(ssid.to_hex(), "486f6d65");
        assert_eq!(Ssid::from_hex("486f6d65").unwrap(), ssid);
    }

    /// The regression this module exists to prevent: a non-UTF-8 SSID must
    /// survive the portal round-trip byte-for-byte, even though its display
    /// form is lossy.
    #[test]
    fn non_utf8_ssid_survives_round_trip() {
        let raw = vec![0x4d, 0x79, 0xff, 0xfe, 0x4e, 0x65, 0x74];
        let ssid = Ssid::new(raw.clone());

        assert!(ssid.to_display_string().contains('\u{fffd}'));

        let recovered = Ssid::from_hex(&ssid.to_hex()).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_slice());

        // And the lossy path would NOT have survived.
        let lossy = Ssid::from(ssid.to_display_string().as_str());
        assert_ne!(lossy.as_bytes(), raw.as_slice());
    }

    #[test]
    fn empty_ssid_is_detected() {
        // Hidden networks report an empty SSID; the scan list must drop them.
        assert!(Ssid::new(Vec::new()).is_empty());
    }

    #[test]
    fn debug_shows_the_readable_form() {
        assert_eq!(format!("{:?}", Ssid::from("Home")), r#"Ssid("Home")"#);
    }
}
