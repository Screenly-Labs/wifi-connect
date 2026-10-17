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

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
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
