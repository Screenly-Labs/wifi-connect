//! Deriving a network's security type from NetworkManager's flag bitfields.
//!
//! Pure, and worth testing hard: the portal asks the user for a password
//! based on this answer, so getting it wrong means either prompting for a
//! credential that does not exist or silently building a profile that cannot
//! associate.
//!
//! Three cases are easy to get wrong:
//!
//! * **OWE** ("enhanced open") sets the privacy bit but takes no passphrase.
//!   A naive `PRIVACY => ask for a password` check prompts for one that does
//!   not exist, and the join then fails with no useful explanation.
//! * **WEP** has no key-management bit of its own. It is only inferrable as
//!   "the privacy bit is set and *both* the WPA and RSN flags are zero".
//! * **WPA2/WPA3 transitional** advertises SAE *and* PSK. Joining it as
//!   `wpa-psk` works with every client; insisting on `sae` does not.

/// `NM80211ApFlags`.
pub const AP_FLAGS_PRIVACY: u32 = 0x0000_0001;

/// `NM80211ApSecurityFlags`.
pub const SEC_KEY_MGMT_PSK: u32 = 0x0000_0100;
pub const SEC_KEY_MGMT_802_1X: u32 = 0x0000_0200;
pub const SEC_KEY_MGMT_SAE: u32 = 0x0000_0400;
pub const SEC_KEY_MGMT_OWE: u32 = 0x0000_0800;
pub const SEC_KEY_MGMT_OWE_TM: u32 = 0x0000_1000;
pub const SEC_KEY_MGMT_EAP_SUITE_B_192: u32 = 0x0000_2000;

/// What the portal must ask the user for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Security {
    /// No credential at all.
    Open,
    /// Opportunistic Wireless Encryption: encrypted, but still no credential.
    Owe,
    /// Deprecated and weak, but still occasionally in the field.
    Wep,
    /// The overwhelmingly common case.
    WpaPsk,
    /// WPA3-Personal only.
    Sae,
    /// WPA2/WPA3 transitional: advertises both SAE and PSK.
    SaeTransitional,
    /// 802.1X. Needs an identity as well as a password.
    Enterprise,
}

impl Security {
    /// Does the portal need to show a password field?
    pub fn needs_passphrase(self) -> bool {
        matches!(
            self,
            Security::Wep | Security::WpaPsk | Security::Sae | Security::SaeTransitional
        )
    }

    /// Does it also need a username?
    pub fn needs_identity(self) -> bool {
        matches!(self, Security::Enterprise)
    }
}

/// Classify an access point from the three bitfields NetworkManager exposes.
pub fn classify(flags: u32, wpa_flags: u32, rsn_flags: u32) -> Security {
    let both = wpa_flags | rsn_flags;

    // Enterprise wins the dispatch. An AP offering both 802.1X and PSK is
    // rare, but if we guessed PSK there we would never ask for the identity
    // and the association could not complete.
    if both & (SEC_KEY_MGMT_802_1X | SEC_KEY_MGMT_EAP_SUITE_B_192) != 0 {
        return Security::Enterprise;
    }

    let sae = both & SEC_KEY_MGMT_SAE != 0;
    let psk = both & SEC_KEY_MGMT_PSK != 0;

    match (sae, psk) {
        (true, true) => Security::SaeTransitional,
        (true, false) => Security::Sae,
        (false, true) => Security::WpaPsk,
        (false, false) => {
            if both & (SEC_KEY_MGMT_OWE | SEC_KEY_MGMT_OWE_TM) != 0 {
                Security::Owe
            } else if flags & AP_FLAGS_PRIVACY != 0 {
                // Privacy with no WPA/RSN information element at all.
                Security::Wep
            } else {
                Security::Open
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_table() {
        let cases: &[(&str, u32, u32, u32, Security)] = &[
            ("open", 0, 0, 0, Security::Open),
            ("wep", AP_FLAGS_PRIVACY, 0, 0, Security::Wep),
            (
                "wpa2-psk",
                AP_FLAGS_PRIVACY,
                0,
                SEC_KEY_MGMT_PSK,
                Security::WpaPsk,
            ),
            (
                "wpa-psk (legacy wpa ie only)",
                AP_FLAGS_PRIVACY,
                SEC_KEY_MGMT_PSK,
                0,
                Security::WpaPsk,
            ),
            (
                "wpa3-sae only",
                AP_FLAGS_PRIVACY,
                0,
                SEC_KEY_MGMT_SAE,
                Security::Sae,
            ),
            (
                "wpa2/wpa3 transitional",
                AP_FLAGS_PRIVACY,
                0,
                SEC_KEY_MGMT_SAE | SEC_KEY_MGMT_PSK,
                Security::SaeTransitional,
            ),
            (
                "wpa-enterprise",
                AP_FLAGS_PRIVACY,
                0,
                SEC_KEY_MGMT_802_1X,
                Security::Enterprise,
            ),
            (
                "wpa3-enterprise 192-bit",
                AP_FLAGS_PRIVACY,
                0,
                SEC_KEY_MGMT_EAP_SUITE_B_192,
                Security::Enterprise,
            ),
            (
                "802.1x and psk together: enterprise wins",
                AP_FLAGS_PRIVACY,
                0,
                SEC_KEY_MGMT_802_1X | SEC_KEY_MGMT_PSK,
                Security::Enterprise,
            ),
            ("owe", AP_FLAGS_PRIVACY, 0, SEC_KEY_MGMT_OWE, Security::Owe),
            (
                "owe transition mode",
                AP_FLAGS_PRIVACY,
                0,
                SEC_KEY_MGMT_OWE_TM,
                Security::Owe,
            ),
        ];

        for (name, flags, wpa, rsn, expected) in cases {
            assert_eq!(
                classify(*flags, *wpa, *rsn),
                *expected,
                "misclassified {name}"
            );
        }
    }

    /// OWE is encrypted but credential-free. Prompting for a password here
    /// is the bug this test exists to prevent.
    #[test]
    fn owe_must_not_prompt_for_a_password() {
        let s = classify(AP_FLAGS_PRIVACY, 0, SEC_KEY_MGMT_OWE);
        assert_eq!(s, Security::Owe);
        assert!(!s.needs_passphrase());
        assert!(!s.needs_identity());
    }

    #[test]
    fn open_networks_prompt_for_nothing() {
        let s = classify(0, 0, 0);
        assert!(!s.needs_passphrase());
        assert!(!s.needs_identity());
    }

    #[test]
    fn enterprise_needs_both_fields() {
        let s = classify(AP_FLAGS_PRIVACY, 0, SEC_KEY_MGMT_802_1X);
        assert!(s.needs_passphrase() || s.needs_identity());
        assert!(s.needs_identity());
    }

    #[test]
    fn personal_networks_prompt_for_a_password_only() {
        for s in [
            Security::WpaPsk,
            Security::Sae,
            Security::SaeTransitional,
            Security::Wep,
        ] {
            assert!(s.needs_passphrase(), "{s:?} should want a password");
            assert!(!s.needs_identity(), "{s:?} should not want an identity");
        }
    }

    /// Without the privacy bit there is no encryption, whatever stray bits
    /// a vendor sets elsewhere.
    #[test]
    fn no_privacy_bit_and_no_key_mgmt_is_open() {
        assert_eq!(classify(0, 0, 0), Security::Open);
        assert_eq!(
            classify(0xffff_0000 & !AP_FLAGS_PRIVACY, 0, 0),
            Security::Open
        );
    }

    #[test]
    fn serialises_in_kebab_case_for_the_portal() {
        let json = serde_json::to_string(&Security::SaeTransitional).unwrap();
        assert_eq!(json, "\"sae-transitional\"");
        assert_eq!(
            serde_json::to_string(&Security::WpaPsk).unwrap(),
            "\"wpa-psk\""
        );
    }
}
