//! Deciding what credential a network needs.
//!
//! Worth testing hard: the portal asks the user for a password based on this
//! answer, so getting it wrong means either prompting for a credential that
//! does not exist or silently building a profile that cannot associate.
//!
//! There is exactly **one** classifier, [`classify`], over decoded
//! [`Features`]. NetworkManager's raw `NM80211ApSecurityFlags` bitfields are
//! decoded for us by `nmrs`, so this module deliberately does *not* carry a
//! second decoder: two of them would drift, and the drift would surface as
//! "WPA3 networks ask for a password twice" on somebody's desk six months
//! later.
//!
//! Three cases are easy to get wrong:
//!
//! * **OWE** ("enhanced open") sets the privacy bit but takes no passphrase.
//!   A naive `PRIVACY => ask for a password` check prompts for one that does
//!   not exist, and the join then fails with no useful explanation.
//! * **WEP** has no key-management bit of its own. It is only inferrable as
//!   "the privacy bit is set and nothing else is".
//! * **WPA2/WPA3 transitional** advertises SAE *and* PSK. Joining it as
//!   `wpa-psk` works with every client; insisting on `sae` does not.

/// What an access point advertises.
///
/// One field per `NM80211ApSecurityFlags` key-management bit that changes
/// what we must ask the user for, plus the privacy bit from
/// `NM80211ApFlags`. Ciphers (TKIP, CCMP, WEP40/104) and WPS are
/// deliberately absent: they affect how an association is negotiated, not
/// what credential a human has to supply.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Features {
    /// The access point advertises encryption of some kind.
    pub privacy: bool,
    /// Pre-shared key: WPA/WPA2-Personal.
    pub psk: bool,
    /// 802.1X: enterprise, and the only case needing an identity.
    pub eap: bool,
    /// Simultaneous Authentication of Equals: WPA3-Personal.
    pub sae: bool,
    /// Opportunistic Wireless Encryption: encrypted, but no credential.
    pub owe: bool,
    /// OWE transition mode (an open BSS paired with an OWE one).
    pub owe_transition: bool,
    /// WPA3-Enterprise 192-bit.
    pub eap_suite_b_192: bool,
}

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

    /// Will we join it at all?
    ///
    /// WEP is listed, so a user looking for their network finds it and
    /// learns why it cannot be used, but never joined: its encryption has
    /// been broken for two decades, and a device set up on it is exposed
    /// to anyone in radio range.
    pub fn is_supported(self) -> bool {
        !matches!(self, Security::Wep)
    }

    /// Does it also need a username?
    pub fn needs_identity(self) -> bool {
        matches!(self, Security::Enterprise)
    }
}

/// Classify an access point.
pub fn classify(f: Features) -> Security {
    // Enterprise wins the dispatch. An access point offering both 802.1X and
    // PSK is rare, but if we guessed PSK we would never ask for the identity
    // and the association could not complete.
    if f.eap || f.eap_suite_b_192 {
        return Security::Enterprise;
    }

    match (f.sae, f.psk) {
        (true, true) => Security::SaeTransitional,
        (true, false) => Security::Sae,
        (false, true) => Security::WpaPsk,
        (false, false) => {
            if f.owe || f.owe_transition {
                Security::Owe
            } else if f.privacy {
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

    /// Build `Features` by mutation, so each case names only the bits it
    /// actually sets.
    fn f(set: impl Fn(&mut Features)) -> Features {
        let mut features = Features::default();
        set(&mut features);
        features
    }

    #[test]
    fn classification_table() {
        let cases: &[(&str, Features, Security)] = &[
            ("open", f(|_| {}), Security::Open),
            (
                "wep: privacy and nothing else",
                f(|x| x.privacy = true),
                Security::Wep,
            ),
            (
                "wpa2-psk",
                f(|x| {
                    x.privacy = true;
                    x.psk = true;
                }),
                Security::WpaPsk,
            ),
            (
                "wpa3-sae only",
                f(|x| {
                    x.privacy = true;
                    x.sae = true;
                }),
                Security::Sae,
            ),
            (
                "wpa2/wpa3 transitional",
                f(|x| {
                    x.privacy = true;
                    x.sae = true;
                    x.psk = true;
                }),
                Security::SaeTransitional,
            ),
            (
                "wpa-enterprise",
                f(|x| {
                    x.privacy = true;
                    x.eap = true;
                }),
                Security::Enterprise,
            ),
            (
                "wpa3-enterprise 192-bit",
                f(|x| {
                    x.privacy = true;
                    x.eap_suite_b_192 = true;
                }),
                Security::Enterprise,
            ),
            (
                "802.1x and psk together: enterprise wins",
                f(|x| {
                    x.privacy = true;
                    x.eap = true;
                    x.psk = true;
                }),
                Security::Enterprise,
            ),
            (
                "owe",
                f(|x| {
                    x.privacy = true;
                    x.owe = true;
                }),
                Security::Owe,
            ),
            (
                "owe transition mode",
                f(|x| {
                    x.privacy = true;
                    x.owe_transition = true;
                }),
                Security::Owe,
            ),
        ];

        for (name, features, expected) in cases {
            assert_eq!(classify(*features), *expected, "misclassified {name}");
        }
    }

    /// OWE is encrypted but credential-free. Prompting for a password here
    /// is the bug this test exists to prevent.
    #[test]
    fn owe_must_not_prompt_for_a_password() {
        let s = classify(f(|x| {
            x.privacy = true;
            x.owe = true;
        }));
        assert_eq!(s, Security::Owe);
        assert!(!s.needs_passphrase());
        assert!(!s.needs_identity());
    }

    #[test]
    fn open_networks_prompt_for_nothing() {
        let s = classify(Features::default());
        assert!(!s.needs_passphrase());
        assert!(!s.needs_identity());
    }

    #[test]
    fn enterprise_needs_an_identity() {
        let s = classify(f(|x| {
            x.privacy = true;
            x.eap = true;
        }));
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

    /// Without the privacy bit there is no encryption at all.
    #[test]
    fn no_privacy_and_no_key_management_is_open() {
        assert_eq!(classify(Features::default()), Security::Open);
    }

    #[test]
    fn serialises_in_kebab_case_for_the_portal() {
        assert_eq!(
            serde_json::to_string(&Security::SaeTransitional).unwrap(),
            "\"sae-transitional\""
        );
        assert_eq!(
            serde_json::to_string(&Security::WpaPsk).unwrap(),
            "\"wpa-psk\""
        );
    }
}
