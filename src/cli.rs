//! Command line and environment.
//!
//! Upstream's eight flags all keep working, name, short form and
//! environment variable alike. Dropping flags from a tool people are
//! migrating *from* is how you make migration not happen, so every one of
//! them is honoured even where we would have named it differently.
//!
//! Environment variables are accepted under both the legacy bare names
//! (`PORTAL_SSID`) and a `WIFI_CONNECT_`-prefixed form. The prefix matters
//! in a container, where the environment is shared with other services and
//! a bare `PORTAL_SSID` could plausibly belong to something else.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

use crate::nm::ApSecurity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum SecurityMode {
    /// WPA2-PSK (CCMP) — the interoperable default. Same as `wpa2`.
    Auto,
    Wpa2,
    Wpa3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum ThemeMode {
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "wifi-connect",
    version,
    about = "Raise an encrypted WiFi access point with a captive portal, and join the network the user chooses.",
    long_about = None,
)]
pub struct Cli {
    /// SSID of the setup access point.
    #[arg(short = 's', long, env = "PORTAL_SSID", default_value = "WiFi Connect")]
    pub portal_ssid: String,

    /// WPA passphrase for the setup access point.
    ///
    /// Omit it and one is generated for this run and shown as a QR code.
    /// Upstream defaults to an *open* access point; we do not.
    #[arg(short = 'p', long, env = "PORTAL_PASSPHRASE")]
    pub portal_passphrase: Option<String>,

    /// Security for the setup access point.
    ///
    /// `auto` (the default) and `wpa2` both raise a WPA2-PSK/CCMP access
    /// point — the mode every client and every target chipset handle.
    /// `wpa3` raises a WPA3-SAE access point; it is opt-in because AP-mode
    /// SAE on the brcmfmac radios in every Raspberry Pi is unreliable in
    /// practice (the AP comes up but clients fail to associate), so it is
    /// not safe as a default. There is no automatic SAE-to-WPA2 fallback:
    /// the AP cannot see a client's association failure, so a failed SAE
    /// association looks identical to a healthy AP with no clients yet.
    #[arg(long, env = "WIFI_CONNECT_PORTAL_SECURITY", default_value = "auto")]
    pub portal_security: SecurityMode,

    /// Raise the access point with NO encryption.
    ///
    /// Everything the user types then crosses the air in clear. Provided
    /// only for parity with upstream's default; it is not CRA-compliant.
    #[arg(
        long,
        env = "WIFI_CONNECT_INSECURE_OPEN_PORTAL",
        default_value_t = false
    )]
    pub insecure_open_portal: bool,

    /// Join enterprise (802.1X) networks WITHOUT verifying the RADIUS
    /// server's certificate.
    ///
    /// By default the server must chain to the host's system CA store, and
    /// to the server domain the user typed, when they typed one. A network
    /// whose RADIUS server uses a private CA will then fail to join; this
    /// restores the old accept-anything behaviour for it. Anyone in radio
    /// range can then impersonate the network and capture the user's
    /// MSCHAPv2 exchange, which cracks offline to their password hash.
    #[arg(long, env = "WIFI_CONNECT_INSECURE_EAP", default_value_t = false)]
    pub insecure_eap_skip_server_verification: bool,

    /// Gateway address of the setup network.
    #[arg(
        short = 'g',
        long,
        env = "PORTAL_GATEWAY",
        default_value = "192.168.42.1"
    )]
    pub portal_gateway: Ipv4Addr,

    /// DHCP range of the setup network, as `first,last`.
    #[arg(
        short = 'd',
        long,
        env = "PORTAL_DHCP_RANGE",
        default_value = "192.168.42.2,192.168.42.254"
    )]
    pub portal_dhcp_range: String,

    /// Listening port of the portal web server.
    ///
    /// Captive-portal detection assumes port 80; changing this stops the
    /// sign-in sheet opening automatically.
    #[arg(short = 'o', long, env = "PORTAL_LISTENING_PORT", default_value_t = 80)]
    pub portal_listening_port: u16,

    /// WiFi interface to use. Auto-detected when omitted.
    #[arg(
        short = 'i',
        long,
        env = "WIFI_CONNECT_INTERFACE",
        alias = "portal-interface",
        visible_alias = "portal-interface"
    )]
    pub interface: Option<String>,

    /// Exit after this many seconds with no successful join. 0 disables it.
    #[arg(short = 'a', long, env = "ACTIVITY_TIMEOUT", default_value_t = 0)]
    pub activity_timeout: u64,

    /// Serve the portal UI from this directory instead of the embedded copy.
    #[arg(short = 'u', long, env = "UI_DIRECTORY")]
    pub ui_directory: Option<PathBuf>,

    /// Write the join QR code (SVG and a text form) into this directory.
    ///
    /// This is the primary way the generated passphrase reaches the user:
    /// the host application displays it on the device's screen.
    #[arg(long, env = "WIFI_CONNECT_QR_OUTPUT")]
    pub qr_output: Option<PathBuf>,

    /// Do not print the QR code to stdout.
    #[arg(long, env = "WIFI_CONNECT_NO_QR_STDOUT", default_value_t = false)]
    pub no_qr_stdout: bool,

    /// Raise the portal even when the device is already online.
    #[arg(long, env = "WIFI_CONNECT_FORCE", default_value_t = false)]
    pub force: bool,

    /// Seconds to let a saved network come up before showing the portal.
    ///
    /// Only applied when at least one WiFi profile is saved: a first-boot
    /// device has nothing to wait for.
    #[arg(long, env = "WIFI_CONNECT_WAIT_FOR_CONNECTION", default_value_t = 60)]
    pub wait_for_connection: u64,

    /// Seconds to allow for one join attempt.
    #[arg(long, env = "WIFI_CONNECT_CONNECTION_TIMEOUT", default_value_t = 45)]
    pub connection_timeout: u64,

    /// Product name shown in the portal.
    #[arg(long, env = "WIFI_CONNECT_BRAND_NAME", default_value = "WiFi Connect")]
    pub brand_name: String,

    /// Path to a stylesheet served at `/brand.css`, loaded after the
    /// portal's own CSS.
    ///
    /// Override the role tokens (`--color-accent` and friends) and nothing
    /// else; see `ui/dist/brand.example.css`. The primitives and the markup
    /// are deliberately not a public surface, so a rebrand that sticks to
    /// roles survives a layout change.
    #[arg(long, env = "WIFI_CONNECT_BRAND_CSS")]
    pub brand_css: Option<PathBuf>,

    /// Path to an image shown in place of the product name in the page
    /// header, served at `/brand-logo`.
    ///
    /// SVG, PNG, JPEG or WebP. `--brand-name` is still required: it is the
    /// image's alt text and the window title.
    #[arg(long, env = "WIFI_CONNECT_BRAND_LOGO")]
    pub brand_logo: Option<PathBuf>,

    /// Default theme when the viewer has expressed no preference.
    #[arg(long, env = "WIFI_CONNECT_DEFAULT_THEME", default_value = "system")]
    pub default_theme: ThemeMode,

    #[arg(long, env = "WIFI_CONNECT_LOG_FORMAT", default_value = "text")]
    pub log_format: LogFormat,

    /// Log level. `RUST_LOG` overrides this when set.
    #[arg(long, env = "WIFI_CONNECT_LOG_LEVEL", default_value = "info")]
    pub log_level: String,
}

/// A DHCP pool, parsed from `first,last`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpRange {
    pub first: Ipv4Addr,
    pub last: Ipv4Addr,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("--portal-dhcp-range must be `first,last`, for example 192.168.42.2,192.168.42.254")]
    DhcpRangeShape,
    #[error("--portal-dhcp-range start {first} is after its end {last}")]
    DhcpRangeInverted { first: Ipv4Addr, last: Ipv4Addr },
    #[error("the gateway {0} must not be inside the DHCP range, or it will be handed to a client")]
    GatewayInRange(Ipv4Addr),
    #[error("--portal-ssid must be 1 to 32 bytes, got {0}")]
    SsidLength(usize),
    #[error("--portal-passphrase: {0}")]
    Passphrase(String),
}

pub fn parse_dhcp_range(spec: &str, gateway: Ipv4Addr) -> Result<DhcpRange, ConfigError> {
    let (a, b) = spec.split_once(',').ok_or(ConfigError::DhcpRangeShape)?;
    let first: Ipv4Addr = a.trim().parse().map_err(|_| ConfigError::DhcpRangeShape)?;
    let last: Ipv4Addr = b.trim().parse().map_err(|_| ConfigError::DhcpRangeShape)?;

    if first > last {
        return Err(ConfigError::DhcpRangeInverted { first, last });
    }
    // Handing the gateway's own address to a client breaks the portal in a
    // way that is very hard to diagnose from the client side.
    if gateway >= first && gateway <= last {
        return Err(ConfigError::GatewayInRange(gateway));
    }
    Ok(DhcpRange { first, last })
}

impl Cli {
    /// The access point's security mode, as the settings builder wants it.
    ///
    /// `auto` and `wpa2` both map to WPA2-PSK; only an explicit `wpa3`
    /// selects SAE. See [`SecurityMode`] for why `auto` is not SAE.
    pub fn ap_security(&self) -> ApSecurity {
        match self.portal_security {
            SecurityMode::Wpa3 => ApSecurity::Wpa3Sae,
            SecurityMode::Auto | SecurityMode::Wpa2 => ApSecurity::Wpa2Psk,
        }
    }

    pub fn activity_timeout(&self) -> Duration {
        Duration::from_secs(self.activity_timeout)
    }

    pub fn wait_for_connection(&self) -> Duration {
        Duration::from_secs(self.wait_for_connection)
    }

    pub fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.connection_timeout)
    }

    /// Validate everything that can be checked without touching the radio.
    pub fn validate(&self) -> Result<DhcpRange, ConfigError> {
        // Bytes, not characters: 802.11 caps the SSID element at 32 octets.
        let ssid_len = self.portal_ssid.len();
        if ssid_len == 0 || ssid_len > 32 {
            return Err(ConfigError::SsidLength(ssid_len));
        }
        if let Some(p) = &self.portal_passphrase {
            crate::passphrase::validate(p).map_err(|e| ConfigError::Passphrase(e.to_string()))?;
        }
        parse_dhcp_range(&self.portal_dhcp_range, self.portal_gateway)
    }

    pub fn portal_url(&self) -> String {
        if self.portal_listening_port == 80 {
            format!("http://{}/", self.portal_gateway)
        } else {
            format!(
                "http://{}:{}/",
                self.portal_gateway, self.portal_listening_port
            )
        }
    }

    pub fn captive_portal_api_url(&self) -> String {
        format!("{}api/captive-portal", self.portal_url())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn cli(args: &[&str]) -> Cli {
        let mut full = vec!["wifi-connect"];
        full.extend_from_slice(args);
        Cli::parse_from(full)
    }

    #[test]
    fn the_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// Upstream's flags are the migration contract.
    #[test]
    fn upstream_short_flags_still_work() {
        let c = cli(&[
            "-s",
            "My Setup",
            "-p",
            "hunter2hunter2",
            "-g",
            "10.0.0.1",
            "-d",
            "10.0.0.10,10.0.0.20",
            "-o",
            "8080",
            "-i",
            "wlan1",
            "-a",
            "600",
            "-u",
            "/srv/ui",
        ]);

        assert_eq!(c.portal_ssid, "My Setup");
        assert_eq!(c.portal_passphrase.as_deref(), Some("hunter2hunter2"));
        assert_eq!(c.portal_gateway, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(c.portal_listening_port, 8080);
        assert_eq!(c.interface.as_deref(), Some("wlan1"));
        assert_eq!(c.activity_timeout, 600);
        assert_eq!(
            c.ui_directory.as_deref(),
            Some(std::path::Path::new("/srv/ui"))
        );
    }

    /// `--portal-interface` was upstream's name; it must keep working.
    #[test]
    fn the_legacy_interface_flag_is_still_accepted() {
        assert_eq!(
            cli(&["--portal-interface", "wlan2"]).interface.as_deref(),
            Some("wlan2")
        );
    }

    #[test]
    fn upstream_defaults_are_preserved() {
        let c = cli(&[]);
        assert_eq!(c.portal_ssid, "WiFi Connect");
        assert_eq!(c.portal_gateway, Ipv4Addr::new(192, 168, 42, 1));
        assert_eq!(c.portal_dhcp_range, "192.168.42.2,192.168.42.254");
        assert_eq!(c.portal_listening_port, 80);
        assert_eq!(c.activity_timeout, 0, "0 means no timeout, as upstream");
    }

    /// The one deliberate behavioural change from upstream, which the
    /// migration guide has to call out.
    #[test]
    fn the_access_point_is_encrypted_by_default() {
        let c = cli(&[]);
        assert!(
            !c.insecure_open_portal,
            "upstream defaults to an open AP; we must not"
        );
    }

    /// Skipping RADIUS server verification hands the user's credentials to
    /// any look-alike access point, so it must never be the default.
    #[test]
    fn enterprise_server_verification_is_on_by_default() {
        assert!(!cli(&[]).insecure_eap_skip_server_verification);
        assert!(
            cli(&["--insecure-eap-skip-server-verification"]).insecure_eap_skip_server_verification
        );
    }

    #[test]
    fn dhcp_range_parses() {
        let r = parse_dhcp_range(
            "192.168.42.2,192.168.42.254",
            Ipv4Addr::new(192, 168, 42, 1),
        )
        .unwrap();
        assert_eq!(r.first, Ipv4Addr::new(192, 168, 42, 2));
        assert_eq!(r.last, Ipv4Addr::new(192, 168, 42, 254));

        // Whitespace around the comma is forgiving.
        assert!(parse_dhcp_range(" 10.0.0.2 , 10.0.0.9 ", Ipv4Addr::new(10, 0, 0, 1)).is_ok());
    }

    #[test]
    fn a_malformed_dhcp_range_is_rejected() {
        let gw = Ipv4Addr::new(192, 168, 42, 1);
        for spec in ["192.168.42.2", "a,b", "192.168.42.2;192.168.42.9", ""] {
            assert_eq!(
                parse_dhcp_range(spec, gw).unwrap_err(),
                ConfigError::DhcpRangeShape,
                "accepted {spec:?}"
            );
        }
    }

    #[test]
    fn an_inverted_dhcp_range_is_rejected() {
        let err = parse_dhcp_range(
            "192.168.42.254,192.168.42.2",
            Ipv4Addr::new(192, 168, 42, 1),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::DhcpRangeInverted { .. }));
    }

    /// Handing out the gateway's own address breaks the portal in a way
    /// that is almost impossible to diagnose from the client.
    #[test]
    fn a_gateway_inside_the_pool_is_rejected() {
        let err = parse_dhcp_range(
            "192.168.42.1,192.168.42.254",
            Ipv4Addr::new(192, 168, 42, 1),
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConfigError::GatewayInRange(Ipv4Addr::new(192, 168, 42, 1))
        );
    }

    #[test]
    fn ssid_length_is_enforced_in_bytes_not_characters() {
        let mut c = cli(&[]);

        c.portal_ssid = String::new();
        assert_eq!(c.validate().unwrap_err(), ConfigError::SsidLength(0));

        // 32 bytes is the limit; these emoji are 4 bytes each.
        c.portal_ssid = "\u{1F600}".repeat(8);
        assert!(c.validate().is_ok(), "32 bytes should be accepted");

        c.portal_ssid = "\u{1F600}".repeat(9);
        assert_eq!(c.validate().unwrap_err(), ConfigError::SsidLength(36));
    }

    #[test]
    fn a_short_operator_passphrase_is_rejected_at_startup() {
        let mut c = cli(&[]);
        c.portal_passphrase = Some("short".into());
        assert!(matches!(
            c.validate().unwrap_err(),
            ConfigError::Passphrase(_)
        ));
    }

    #[test]
    fn urls_omit_the_default_port_but_keep_a_custom_one() {
        let c = cli(&[]);
        assert_eq!(c.portal_url(), "http://192.168.42.1/");
        assert_eq!(
            c.captive_portal_api_url(),
            "http://192.168.42.1/api/captive-portal"
        );

        let c = cli(&["-o", "8080", "-g", "10.0.0.1"]);
        assert_eq!(c.portal_url(), "http://10.0.0.1:8080/");
    }

    #[test]
    fn security_modes_map_to_the_settings_builder() {
        assert_eq!(
            cli(&["--portal-security", "wpa3"]).ap_security(),
            ApSecurity::Wpa3Sae
        );
        assert_eq!(
            cli(&["--portal-security", "wpa2"]).ap_security(),
            ApSecurity::Wpa2Psk
        );
        // auto starts at WPA2 and is upgraded once the adapter is known.
        assert_eq!(
            cli(&["--portal-security", "auto"]).ap_security(),
            ApSecurity::Wpa2Psk
        );
    }

    #[test]
    fn durations_come_from_the_second_valued_flags() {
        let c = cli(&[
            "-a",
            "600",
            "--connection-timeout",
            "30",
            "--wait-for-connection",
            "15",
        ]);
        assert_eq!(c.activity_timeout(), Duration::from_secs(600));
        assert_eq!(c.connection_timeout(), Duration::from_secs(30));
        assert_eq!(c.wait_for_connection(), Duration::from_secs(15));
    }
}
