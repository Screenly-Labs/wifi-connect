# wifi-connect

Minimal tool for joining WiFi networks.

A headless Linux device has a chicken-and-egg problem: it needs WiFi
credentials, and the only way to give it any is over a network it does not
have yet. `wifi-connect` solves it the usual way — raise a temporary access
point, serve a captive portal, take the credentials, join — and then gets
out of the way.

```
         ┌── the device ──────────────────────────────┐
         │  NetworkManager ──► wlan0 192.168.42.1/24  │
         │                     WPA2/WPA3, AP mode     │
         │  wifi-connect   ──► udp/67  DHCP           │
         │                     udp/53  DNS (wildcard) │
         │                     tcp/80  portal         │
         └────────────────────────────────────────────┘
                 ▲ scan the QR on screen to join
                 │ the portal opens by itself
            📱 a phone
```

## What is different from balena's wifi-connect

This is a ground-up replacement, not a fork. The things that differ are the
things that bit us in production:

| | balena wifi-connect | this |
|---|---|---|
| Setup access point | **open by default** | always WPA2/WPA3-encrypted |
| Getting the passphrase to the user | n/a | a QR code on the device's screen |
| DHCP / DNS | spawns `dnsmasq` | in-process, no external binaries |
| Runtime | needs a shell and helpers | one static binary, `FROM scratch`, ~4 MB |
| Wrong password | frequently just hangs | the portal comes back and says so |
| Architectures | ARMv6 binary silently dropped in 4.4.6 | amd64, arm64, armv7 **and armv6**, each executed in CI |

The encryption is the headline. A captive portal cannot use TLS — there is
no publicly trusted certificate for `192.168.42.1`, and a self-signed one
makes OS portal detection fail outright instead of degrading — so the
confidentiality has to come from the link layer. Encrypting the access point
itself covers DHCP and DNS too, not merely an HTTPS credential POST.

## Quick start

### Docker / balenaOS

```yaml
services:
  wifi-connect:
    image: ghcr.io/screenly-labs/wifi-connect:2026.10
    network_mode: host        # required: see docker-compose.balena.yml
    labels:
      io.balena.features.dbus: '1'
    environment:
      DBUS_SYSTEM_BUS_ADDRESS: 'unix:path=/host/run/dbus/system_bus_socket'
      PORTAL_SSID: 'Device Setup'
```

### Ubuntu Core

```bash
sudo snap install wifi-connect
sudo snap connect wifi-connect:network-manager network-manager:service
sudo snap start --enable wifi-connect
```

The `network-manager` interface does **not** auto-connect, so that second
line is required. For an image you build yourself, declare it in
`gadget.yaml` instead so it is connected on first boot.

### Debian / Raspberry Pi OS

```bash
tar xzf wifi-connect-*-aarch64-unknown-linux-musl.tar.gz
sudo install -m0755 wifi-connect /usr/bin/
sudo install -m0644 wifi-connect.service /etc/systemd/system/
sudo install -m0644 wifi-connect.env /etc/default/wifi-connect
sudo systemctl enable --now wifi-connect
```

## How it works

1. **Preflight.** Find the WiFi device, confirm NetworkManager manages it,
   and confirm the adapter can actually do AP mode. Each failure has its own
   message and exit code, because "it didn't work" is not a bug report.
2. **Should we even run?** If the device is already online, exit 0. If it
   has saved WiFi profiles, wait up to 60s for one to come up first —
   associating plus DHCP plus a probe genuinely takes 15-30s from cold. If
   it has none, show the portal immediately rather than making a first-boot
   user stare at nothing for a minute.
3. **Scan, then raise the access point.** In that order: a radio in AP mode
   cannot scan.
4. **Serve the portal.** DHCP hands out leases and advertises the portal via
   DHCP option 114 (RFC 8910); the wildcard DNS resolver points every name
   at us so the OS connectivity probe lands here; the HTTP server answers
   those probes in the way that makes each OS open its sign-in sheet.
5. **Join.** The browser is answered *before* the access point comes down,
   because the radio cannot be an AP and a station at once and an unflushed
   response dies with the client's connection.
6. **If it fails,** delete the half-made profile, raise the access point
   again with the same SSID and passphrase so the phone rejoins by itself,
   and show the user what went wrong.

## Configuration

Every flag has an environment variable. Flags win.

| Flag | Short | Environment | Default |
|---|---|---|---|
| `--portal-ssid` | `-s` | `PORTAL_SSID` | `WiFi Connect` |
| `--portal-passphrase` | `-p` | `PORTAL_PASSPHRASE` | *generated per run* |
| `--portal-security` | | `WIFI_CONNECT_PORTAL_SECURITY` | `auto` |
| `--portal-gateway` | `-g` | `PORTAL_GATEWAY` | `192.168.42.1` |
| `--portal-dhcp-range` | `-d` | `PORTAL_DHCP_RANGE` | `192.168.42.2,192.168.42.254` |
| `--portal-listening-port` | `-o` | `PORTAL_LISTENING_PORT` | `80` |
| `--interface` | `-i` | `WIFI_CONNECT_INTERFACE` | auto-detect |
| `--activity-timeout` | `-a` | `ACTIVITY_TIMEOUT` | `0` (never) |
| `--ui-directory` | `-u` | `UI_DIRECTORY` | embedded |
| `--qr-output` | | `WIFI_CONNECT_QR_OUTPUT` | — |
| `--brand-name` | | `WIFI_CONNECT_BRAND_NAME` | `WiFi Connect` |
| `--brand-css` | | `WIFI_CONNECT_BRAND_CSS` | — |
| `--brand-logo` | | `WIFI_CONNECT_BRAND_LOGO` | — |
| `--force` | | `WIFI_CONNECT_FORCE` | `false` |
| `--connection-timeout` | | `WIFI_CONNECT_CONNECTION_TIMEOUT` | `45` |
| `--wait-for-connection` | | `WIFI_CONNECT_WAIT_FOR_CONNECTION` | `60` |
| `--insecure-eap-skip-server-verification` | | `WIFI_CONNECT_INSECURE_EAP` | `false` |

### Migrating from balena wifi-connect

All eight of its flags keep working under the same names, short forms and
environment variables. Two behaviours changed:

- **The access point is now encrypted.** Previously, omitting
  `--portal-passphrase` gave an *open* network; now it generates one and
  shows it as a QR code. `--insecure-open-portal` restores the old
  behaviour, logs a warning, and is not CRA-compliant.
- **`--ui-directory` is now an override**, not a requirement. The UI is
  embedded in the binary, so the common deployment failure of the binary
  not finding a relative `ui/` directory is gone.

`--portal-interface` is accepted as a hidden alias for `--interface`.

## Getting the passphrase to the user

The access point always has a passphrase, so the user needs it before they
can join. It is rendered **on the device**, since it is what gets you onto
the network and therefore cannot be served over it:

- `--qr-output <dir>` writes `wifi-connect-qr.svg` plus the raw payload, for
  a host application to show full-screen. This is the primary path.
- A Unicode QR is printed to stdout, which a plain HDMI console or a serial
  terminal renders directly with no host application at all.
- The SSID and passphrase are logged as text, for operators and for anyone
  whose scanner refuses.

## White-labelling the portal

`--brand-name` changes the name in the page. `--brand-css` points at a
stylesheet served at `/brand.css` and loaded after the portal's own CSS, so
it can override the role tokens:

```bash
wifi-connect --brand-name Anthias --brand-css /etc/wifi-connect/brand.css
```

```css
:root {
  --color-accent: #ffe11a;
  --color-accent-hover: #e6cb17;
  --color-on-accent: #1f002a;
  --color-focus-ring: rgb(255 225 26 / 0.45);
}
```

Override **roles only** — never the `--c-*` primitives and never the markup.
That split is the whole point: a rebrand that sticks to roles keeps working
when the portal's layout changes. `ui/dist/brand.example.css` is a worked
example.

That one block covers light and dark both: the portal's dark arms weigh no
more than the `:root` that sets the light defaults, so a stylesheet loaded
after them wins in either scheme. Use a `prefers-color-scheme` arm only to
set a *different* value in dark.

`--brand-logo` points at an image shown in the header in place of the
product name, served at `/brand-logo`:

```bash
wifi-connect --brand-name Anthias --brand-logo /etc/wifi-connect/logo.svg
```

SVG, PNG, JPEG or WebP, up to 256 KB; anything else is refused at startup
rather than served as a broken image. `--brand-name` is still required and
becomes the image's alt text, so the heading reads correctly to a screen
reader and to anyone whose image did not load. The logo *replaces* the
wordmark rather than sitting above it.

`--default-theme` decides which scheme the page opens in:

```bash
wifi-connect --brand-name Anthias --default-theme dark
```

`system` (the default) follows the phone and leaves an in-page **Switch
theme** control in the footer. `light` or `dark` pins the page — the
attribute is rendered on `<html>` server side, so it is right in the first
paint rather than flashing the other scheme — and **removes that control**.
Which of two colour schemes a one-minute setup page uses is the
integrator's decision, and an end user who flips it is only undoing it. A
preference already in the phone's storage from another portal does not
override a pinned theme either.

The file is read once at startup, so a path that does not exist stops the
portal with a clear message rather than quietly serving an unbranded page.
When the flag is unset the pages link nothing at all and stay a single
request, which is what makes them work in a captive-portal mini-browser with
no internet behind it.

## Exit codes

A run ends in one of these. They matter to whoever writes the unit file:
`0`, `3`, `4` and `6` are endings nobody can act on from a service manager,
and belong in `SuccessExitStatus=`. The rest are worth surfacing as a
failed unit.

| code | meaning | actionable? |
| --- | --- | --- |
| 0 | joined, already online, or asked to stop | no |
| 1 | anything not listed below | yes |
| 3 | no WiFi device on this machine | no — nothing to configure |
| 4 | adapter cannot do AP mode, is unmanaged, or the radio is blocked | no — a hardware fact |
| 5 | NetworkManager is unreachable over the bus | yes |
| 6 | the activity timeout elapsed with no join | no — the ordinary "nobody came" ending |
| 7 | the portal could not bind its address or port | yes — it will recur until something changes |

## Requirements and limitations

- **NetworkManager is required.** This tool drives it; it does not replace it.
- **The adapter must support AP mode.** Checked up front via NM's
  `WirelessCapabilities`; known-bad chipsets include BCM43143, MT7601 and
  RTL8188CUS. Note that some out-of-tree drivers *claim* AP support and then
  fail to start one — that surfaces as a distinct error message.
- **Containers need host networking.** DHCP is an L2 broadcast protocol and
  does not survive Docker's DNAT, and the interface pin that stops us
  serving DHCP on your ethernet LAN has nothing to bind to in a bridge
  namespace.
- **Architectures:** amd64, arm64, armv7 and armv6. ARMv6 covers the
  Raspberry Pi 1 and Pi Zero, which is the architecture upstream dropped in
  v4.4.6 without anyone noticing for three years.
- **Enterprise WiFi is PEAP/MSCHAPv2 only.** Certificate-based EAP-TLS
  needs key and certificate paths a portal cannot collect. The RADIUS
  server's certificate must chain to the **host's** system CA store
  (NetworkManager's `system-ca-certs`; it is the host's wpa_supplicant that
  reads it, so the `FROM scratch` container image is irrelevant). The
  portal also asks for an optional *server domain*, which becomes
  `domain-suffix-match`: without one, any certificate a public CA has issued
  for *any* name passes, so it is worth filling in. The outer identity is
  sent as `anonymous@<realm>` (or `anonymous`), so the real username stays
  inside the TLS tunnel. A network whose RADIUS server uses a **private CA**
  will fail to join; `--insecure-eap-skip-server-verification` turns CA
  checking off for it, logs a warning, and lets anyone in radio range who
  copies the network's name capture the user's MSCHAPv2 exchange, which
  cracks offline to their password hash.
- **No rescan button.** A radio in AP mode cannot scan, so rescanning would
  mean dropping the access point and disconnecting the user mid-setup. Use
  the hidden-network field to enter an SSID that did not appear.

### Threat model

The WPA2/WPA3 link protects everything between the phone and the device
against passive sniffing by anyone not on the access point. It does **not**
protect against a second client that joined the same access point and
captured the four-way handshake. That is mitigated by the passphrase being
random per run and the access point being short-lived, but it is a real
limitation and not a confidentiality boundary between clients.

## Versioning

CalVer, `YYYY.MM.MICRO`, with release tags `vYYYY.MM.MICRO` — the same
scheme Anthias uses. Semver would imply a compatibility contract this tool
does not have: there is no library API, and the surface that needs
stability is the CLI, which is pinned to upstream's flags by the migration
table above rather than to a major number.

Container tags are `2026.10.0` (exact), `2026.10` (latest patch that month)
and `latest`. There is deliberately no bare `2026` tag: under CalVer its
meaning would drift for a whole year while reading like a semver promise.

## Development

```bash
cd ui && bun install && bun run build   # the portal; output is committed
cargo test                              # 166 unit tests, no hardware needed
cargo clippy --all-targets
```

`cargo build` never needs bun: `ui/dist` is committed and embedded, and CI
fails if it has drifted from `ui/src`.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
