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
| Wrong passphrase | frequently just hangs | the portal comes back and says so |
| Static IP | not supported ([#110](https://github.com/balena-os/wifi-connect/issues/110), open since 2017) | IPv4 and IPv6, set from the portal |
| Architectures | ARMv6 binary silently dropped in 4.4.6 | amd64, arm64, armv7 **and armv6**, each executed in CI |
| Hidden networks | dropped from the list, cannot be joined | typed by name in the portal |
| Enterprise | PEAP/MSCHAPv2 only | PEAP, TTLS/MSCHAPv2 and TTLS/PAP |
| WEP networks | joined | refused, and the portal says why |

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
sudo snap install network-manager
sudo snap install wifi-connect
sudo snap connect wifi-connect:network-manager network-manager:service
sudo snap start --enable wifi-connect
```

Ubuntu Core does not ship NetworkManager, hence the first line. The
`network-manager` interface does **not** auto-connect, hence the third.
Configure it with `snap set`, e.g.
`sudo snap set wifi-connect portal-ssid="Device Setup"`.

Every GitHub Release also carries the `.snap` for `amd64`, `arm64` and
`armhf`, which installs the same way with
`sudo snap install --dangerous ./wifi-connect_<version>_<arch>.snap`
(no automatic updates).

[docs/snap.md](docs/snap.md) covers configuration keys, building an Ubuntu
Core image with the connection and defaults declared in `gadget.yaml`, and
troubleshooting.

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
   user stare at nothing for a minute. "Online" is NetworkManager's
   connectivity check saying so — or, where that check is disabled (the
   default on Debian, Raspberry Pi OS and Ubuntu Server, which ship no check
   URI), the WiFi device already being connected as a station: the access
   point is never raised over a working WiFi connection on that basis; use
   `--force` to override. A wired link alone does not count when the check
   is disabled, because nothing then tells a LAN with internet from one
   without — configure a check URI if ethernet should suppress the portal.
   A probe that positively reports no or limited connectivity still brings
   the portal up, so a device stuck on a dead network can be moved to
   another.
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
| `--portal-ssid-suffix` | | `PORTAL_SSID_SUFFIX` | `4` |
| `--state-file` | | `WIFI_CONNECT_STATE_FILE` | |
| `--recheck-interval` | | `WIFI_CONNECT_RECHECK_INTERVAL` | `0` |
| `--retry-after` | | `WIFI_CONNECT_RETRY_AFTER` | `--recheck-interval` |
| `--portal-passphrase` | `-p` | `PORTAL_PASSPHRASE` | *generated per run* |
| `--portal-security` | | `WIFI_CONNECT_PORTAL_SECURITY` | `auto` |
| `--portal-gateway` | `-g` | `PORTAL_GATEWAY` | `192.168.42.1` |
| `--portal-dhcp-range` | `-d` | `PORTAL_DHCP_RANGE` | `192.168.42.2,192.168.42.254` |
| `--portal-listening-port` | `-o` | `PORTAL_LISTENING_PORT` | `80` |
| `--interface` | `-i` | `WIFI_CONNECT_INTERFACE`, or upstream's `PORTAL_INTERFACE` | auto-detect |
| `--activity-timeout` | `-a` | `ACTIVITY_TIMEOUT` | `0` (never) |
| `--ui-directory` | `-u` | `UI_DIRECTORY` | embedded |
| `--qr-output` | | `WIFI_CONNECT_QR_OUTPUT` | — |
| `--qr-stdout` | | `WIFI_CONNECT_QR_STDOUT` | `false` (see below) |
| `--no-qr-stdout` | | `WIFI_CONNECT_NO_QR_STDOUT` | `false` |
| `--log-passphrase` | | `WIFI_CONNECT_LOG_PASSPHRASE` | `false` |
| `--brand-name` | | `WIFI_CONNECT_BRAND_NAME` | `WiFi Connect` |
| `--brand-css` | | `WIFI_CONNECT_BRAND_CSS` | — |
| `--brand-logo` | | `WIFI_CONNECT_BRAND_LOGO` | — |
| `--force` | | `WIFI_CONNECT_FORCE` | `false` |
| `--connection-timeout` | | `WIFI_CONNECT_CONNECTION_TIMEOUT` | `45` |
| `--wait-for-connection` | | `WIFI_CONNECT_WAIT_FOR_CONNECTION` | `60` |
| `--insecure-eap-skip-server-verification` | | `WIFI_CONNECT_INSECURE_EAP` | `false` |

`--portal-security` takes `auto`, `wpa2` or `wpa3`. `auto` is currently
WPA2-PSK (CCMP), identical to `wpa2`; the name is reserved for picking the
best mode the adapter reliably supports, but it does not probe the adapter
or upgrade to WPA3 today. `wpa3` (SAE) is opt-in because AP-mode SAE on the
`brcmfmac` radio in every Raspberry Pi with built-in Wi-Fi comes up but
clients fail to associate, and the access point cannot see that failure to
fall back.

### Migrating from balena wifi-connect

All eight of its flags keep working under the same names, short forms and
environment variables. Two behaviours changed:

- **The access point is now encrypted.** Previously, omitting
  `--portal-passphrase` gave an *open* network; now it generates one and
  shows it as a QR code. `--insecure-open-portal` restores the old
  behaviour, logs a warning, and is not CRA-compliant.
- **`--ui-directory` is now an override**, not a requirement. The UI is
  embedded in the binary, so the common deployment failure of the binary
  not finding a relative `ui/` directory is gone. The directory it takes
  is not interchangeable with upstream's: see
  [Replacing the pages](#replacing-the-pages---ui-directory).

`--portal-interface` is accepted as a hidden alias for `--interface`, and
its variable `PORTAL_INTERFACE` is read when neither the flag nor
`WIFI_CONNECT_INTERFACE` is set.

Upstream's HTTP API is kept too, for scripts and front ends written
against it:

- `GET /networks` returns `[{"ssid": "…", "security": "…"}]` with
  upstream's security values `none`, `wpa` and `enterprise`. WEP
  networks are left out, since they cannot be joined (see
  [Requirements](#requirements-and-limitations)). (`/api/networks` has more: exact SSID bytes, signal and
  frequency.)
- `POST /connect` with `Content-Type: application/json` takes
  `{"ssid", "identity", "passphrase"}`. A name the scan listed is joined
  by its exact bytes, anything else as a hidden network. It answers `202`
  with `{"ssid": …}` once the join is under way, or `400`, `403` or `409`
  with `{"error": …}`. The same cross-site checks as the form apply.

## Getting the passphrase to the user

The access point always has a passphrase, so the user needs it before they
can join. It is rendered **on the device**, since it is what gets you onto
the network and therefore cannot be served over it:

- `--qr-output <dir>` writes `wifi-connect-qr.svg` plus the raw payload
  (`wifi-connect-qr.txt`), for a host application to show full-screen. This
  is the primary path. Both files contain the passphrase, so they are
  written mode `0640` (a directory wifi-connect creates is `0750`),
  atomically, and never through a symlink at the target. The application
  displaying them must run as the same user or group as wifi-connect. The
  files take wifi-connect's group, so give it the reader's group rather
  than loosening the mode: in Docker, `user: '0:<reader gid>'` (root is
  still needed for NetworkManager; see `docker-compose.balena.yml`); under
  systemd, `Group=` in a drop-in.
- A Unicode QR on stdout, which a plain HDMI console or a serial terminal
  renders directly with no host application at all. Under systemd or
  Docker, stdout is captured into the journal or container log, where a QR
  is as good as the passphrase. So it is printed only when stdout is a
  terminal, or when there is no other channel: `--qr-output` is not set, or
  writing its files failed. With the files written and stdout not a
  terminal (the balena and Anthias setup), the QR stays out of the logs.
  `--qr-stdout` prints it regardless; `--no-qr-stdout` never prints it and
  wins over `--qr-stdout`. With neither `--qr-output` nor a fixed
  `PORTAL_PASSPHRASE`, the journal QR is the only place a generated
  passphrase appears, so `--no-qr-stdout` there leaves nobody able to join.
- The passphrase is **not** logged. The log names the SSID and says the
  passphrase is in the QR. `--log-passphrase` adds it as plain text, for a
  bench where a scanner refuses the QR; leave it off anywhere logs are
  shipped off the device or readable beyond the people allowed to join.
  It is a dedicated flag rather than DEBUG level so that raising the log
  level to troubleshoot a radio does not start shipping a credential.

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

### Replacing the pages: `--ui-directory`

When the role tokens are not enough, `--ui-directory` serves the pages from
a directory instead of the copy embedded in the binary:

```bash
wifi-connect --ui-directory /etc/wifi-connect/ui
```

- **It replaces the embedded UI wholesale.** `index.html` and
  `connecting.html` must both be there, and `/assets/<path>` serves files
  from the directory and nothing else. There is no per-file fallback, so a
  misspelt file name fails loudly rather than giving you a mixed portal.
- **The pages are this portal's templates**, not static HTML. They are
  rendered with the same `{{TOKENS}}` as the embedded ones (`{{NETWORKS}}`,
  `{{BANNER}}`, `{{SSID}}`, `{{BRAND_NAME}}`, `{{BRAND_HEADING}}`,
  `{{BRAND_CSS}}`, `{{THEME_ATTR}}`, `{{THEME_TOGGLE}}`) and must keep the
  form fields the server reads. Start by copying `ui/dist`. **balena's
  React UI build will not work** — it is a client-side app loading
  `/static/` paths this portal does not serve, not a template — and an
  `index.html` with no `{{NETWORKS}}` token is refused at startup for
  that reason. A front end hosted elsewhere can still drive the portal
  through upstream's API (see
  [Migrating](#migrating-from-balena-wifi-connect)). Any other token the built-in pages use but
  yours lack is logged as a warning at startup: a template copied from an
  older release still works, but without `{{BRAND_CSS}}` or
  `{{BRAND_HEADING}}`, `--brand-css` and `--brand-logo` have nowhere to go.
- **It is read once, at startup**, like `--brand-css`: a missing directory
  or template stops the portal with the path in the message. Restart to
  pick up edits. The directory is capped at 256 files and 8 MB, dotfiles
  are skipped, and a symlink that resolves outside it is refused.
- **Inline script and style are allowed by hash.** The portal sends a
  Content-Security-Policy; with `--ui-directory` it is built at startup
  from the SHA-256 of each bare `<script>…</script>` and
  `<style>…</style>` block in your two templates, and `script-src` also
  allows `'self'`, so `<script src="/assets/app.js">` works. Everything
  else in the policy is unchanged. A block with attributes
  (`<script type="module">`, `<style media="…">`) is not hashed, and a
  `{{TOKEN}}` inside a block changes its bytes per request; the browser
  blocks both, so both are logged as a warning at startup. Inline event
  handlers (`onclick="…"`) and `style="…"` attributes are blocked too.

## When the portal comes up

The portal is for a device with no network. Before raising an access
point, wifi-connect asks NetworkManager whether this host is already
online, and treats three things as "yes, leave it alone":

| | |
| --- | --- |
| NetworkManager reports full connectivity, *and a probe actually ran* | measured, so it stands |
| The radio is already an associated station | raising the AP would replace that very connection |
| Another interface is up — wired, a second radio, a modem | the device has a network; taking the radio down to offer it one is backwards |

The last two matter because **connectivity checking is unavailable on
most of the platforms this runs on**: Debian and Raspberry Pi OS build
NetworkManager without it, so it answers "unknown" forever and the
probe tells you nothing. A wired screen never associates, so without
the interface check it would be offered WiFi setup on every single
start, for as long as it is deployed.

That makes the daemon safe to start unconditionally — which matters on
any platform with no init system to gate it with. On balenaOS the
supervisor starts every service in the compose file on every boot and
every release apply, and there is no `ExecCondition` to hang a
host-side gate on; the decision has to be sound from in here.

A verdict only counts when `ConnectivityCheckAvailable` is true. Where
it is false NetworkManager still answers — confidently — from the
routing table: measured on balenaOS, `full` with a cable in and
`limited` with it out, having probed nothing. Taking `limited` at face
value there raises an access point at a wired screen on an isolated
LAN, so an unmeasured verdict of any kind falls through to the device
checks above.

Deliberately *not* consulted: NetworkManager's global `State`. With
checking disabled it reads `CONNECTED_GLOBAL` for any link with a
default route, including an airgapped LAN, so trusting it would stop
the portal appearing on a device that needs it. The checks above ask
whether an interface is **up**, not whether the internet is reachable
through it.

`--force` raises the portal regardless, for deliberately reconfiguring
a device that is online.

## Running without an init system

This daemon does one pass and exits — the right shape when a systemd
timer, a cron entry or a supervisor decides when it runs. On a platform
that has none of those, the container runtime's restart policy is the
only scheduler available, and it has no notion of "in five minutes": it
restarts as soon as the process is gone.

So `restart: always` plus an immediate exit is a spin. Measured on a
wired Raspberry Pi 5, where the daemon correctly decides within twenty
seconds that it is not needed:

```
13 container starts in 240 seconds  ->  4,680 per device per day
53 log lines in 240 seconds         ->  19,000 per device per day
```

Forever, on every healthy screen, which on a fleet with cloud log
shipping is a bill as well as a nuisance.

`--recheck-interval` fixes that without any new machinery: the daemon
waits before exiting, so the restart policy becomes a schedule. The
exit is still clean, it just happens later.

```bash
wifi-connect --recheck-interval 300 --retry-after 21600
```

- **`--recheck-interval`** — how long to wait once the device is online.
  Five minutes is a reasonable screen refresh; the check costs one
  D-Bus round trip.
- **`--retry-after`** — how long to wait after a portal session nobody
  completed. Longer, because that session just held the display for a
  quarter of an hour: an unjoinable site with a five-minute retry never
  shows content again.

Both default to 0, which exits immediately — keep it that way wherever
something else owns the schedule, or the next tick will land while the
last run is still waiting.

`SIGTERM` cuts the wait short, so a release apply or a reboot never has
to sit out a six-hour window.

## When the portal stands down

`--activity-timeout` is an **idle** timeout, not a cap on the session.
The clock restarts whenever somebody loads a page, lists networks or
submits a join, so a portal in use is never taken away mid-session —
which matters more than it sounds, because the next run generates a
new passphrase *and* a new SSID suffix, so an interrupted user does not
simply reconnect and carry on.

Captive-portal probe endpoints deliberately do not count. A phone that
joins the setup network and goes back into a pocket keeps polling
`/hotspot-detect.html` and friends for as long as it stays associated,
and counting that would hold a screen in setup mode until someone
walked away with the phone.

An untouched portal stands down after exactly the configured interval,
as before.

## Telling the host application what is going on

A device that raises a setup access point usually has a screen on it, and
that screen is the only way the generated passphrase reaches the person
standing in front of it — the passphrase is what gets you *onto* the
network, so it cannot be served over the network.

`--state-file` is the supported way to drive that screen:

```bash
wifi-connect --state-file /data/hotspot/state.json
```

```json
{
  "schema": 1,
  "portal_active": true,
  "ssid": "Anthias Setup-G4VV",
  "security": "wpa",
  "passphrase": "brave-plum-42",
  "qr_payload": "WIFI:T:WPA;S:Anthias Setup-G4VV;P:brave-plum-42;H:false;;",
  "portal_url": "http://192.168.42.1:8000/",
  "gateway": "192.168.42.1",
  "interface": "wlan0",
  "port": 8000,
  "started_at_unix": 1761048000,
  "heartbeat_unix": 1761048345,
  "heartbeat_interval_s": 15
}
```

**Presence is the liveness signal.** The file appears once a run has
committed to raising the access point and is removed when the run ends,
on every exit including the failures. It is deliberately not written by
the runs that exit immediately because the device turned out to be
online — which is exactly why `--qr-output`'s files cannot answer the
question: they are written *before* that check, so a healthy device also
has them.

Do not probe the portal's HTTP listener to find out whether it is up.
It is bound to the gateway address scoped to the wireless device, so
that a setup portal cannot answer requests arriving over the customer's
wired LAN; anything not on the access point — including a sibling
container on the same host — is refused by design.

Notes for consumers:

- `ssid` is the name **on the air**, suffix included, not the configured
  prefix. Print this one or you will send someone looking for a network
  nobody is broadcasting.
- `security` is `wpa` or `open`. On `open` there is no passphrase and no
  join payload, and both fields are `null` — say "no password needed"
  rather than rendering a null.
- `qr_payload` is the same string the QR encodes, so you can render the
  code at whatever size your screen wants without re-deriving the
  `WIFI:` escaping rules.
- **Do not hardcode the setup address.** `--portal-gateway` is
  configurable; `gateway` and `port` in this file are the authority for
  where the portal actually is.
- **Match on `gateway` *and* `interface` when identifying the portal's
  address among the host's own.** A host application that lists "you can
  reach this device at ..." has to leave the setup address out of it,
  and the number alone is ambiguous — `192.168.42.1` is an ordinary LAN
  address too, and a device whose ethernet happens to hold it would
  otherwise hide its real address from its own operator. `interface` is
  the device the portal is on, resolved rather than taken from the flag.
- Parse leniently: new fields may appear without `schema` changing. It
  is bumped only when a field is removed or changes meaning.
- **Check the heartbeat, not just the file.** `heartbeat_unix` is
  refreshed every `heartbeat_interval_s` while the portal runs. A file
  whose heartbeat is older than a few intervals is a portal that died
  too hard to remove it, and `portal_active` will still say `true`.
  Take the interval from the file rather than hardcoding 15, and allow
  a couple of missed beats before calling it dead.

  This is the case worth handling: a `SIGKILL`\ ed portal leaves
  NetworkManager holding the access point, so the radio still looks
  healthy from outside and the gateway address is still up. Measured on
  a Pi 5. Nothing but the heartbeat distinguishes it.
- It holds a WPA passphrase in clear text. It is written `0640`,
  atomically, and never through a symlink at the target — put it
  somewhere the host application can read and the network cannot.

## The setup network's name

`--portal-ssid` is a *prefix*. Four random characters are appended to it, so
what a phone sees is `WiFi Connect-K3QM`.

That is not decoration. Unbox five screens in one room with a fixed name and
they all broadcast it: the phone shows one entry, joins whichever is
loudest, and the installer configures a device at random while reading the
screen of another — and because every portal generates its own passphrase,
four of the five will not accept the credentials displayed in front of
them.

```bash
wifi-connect --portal-ssid 'Anthias Setup'       # Anthias Setup-7FQR
wifi-connect --portal-ssid 'Anthias Setup' --portal-ssid-suffix 0   # as-is
```

Set `0` if the name is printed on a sticker or in a manual, and accept that
two devices in earshot are indistinguishable.

The suffix is random per run rather than derived from the MAC: the
passphrase and the QR already change on every run, so a stable name would
be the only thing implying a continuity it does not have.

Characters come from the upper-case half of the passphrase alphabet, which
excludes everything needing escaping inside a `WIFI:` QR payload and every
glyph that is easy to misread — this one is *compared*, against a list on a
phone, so `K3QM` must not be a guess between `0` and `O`.

**The 32-octet limit counts the suffix.** A 30-byte prefix is legal alone
and five bytes too long once the separator and four characters are
appended; that is rejected at startup, with the real length in the message,
rather than discovered at the radio.

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
- **WEP is not supported.** Its encryption has been broken for two
  decades, so a device set up on it is open to anyone in radio range. A
  WEP network is listed as "WEP (not supported)" so the user can find it
  and learn why, but it cannot be chosen, and a submission naming it is
  refused before the access point comes down. Switch the router to WPA2
  or WPA3.
- **Enterprise WiFi is PEAP/MSCHAPv2, TTLS/MSCHAPv2 or TTLS/PAP.** The
  portal offers the three as a *sign-in method* next to the username,
  PEAP by default. Certificate-based EAP-TLS needs key and certificate
  paths a portal cannot collect. TTLS/PAP sends the password itself
  through the tunnel, so it is refused while
  `--insecure-eap-skip-server-verification` is set: without a verified
  server, the tunnel could end at a look-alike network. The RADIUS
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
- **Static addressing is per join, from the portal.** The collapsed *IP
  settings* block takes an IPv4 address and gateway, an IPv6 address and
  gateway, and DNS servers. Each family is independent and blank means
  automatic (DHCP for IPv4; SLAAC/DHCPv6 for IPv6). Addresses need a prefix
  length (`192.168.1.50/24`, or `/255.255.255.0`, or `2001:db8::50/64`).
  A fixed IPv4 address needs at least one DNS server, since DHCP is where
  the network would otherwise have supplied one; DNS servers entered here
  replace the network's on both families. The portal refuses a gateway
  outside the subnet before the access point goes down, because that
  mistake joins fine and then reaches nothing. Once the join succeeds, the
  device's older profiles for that network are removed, so the next boot
  cannot bring the network back up with DHCP instead. A secured network
  needs its password re-entered when setting a static address; the
  password saved with the old profile is not reused.
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

## Verifying releases

Every release is signed keylessly with [Sigstore cosign](https://docs.sigstore.dev/)
by the release workflow itself: there is no long-lived key to leak, and
the signing certificate names the exact workflow file and tag that
produced the artifact. Signatures are recorded in the public Rekor
transparency log.

The container image (the multi-arch index and each platform manifest
under it):

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/Screenly-Labs/wifi-connect/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/screenly-labs/wifi-connect:2026.10.0
```

Every file on a GitHub Release (binaries, tarballs, snaps and
`SHA256SUMS`) has a `<file>.sigstore.json` bundle next to it:

```bash
cosign verify-blob \
  --bundle wifi-connect-2026.10.0-aarch64-unknown-linux-musl.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/Screenly-Labs/wifi-connect/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  wifi-connect-2026.10.0-aarch64-unknown-linux-musl.tar.gz
```

Verifying `SHA256SUMS` this way and then running `sha256sum -c SHA256SUMS
--ignore-missing` covers whatever else you downloaded. (`SHA256SUMS`
lists the release files, not the bundles.) Use cosign v3 or later: the
signatures use the standard Sigstore bundle format, and the image
signatures are stored as OCI referrers, which is what v3 looks for by
default.

The image and the tarballs also carry GitHub build-provenance
attestations, which record the commit and workflow run they were built
from:

```bash
gh attestation verify oci://ghcr.io/screenly-labs/wifi-connect:2026.10.0 -R Screenly-Labs/wifi-connect
gh attestation verify wifi-connect-2026.10.0-aarch64-unknown-linux-musl.tar.gz -R Screenly-Labs/wifi-connect
```

Snaps installed from the Snap Store are additionally verified by `snapd`
against the store's own signature.

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
