# The snap, and Ubuntu Core

The snap is strictly confined, runs as a disabled-by-default daemon, and
talks to NetworkManager over D-Bus. On Ubuntu Core that NetworkManager is
the `network-manager` snap. Ubuntu Core does not ship it, so it has to be
installed alongside.

## Install

```bash
sudo snap install network-manager
sudo snap install wifi-connect
sudo snap connect wifi-connect:network-manager network-manager:service
sudo snap start --enable wifi-connect
```

- **`network-manager` first.** Out of the box Ubuntu Core networks with
  netplan and systemd-networkd, which wifi-connect cannot drive. The
  `network-manager` snap's `defaultrenderer` option, on by default, switches
  netplan's renderer to NetworkManager so that it manages the WiFi device.
- **The `connect` line is not optional.** snapd does not auto-connect the
  `network-manager` interface. Without it, every D-Bus call is denied and
  the daemon exits at preflight.
- **The daemon is not started by installing it.** `install-mode: disable`
  is deliberate: installing a package should not start broadcasting a setup
  access point on a device that is already online.

`snap services wifi-connect` and `sudo snap logs -n 50 wifi-connect` show
what it is doing.

## Configuration

There is no `/etc/default/wifi-connect` inside a snap. Use `snap set`. Each
key is the binary's long flag name, so `wifi-connect --help` documents both:

```bash
sudo snap set wifi-connect portal-ssid="Acme Setup" interface=wlan0
sudo snap restart wifi-connect
```

| Key | Default |
| --- | --- |
| `portal-ssid` | `WiFi Connect` |
| `portal-passphrase` | generated per run |
| `portal-security` | `auto` (`auto`, `wpa2`, `wpa3`) |
| `insecure-open-portal` | `false` |
| `portal-gateway` | `192.168.42.1` |
| `portal-dhcp-range` | `192.168.42.2,192.168.42.254` |
| `portal-listening-port` | `80` |
| `interface` | auto-detected |
| `activity-timeout` | `0` (never) |
| `wait-for-connection` | `60` |
| `connection-timeout` | `45` |
| `force` | `false` |
| `qr-output` | unset |
| `no-qr-stdout` | `false` |
| `brand-name` | `WiFi Connect` |
| `brand-css`, `brand-logo`, `ui-directory` | unset |
| `default-theme` | `system` (`system`, `light`, `dark`) |
| `log-format` | `text` (`text`, `json`) |
| `log-level` | `info` |

`sudo snap unset wifi-connect <key>` restores a default.

The configure hook validates values when you set them. A passphrase that is
too short, a non-numeric timeout or a misspelt enum value fails `snap set`
and keeps the previous value. Without that check, the bad value would only
show up when the daemon fails to start on the next boot.

A change applies the next time the daemon starts. The hook does not restart
it for you, because it also runs on every refresh, and a restart there would
undo `refresh-mode: endure` (see below).

**Paths** (`brand-css`, `brand-logo`, `ui-directory`, `qr-output`) must sit
under `/var/snap/wifi-connect/common/`. That is the only place on the host
the confined daemon can read from, so the hook rejects any other path at
`snap set` time instead of leaving AppArmor to deny it at runtime.

```bash
sudo install -D -m0644 brand.css /var/snap/wifi-connect/common/brand.css
sudo snap set wifi-connect brand-css=/var/snap/wifi-connect/common/brand.css
```

**The passphrase.** If you leave `portal-passphrase` unset, a new one is
generated on every run and goes to the journal, both as a QR code and in
plain text. Set `qr-output=/var/snap/wifi-connect/common/qr` to also have
the SVG written somewhere a display application can pick it up. If you do
set a fixed passphrase, it is stored in snapd's configuration. Reading that
back with `snap get` requires root.

## Building an Ubuntu Core image

For a fleet you build the image once, and nobody should have to SSH in and
run `snap connect`. Add both snaps to the model, then declare the
connection, and any defaults, in the gadget's `gadget.yaml`:

```yaml
# The model assertion
snaps:
  - name: network-manager
    id: RmBXKl6HO6YOC2DE4G2q1JzWImC04EUy
    type: app
    default-channel: 24/stable
  - name: wifi-connect
    id: <wifi-connect snap-id>
    type: app
    default-channel: latest/stable
```

```yaml
# gadget.yaml
connections:
  - plug: <wifi-connect snap-id>:network-manager
    slot: RmBXKl6HO6YOC2DE4G2q1JzWImC04EUy:service

defaults:
  <wifi-connect snap-id>:
    portal-ssid: Acme Setup
    brand-name: Acme
```

Both blocks address snaps by **snap-id**, not name, and only a snap that
came from the store has one. A `--dangerous` side-loaded `.snap` cannot be
named here. Look the id up with
`snap info wifi-connect | grep snap-id` on any machine.

`defaults` are applied by the configure hook on first boot, before the
daemon first starts, so they go through the same validation as `snap set`.

Starting the daemon is still a separate step. `install-mode: disable` also
applies to a seeded snap, so the image needs something to run
`snap start --enable wifi-connect` once: a configure hook in your own
gadget or app snap, or your provisioning flow. This is on purpose. Only
you know whether a given device should broadcast a setup network on first
boot.

## Behaviour worth knowing about

- **Refreshes do not interrupt a setup in progress.** `refresh-mode:
  endure` means snapd does not restart the daemon on refresh. The new
  revision takes over on the next start. The worst possible moment for a
  restart is the roughly 15-second window where the access point is down
  and the join is in flight.
- **It exits once the device is online.** Exit code 0 after a successful
  join, or at preflight if the device is already online, so the service
  shows `inactive` at that point. That is expected, not a failure.
  `restart-condition: on-failure` restarts it only after a genuine error.

## Troubleshooting

**`apparmor="DENIED" ... name="/sys/devices/.../rfkill*/type"`**. This is
harmless. The NetworkManager client library cross-checks NetworkManager's
own `WirelessHardwareEnabled` against sysfs. Under confinement the sysfs
read is denied, the library falls back to NetworkManager's answer, and a
hard-blocked radio is still reported as one.

**"no WiFi device was found", exit 3, on a device that has one.** Check
the `network-manager` interface first, with
`snap connections wifi-connect`. When it is not connected, AppArmor
filters the replies from NetworkManager, the device list comes back empty,
and this message is the result. If the interface is connected, check
`snap services network-manager`.

**The access point comes up and then goes down again, exit 6.** One of
the portal's three servers could not start, usually because something else
on the host already holds port 53, 67 or 80. The log line before the exit
says which server failed.

**`SO_BINDTODEVICE` denied.** The DHCP socket is pinned to the AP
interface with `SO_BINDTODEVICE`. That has been unprivileged since Linux
5.7, and Ubuntu Core 22 and later ship 5.15 or newer, so this applies at
most to an old Ubuntu Core 20 kernel. The snap deliberately does not plug
`network-control` for it.

## Publishing (maintainers)

The release workflow builds the three snaps on every tag, and attaches them
to the GitHub Release whether or not the store is set up. It publishes to
the store's `stable` channel only when the `SNAPCRAFT_STORE_CREDENTIALS`
repository secret exists. On this repository, the run summary carries a
warning when it does not.

One-time setup, done by hand by whoever owns the store account:

```bash
snapcraft login
snapcraft register wifi-connect
snapcraft export-login --snaps=wifi-connect \
  --acls=package_access,package_push,package_update,package_release \
  credentials.txt
gh secret set SNAPCRAFT_STORE_CREDENTIALS < credentials.txt
rm credentials.txt
```

After that, re-running the release workflow for the latest tag publishes
it. To publish without a new tag, upload the attached `.snap` files once:

```bash
snapcraft upload --release=stable wifi-connect_<version>_<arch>.snap
```
