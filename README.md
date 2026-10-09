# drukarka

Raspberry Pi print server for an HP LaserJet P1005, with passkey-gated admin UI and CUPS kept off the LAN.

## Host workflows

All host operations go through Cargo aliases (Rust `xtask`, no project shell scripts):

| Command | Purpose |
|---------|---------|
| `cargo flash --disk /dev/sda --link ethernet` | Write Pi OS Lite + cloud-init/SSH key (ethernet DHCP) |
| `cargo flash --disk /dev/sda --link wifi --ssid … --password …` | Same, join Wi‑Fi on first boot |
| `cargo netconfig --boot /run/media/$USER/bootfs --link wifi --ssid … --password …` | Change link on an already-flashed boot partition |

Wi‑Fi credentials are **never** stored in the repo. Pass `--ssid` / `--password`, or export `DRUKARKA_WIFI_SSID` and `DRUKARKA_WIFI_PASSWORD`. Optional: `DRUKARKA_WIFI_COUNTRY` (default `PL`).
| `cargo bootstrap` | Packages, CA, CUPS, Avahi over SSH |
| `cargo build-pi` | Cross-compile `drukarka-server` for aarch64 |
| `cargo deploy` | Upload release, migrate, flip symlink, restart |
| `cargo rollback` | Previous release |
| `cargo migrate` | Apply DB migrations on the Pi |
| `cargo enroll` | One-time passkey enroll URL |
| `cargo status` | Remote health |

## Clients

- **Apple / Linux:** discover `HP LaserJet P1005 @ drukarka` (AirPrint / IPP) or `http://drukarka.local:631/ipp/print`
- **Windows 7:** add IPP printer `http://drukarka.local:631/ipp/print` (path rewrite proxy)
- **Admin UI:** `https://drukarka.local/` — trust `out/ca.crt` first, then `cargo enroll`

## Tests

```bash
cargo test-e2e          # mock CUPS, no printer — in-process + real HTTPS binary
cargo test --workspace  # unit + e2e
```

E2E (`crates/server/tests/e2e.rs`): mock CUPS backend (never talks to hardware). Covers auth gate, `/cups/` HTML/`Location` wrap, escaped `/printers/…` redirects, fake print POST, Win7 IPP `/ipp/print` rewrite, logout, and a process-level HTTPS run of `drukarka-server`.

## Layout on the Pi

```
/opt/drukarka/current → releases/<id>/
/var/lib/drukarka/state.db
/etc/drukarka-ca/
```
