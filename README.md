# esp32-c3-adblock

**English** · [Русский](README_RU.md)

A **Pi-hole-style DNS ad-blocker** that runs on a **$2 ESP32-C3** — *no PSRAM required*.

> 📰 Featured on [Tom's Hardware](https://www.tomshardware.com/networking/clever-hacker-fits-537-000-domains-in-a-tiny-usd5-esp32-ad-blocking-dongle-firmware-uses-only-around-50kb-of-ram-and-can-answer-blocked-lookups-in-10-milliseconds), [XDA Developers](https://www.xda-developers.com/this-tiny-esp32-powered-gadget-blocks-537000-domains-only-uses-50kb-of-ram/), and [Korben](https://korben.info/en/half-million-ad-blocking-domains-50kb-ram-esp32.html).

The trick everyone misses: you don't need to keep the blocklist in RAM. Store the
domains as **sorted 40-bit hashes in flash** and binary-search them. 140,000+ domains
fit in ~0.7 MB of flash and are matched in ~10 ms, using **~50 KB of RAM**.

```
query in ──▶ extract domain ──▶ FNV-1a hash (+ parent suffixes)
         ──▶ binary-search the flash hash table
              ├─ hit  ──▶ answer 0.0.0.0   (sinkholed)
              └─ miss ──▶ forward to upstream resolver, relay the reply
```

## Why this is interesting

Most ESP32 DNS sinkholes load the blocklist (domain *strings*) into RAM, so they
demand PSRAM. This project stores fixed **5-byte (40-bit) hashes in flash** instead:

| | string-in-RAM approach | this (hash-in-flash) |
|---|---|---|
| Hardware | ESP32 + PSRAM (~$8) | ESP32-C3, no PSRAM (~$2) |
| 141k domains | ~2.5 MB of RAM | **0.67 MB of flash** |
| RAM used | most of it | **~50 KB** |
| Lookup | string compare | ~18 flash reads (~10 ms incl. WiFi RTT) |
| Collisions | n/a | 0 at 141k (1 at 537k) |

**Why 40 bits?** It's the sweet spot for this flash budget. Collisions follow the
birthday bound — at 141k domains you get ~0, at 537k about 1 (i.e. one unlucky
domain gets over-blocked). Dropping to 32 bits would save 20% of the flash but
cost ~7 collisions at 250k; going to 64 bits wastes 3 bytes per domain to solve
a problem you don't have.

The same trick works on bigger chips — it isn't a C3 workaround. On a 16 MB
ESP32-S3 these hashes hold **~2.7M domains** vs ~466k for strings in 8 MB of
PSRAM. Hashes in flash beat strings in PSRAM basically everywhere; the C3 just
makes it undeniable.

## Hardware

- Any **ESP32-C3** board (tested on a C3 SuperMini), 4 MB flash, **no PSRAM needed**
- Classic **ESP32** (DevKit / WROOM, 4 MB) also builds: `pio run -e esp32dev -t upload` (community-contributed, compile-tested; the C3 is the tested target)
- Power it from a **stable USB source** (a phone charger or your router's USB port).
  Cheap/loose USB-C→A adapters can brown out the radio during WiFi transmit.
- A **USB-A → USB-C dongle** lets it plug straight into the spare USB port on the
  back of most routers — no power supply, no extra box.

### Enclosure

A printable case for the C3 SuperMini: [`hardware/esp32-c3-supermini-enclosure.stl`](hardware/esp32-c3-supermini-enclosure.stl)

Printing notes:
- No supports needed; 0.2 mm layers, ~15% infill is plenty.
- **Keep the antenna end clear.** The C3's PCB antenna is the zig-zag trace on the
  short edge opposite the USB-C port — don't bury it in solid plastic or put metal
  near it, or your RSSI will suffer.
- Leave the vents open: the board idles around 45–55 °C.

## Build & flash (PlatformIO)

One USB flash to get going — after that, **firmware and blocklist both update over WiFi** (see below).

> ⚠️ Use a **current PlatformIO** — the VSCode PlatformIO extension's bundled core, or
> `pip install -U platformio` in a venv. The distro/apt `platformio` package (e.g. 4.3.4) is
> too old and fails with `AttributeError: ... 'resultcallback'` (issue #4). A one-click browser installer is on the way (hosting TBD).

```bash
# 1. copy the secrets template (gitignored, stays local) and edit it:
#    - WIFI_SSID / WIFI_PASS are optional — leave the placeholders and use the
#      on-device setup portal instead (below).
#    - WEB_USER / WEB_PASS / OTA_PASS are NOT optional: they gate the dashboard's
#      state-changing endpoints (/ban, /addblock, /upload, /update, /setupdate,
#      /forgetwifi) and network OTA. Pick real values — these used to be wide
#      open to anyone on the LAN.
cp src/secrets.example.h src/secrets.h
#    then edit src/secrets.h

# 2. build the blocklist hash table (default = Hagezi Pro + StevenBlack +
#    Schakal RU AdList + AdGuard Russian; ~266k entries, RU sites stay usable)
python3 tools/build_blocklist.py data/blocklist.bin

# 3. flash firmware + the blocklist filesystem (the one and only USB flash)
pio run -t upload
pio run -t uploadfs

# 4. watch it boot, note the IP / open the dashboard
pio device monitor          # -> http://c3adblock.local
```

### Your own blocklists

`build_blocklist.py OUT.bin [SOURCE ...]` takes any mix of URLs and local files, in any of
these formats:

- **hosts files** — `0.0.0.0 ads.example.com tracker.example.com` (all domains on the line are included)
- **plain domain lists** — one domain per line
- **AdGuard / Adblock basic rules** — `||ads.example.com^` blocks, `@@||ok.example.com^`
  removes a domain (e.g. to mirror an AdGuard Home allowlist)

A blocked domain also blocks its subdomains. Rules a DNS hash list can't express (regex,
wildcards, `$` modifiers, cosmetic `##` rules) are skipped and counted. An `@@` rule only
un-blocks that exact entry — it can't carve a subdomain out of a blocked parent. If a source
can't be downloaded the build stops instead of silently producing a smaller list
(`--allow-missing` to override).

### WiFi setup (no re-flash needed)

If it can't connect (or you never set `secrets.h`), it starts an open access point
**`C3-AdBlock-XXXX`** with a captive portal — join it from a phone, pick your network,
type the password, done. To move it to a new network later: click **Forget WiFi** on
the dashboard, or hold the **BOOT** button while powering on, and the setup portal
comes back. (`/forgetwifi` requires auth now, so it's no longer a bare URL you can
just visit — see Security below.)

## Over-the-air updates (no more USB)

The dashboard at **http://c3adblock.local** does it all:

- **Blocklist** — drop a freshly built `blocklist.bin` into *Blocklist → Upload*, or set a
  URL under *Remote auto-update* and the device pulls a prebuilt `blocklist.bin`
  on a schedule. A fresh default list is rebuilt **every day** by GitHub Actions and
  published at a stable URL, so pasting this once keeps a device current on its own:
  `https://github.com/hybhyyb/esp32-c3-adblock/releases/download/blocklist/blocklist.bin`
- **Firmware** — upload `.pio/build/c3/firmware.bin` under *Firmware → OTA update* (needs a
  dual-OTA partition table; the default single-app table flashes firmware over USB instead).
  Or push over WiFi from the CLI:
  ```bash
  pio run -t upload --upload-port c3adblock.local --upload-protocol espota
  ```

**4 MB flash tradeoff:** this repo ships a **single-app** `partitions.csv` — no network
firmware OTA (flash firmware over USB), which frees **2.63 MB** for blocklists (**~525k
domains max**) and leaves room for the daily auto-update to write a fresh list alongside
the live one. Prefer network firmware OTA? Switch to a dual-OTA table — two app slots
leave ~1.3 MB for the blocklist (**~250k domains max**).

## Security

The dashboard's read-only view (`/`, `/stats.json`) stays open, but every
state-changing endpoint requires **HTTP Basic Auth** (`WEB_USER`/`WEB_PASS` from
`secrets.h`):

- `/ban`, `/addblock`, `/unblock`, `/forgetwifi`
- `/upload`, `/update` (blocklist and firmware OTA)
- `/setupdate`, `/fetchnow`

Network OTA (`ArduinoOTA`, e.g. `pio run -t upload --upload-port c3adblock.local
--upload-protocol espota`) requires `OTA_PASS` from the same file.

Without this, anyone who could reach the device on the LAN could reflash it
with arbitrary firmware or rewrite the blocklist with zero credentials — worth
knowing given the device sits in the path of every DNS query on your network.
Custom blocked-domain names are also HTML-escaped before being rendered on the
dashboard, closing a stored-XSS path where a domain string containing markup
(added via `/addblock`) would otherwise execute in the viewing browser.

**Basic Auth here is a LAN-trust-boundary control, not encryption.** Everything
is plain HTTP on :80 — this chip has no realistic budget to run a TLS server.
Basic Auth credentials are base64 (not encrypted) and sent on every authenticated
request; anyone who can already sniff your LAN traffic (open/guest WiFi, ARP
spoofing) can read them off the wire. This hardens against the common case —
another device on your network hitting the API with no credentials at all, or a
browser tab CSRF'ing it — not against an on-path network attacker.

**CSRF via cached Basic Auth:** browsers auto-attach cached Basic Auth
credentials to *any* subsequent request to an already-authenticated origin —
including one triggered by a totally unrelated page the same browser visits
later (e.g. `<img src="http://c3adblock.local/forgetwifi">`, no JS required).
That would let any webpage silently drive this API once you've logged into the
dashboard once, regardless of who's on your LAN. Every mutating endpoint above
now also requires a custom `X-Requested-With: c3-adblock` header, which a plain
`<img>`/auto-submitted `<form>` CSRF can't attach (only same-origin `fetch()`
can, which is what the dashboard's own JS does) — this is why `/forgetwifi` is
no longer a bare URL you can visit directly; use the dashboard button instead.

**Default credentials:** if `secrets.h` still has the placeholder
`CHANGE_ME_WEB_PASSWORD` / `CHANGE_ME_OTA_PASSWORD` values from
`secrets.example.h`, the device boots with a "password" that's public (it's
sitting in this repo's example file). The firmware logs a warning over serial
and shows a banner on the dashboard when this is the case — but it will still
boot and run, so don't skip setting real values in `secrets.h` before trusting
this on a network you don't fully control.

Out of scope for now: the WiFi setup portal's access point (`C3-AdBlock-XXXX`)
is still open (unencrypted) by design — it needs to be joinable without knowing
a password first. The real WiFi password you type into the portal is only as
safe as that local radio link during the brief setup window.

## Network topology

```
clients (phones · laptops · TVs · IoT)
        │ DNS queries → 192.168.1.85
        │ (the router's DHCP hands clients this DNS)
        ▼
┌───────────────────────────────────────┐
│   C3 AdBlock · UDP :53                │
│   192.168.1.85 · dashboard: c3adblock.local
│  ┌────────────────┬─────────────────┐ │
│  │ blocklist hit  │ allowed / miss  │ │
│  │ → answer 0.0.0.0│ → forward       │ │
│  └────────────────┴────────┬────────┘ │
└────────────────────────────┼──────────┘
                             │ DNS passthrough → 192.168.1.1
                             ▼
                     router → ISP resolvers
```

The board sits one hop below the router on the DNS path: it answers blocked
queries itself (0.0.0.0) and forwards everything else to the router. The router
keeps doing DHCP/routing; only the DNS pointer changes. `dig @192.168.1.85
doubleclick.net` → `0.0.0.0`, `dig @192.168.1.85 github.com` → real IP.

## Use it

Point a device's DNS at the C3's IP, or add it as a **secondary resolver** behind
your main DNS. Test:

```bash
dig @<c3-ip> doubleclick.net   # -> 0.0.0.0  (blocked)
dig @<c3-ip> github.com        # -> real IP  (forwarded)
```

## Why this instead of router-based ad-blocking?

Keenetic / Asus / TP-Link and other routers ship DNS filtering (Yandex/AdGuard
DNS profiles, dnsmasq lists), and for most people that's the right answer:
free, zero extra hardware, nothing to maintain. This device wins where a router
usually can't:

- **RU coverage + freshness you control.** Vendor profiles are whatever the
  vendor decided to ship, and RU ad networks (Yandex.Direct, AdFox, VK Ads,
  MyTarget) often sit on domains routers don't block. Here the list is your own
  mix (Hagezi Pro + StevenBlack + Schakal RU AdList + AdGuard Russian, ~266k),
  rebuilt every day by GitHub Actions and pulled automatically.
- **Vendor-independent updates.** A router's built-in filter updates on the
  vendor's schedule (or not at all); this device updates itself daily with no
  firmware involvement.
- **Surgical allowlist & bans.** Unblock exactly `youtube.com` (survives every
  list swap), or ban a whole client per-device, from the dashboard. Router
  filters are usually all-or-nothing per profile.
- **Logs and counters.** Live DNS query log with per-client block/pass counts
  and daily totals — routers don't expose this for a DNS filter.
- **The router itself is untouched.** It's a separate little box on the DNS
  path: no firmware risk to your router, no dependency on a vendor keeping the
  feature alive, and it keeps working if you later change routers.

**When it is NOT better:** if you want the simplest possible setup, keep the
router's built-in filter — one extra device is one more thing to power and one
more point of failure. Neither approach can fix first-party in-page ad
injection (widgets inside `mail.ru` etc.): that needs a browser extension / uBO,
DNS-level blocking can't see it. Both are DNS-speed (single-digit ms); the
advantage here is control, freshness and RU coverage, not raw speed.

## FAQ

**YouTube ads are not blocked.** First-party ads are served from the same
domains as the video, so DNS can't tell them apart — that's a browser-extension
job (uBlock Origin). Which is exactly why `youtube.com` sits in the default
allowlist: blocking it would break playback, not just ads.

**My router hands out IPv6 DNS.** The board answers IPv4 UDP :53 only. If
clients learn a DNS server via IPv6 RA/DHCPv6, they bypass it. Fix on the
router: keep handing out the IPv4 DNS (this board), or disable the IPv6 DNS
advertisement. (There is no IPv6 DNS server on the C3.)

**A site I need stopped working.** It's either in an aggressive list or a newly
added domain. Add it under *Allowed domains* on the dashboard — Allow wins over
every list and survives updates.

**My router already has a DNS filter.** It usually can't match the RU coverage,
freshness and control here — see "Why this instead of router-based
ad-blocking?".

**Move it to another WiFi network.** Dashboard → Settings → *Forget Wi-Fi*, or
hold **BOOT** while powering on — the setup portal comes back.

**Newest firmware without USB?** The blocklist always updates over WiFi
(scheduled or a manually uploaded `.bin`). Firmware OTA over WiFi needs the
dual-OTA partition table; this repo defaults to single-app (bigger blocklist
budget), so firmware flashes over USB. A deliberate tradeoff — see "4 MB flash
tradeoff".

## Gotchas (learned the hard way)

- **ModemManager** (default on Fedora/Ubuntu) grabs `/dev/ttyACM0` and toggles
  DTR/RTS, which **resets the C3** and blocks serial. Fix:
  ```bash
  sudo systemctl stop ModemManager
  echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```
- The C3's USB-Serial-JTAG console can swallow early boot output until the host
  connects (`while(!Serial)` helps).
- DNS clients add an **EDNS OPT** record; a blocked reply must contain only the
  question + answer (ANCOUNT=1, NSCOUNT=ARCOUNT=0) or it's malformed.

## Done / how it could grow

- ✅ Web dashboard — per-client block/allow counts, ban a client, add custom domains
- ✅ mDNS (`c3adblock.local`) for discovery
- ✅ OTA — firmware + blocklist update over WiFi, plus scheduled remote blocklist pulls
- ✅ Captive-portal WiFi setup (no hardcoded creds) + one-click browser web-installer
- ⬜ Bucketed prefix index — ~18 flash reads/lookup → ~1–2 (issue #3), the throughput win
- ⬜ Act as the DHCP server (hand itself out as DNS) for true plug-and-play

## Credits

Inspired by [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) — the
"answer 0.0.0.0 for blocklisted domains" idea. This is an independent from-scratch
implementation focused on the hash-in-flash optimization for PSRAM-less chips.

## License

MIT — see [LICENSE](LICENSE).
