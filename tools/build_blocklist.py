#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a sorted truncated-FNV-1a hash blob
for the ESP32-C3 ad-blocker. Hashes live in flash and are binary-searched on the
device, so no PSRAM is needed.

HASH_BYTES MUST match the firmware (src/main.cpp). 5 bytes (40-bit) keeps
~0 collisions up to ~500k domains while fitting half a million in <3 MB.

Usage: build_blocklist.py [out.bin] [src ...]
  src = local file or URL. With none given, downloads a balanced daily-driver set
  (StevenBlack base + Hagezi Light) ~= 100k entries: blocks ads/trackers/malware
  but leaves WhatsApp/Instagram/social/messaging working.

  For the aggressive "test the limits" build (~500k, also blocks social/messaging):
    build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt
"""
import re
import sys, os, math, urllib.request

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

# Keep the blob small enough for the device to update SAFELY: it writes the new
# list to /blocklist.new while the live one keeps serving, so the filesystem
# needs ~2x the list size. On the shipped 2.63 MB LittleFS that means <= ~1.3 MB
# (one entry is 5 bytes -> ~260k domains). A bigger blob still works, but the
# device has to truncate the live list first, which turns blocking off for the
# whole (slow) download. Override with --max-bytes; 0 disables the cap.
MAX_BYTES = 1_300_000

# Daily-driver set for the single-app (no-OTA) partition: ads/trackers/malware
# worldwide (Hagezi Pro + StevenBlack base) plus the RU segment (AdGuard Russian
# filter + Schakal's RU AdList/EasyList conversion). ~260k domains / ~1.3 MB.
DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',                            # base: ads + malware
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt',   # Hagezi Pro (wildcard = domain + subdomains)
    'https://raw.githubusercontent.com/alexsannikov/adguardhome-filters/master/admalware.txt',     # Schakal: RU AdList + EasyList (domains)
    'https://filters.adtidy.org/extension/ublock/filters/1.txt',                                   # AdGuard Russian filter (DNS-usable subset)
]

# ||domain^  or  @@||domain^  optionally followed by $modifiers
ADG = re.compile(r'^(@@)?\|\|([a-z0-9._-]+)\^?(\$.*)?$', re.I)

ALLOW_MISSING = False

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK                      # truncate to HASH_BYTES

def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode('utf-8', 'ignore')

def main():
    global ALLOW_MISSING
    args = [a for a in sys.argv[1:] if a != '--allow-missing']
    ALLOW_MISSING = '--allow-missing' in sys.argv[1:]
    max_bytes = MAX_BYTES
    for a in list(args):
        if a.startswith('--max-bytes'):
            args.remove(a)
            max_bytes = int(a.split('=', 1)[1]) if '=' in a else 0
    out = args[0] if args else 'blocklist.bin'
    sources = args[1:] if len(args) > 1 else DEFAULT_SOURCES

    domains, allow = set(), set()
    prio = {}                     # domain -> index of the first source that listed it
    skipped = 0
    for si, src in enumerate(sources):
        try:
            data = read_source(src)
        except Exception as e:
            # Fail loudly: silently dropping a source shrinks the list without anyone noticing
            # (happened when Hagezi retired domains/light.txt). Pass --allow-missing to continue.
            print(f'  !! FAILED to read {src}: {e}', file=sys.stderr)
            if not ALLOW_MISSING: sys.exit(1)
            continue
        for line in data.splitlines():
            s = line.strip()
            if not s or s[0] in '!/[':
                continue
            # Cosmetic / element-hiding rules (mail.ru##.box_double, vk.com#@#.ad,
            # ...#?#..., ...#%#//scriptlet) look like "domain#..." — splitting at
            # the first '#' (hosts comment) would turn them into the BARE domain and
            # block whole sites. Detect and drop them before comment-stripping.
            if any(m in s for m in ('##', '#?#', '#@#', '#$#', '#%#', '#>#', '#@$#')):
                skipped += 1; continue
            if s.startswith(('||', '@@')):
                line = s
            else:
                line = s.split('#', 1)[0].strip()     # hosts-style trailing comment
            if not line:
                continue
            # AdGuard / ABP basic rules: ||example.com^  and allow rules @@||example.com^
            m = ADG.match(line)
            if m:
                if m.group(3):            # has $modifiers (client/dnstype/etc.) -> can't express, skip
                    skipped += 1; continue
                d = norm(m.group(2))
                if m.group(1):
                    allow.add(d)
                else:
                    domains.add(d); prio.setdefault(d, si)
                continue
            if line.startswith(('||', '@@', '|', '/')) or any(c in line for c in '^$*'):
                skipped += 1; continue    # other adblock syntax (regex, wildcards, cosmetic) -> skip
            parts = line.split()
            if parts[0] in ('0.0.0.0','127.0.0.1','::1','::'):
                entries = parts[1:]
            else:
                entries = parts if len(parts) == 1 else []
            for d in entries:
                d = norm(d)
                if '.' in d and ' ' not in d:
                    domains.add(d); prio.setdefault(d, si)
    if allow:
        before = len(domains); domains -= allow
        print(f'allowlisted      : {before - len(domains):,} removed ({len(allow):,} @@ rules)', file=sys.stderr)
    if skipped:
        print(f'skipped rules    : {skipped:,} (adblock syntax that a DNS hash list cannot express)', file=sys.stderr)

    # Deterministic size cap: keep the domains from the earliest (highest-priority)
    # sources first, then fill with hashes in a stable order. This is what lets the
    # device update side-by-side without ever turning blocking off.
    if max_bytes:
        maxe = max_bytes // HASH_BYTES
        if len(domains) > maxe:
            kept = sorted(domains, key=lambda d: (prio.get(d, 10 ** 9), fnv(d.encode())))[:maxe]
            print(f'capped           : {len(domains):,} -> {len(kept):,} domains '
                  f'({max_bytes:,} B budget; earliest sources win)', file=sys.stderr)
            domains = set(kept)

    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash
    with open(out, 'wb') as f:
        for h in uniq:
            f.write(h.to_bytes(HASH_BYTES, 'little'))

    n, size = len(uniq), len(uniq) * HASH_BYTES
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> over-block)')
    print(f'flash blob       : {size:,} bytes  ({size/1024/1024:.2f} MB)  -> {out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query')

if __name__ == '__main__':
    main()
