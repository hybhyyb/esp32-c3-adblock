// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds + daily counters
#include <esp_task_wdt.h>      // watchdog: reboot if loop() stalls
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include <esp_heap_caps.h>
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 9, 9, 9, 9                    // Quad9
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
// NOTE: replies go out on dnsServer (bound to port 53), NOT on a separate
// ephemeral socket: stub resolvers like Windows nslookup silently discard any
// response whose SOURCE port is not 53 (RFC 1035), which made nslookup always
// time out while DnsClient/raw clients worked. wifi sendto() does not depend
// on unread rx data (plain lwIP sendto), so the old TX-only socket split is
// unnecessary; transient ENOMEM is handled by the OutPkt queue either way.
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// async upstream forwarding: queries are sent and tracked; the reply is matched
// by its echoed transaction id (and question hash) from the loop and relayed to
// the client, so a slow upstream never blocks the DNS/HTTP loop. The question is
// stored as a 32-bit hash (not raw bytes) so hundreds of slots stay cheap:
// a 16-bit random txid alone would collide ~12% at 128 in flight.
struct PendingFwd { uint32_t ip, qh, t0; uint16_t port, qid, wid, ql; uint8_t valid; };
static const int MAX_PENDING = 512;
static PendingFwd pend[MAX_PENDING];
static uint32_t fwdExpired = 0, fwdSent = 0, fwdDone = 0, fwdUnmatched = 0;
static uint32_t dnsRx = 0, fwdTxFail = 0, replyTx = 0, replyTxFail = 0;
static uint32_t replyDrop = 0, rxIdle = 0, passN = 0;
static uint32_t qHash(const uint8_t* p, int n) {
  uint32_t h = 2166136261u;
  for (int i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
  return h;
}

// Deferred TX queue: WiFiUDP::endPacket() fails with ENOMEM (errno 12) whenever
// the WiFi TX ring is full — back-to-back sends during a burst overflow its 32
// dynamic buffers. Retrying inline would stall the read path, but the lwIP
// receive mailbox only holds 6 datagrams (CONFIG_LWIP_UDP_RECVMBOX_SIZE), so a
// stalled reader drops inbound queries by the dozen. Instead the datagram is
// staged here and txDrain() sends it from loop() with yields.
struct OutPkt { OutPkt* next; uint32_t ip, t0; uint16_t port, len; uint8_t up, tries; };
static OutPkt* txHead = nullptr, *txTail = nullptr;
static int txCount = 0;
static uint32_t txBytes = 0, txStaged = 0, txSentN = 0, txGiveUp = 0, txDropQ = 0;
static const int TX_MAX = 256;
static const uint32_t TX_MAXB = 49152;
static bool txPush(uint32_t ip, uint16_t port, uint8_t up, const uint8_t* p, int n) {
  if (n <= 0 || n > 1472 || txCount >= TX_MAX || txBytes + n > TX_MAXB) { txDropQ++; return false; }
  OutPkt* q = (OutPkt*)malloc(sizeof(OutPkt) + n);
  if (!q) { txDropQ++; return false; }
  q->next = nullptr; q->ip = ip; q->port = port; q->len = n; q->up = up;
  q->tries = 0; q->t0 = millis();
  memcpy(q + 1, p, n);
  if (txTail) txTail->next = q; else txHead = q;
  txTail = q; txCount++; txBytes += n; txStaged++;
  return true;
}

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label;
             uint32_t secTs, secN, autoUntil; uint8_t noisy; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

// Explicit allowlist: these domains are never blocked even if a hash in the
// flash list matches them (checked before the flash lookup, so it survives
// any blocklist upload/auto-update — e.g. a remote list still carrying
// youtube.com cannot re-block a domain the owner has whitelisted).
static const int MAX_ALLOW = 64;
String allowDom[MAX_ALLOW]; uint64_t allowHash[MAX_ALLOW]; int numAllow = 0;

// Recent-query log: ring buffer of the last QLOG_N DNS queries (RAM only, no
// flash wear), exposed at /qlog.json so the dashboard can show exactly which
// domains were blocked vs forwarded and by whom.
struct QLogEnt { char dom[48]; uint32_t ip; uint32_t t; uint8_t blocked; };
static const int QLOG_N = 128;
static QLogEnt qlog[QLOG_N]; static int qlogI = 0; static uint32_t qlogTot = 0;
static void qlogAdd(const char* dom, uint32_t ip, bool blocked) {
  QLogEnt& e = qlog[qlogI]; qlogI = (qlogI + 1) % QLOG_N; qlogTot++;
  strncpy(e.dom, dom, sizeof(e.dom) - 1); e.dom[sizeof(e.dom) - 1] = 0;
  e.ip = ip; e.t = millis(); e.blocked = blocked;
}

// Daily blocked/allowed counters: the C3 has no RTC, so wall-clock days come
// from NTP; today's numbers are flushed to NVS every few minutes so a reboot
// doesn't lose them. tzStr is a POSIX TZ string ("MSK-3" = Moscow, no DST),
// editable from the dashboard and kept in backups + /update.cfg.
Preferences prefs;
static const char* DEFAULT_TZ = "MSK-3";
String tzStr = DEFAULT_TZ;
static uint32_t dayToday = 0, dayYest = 0;         // yyyymmdd in local time, 0 = unknown
static uint32_t blkToday = 0, blkYest = 0, alwToday = 0, alwYest = 0;
static uint32_t lastStatFlush = 0;
static void applyTz() { setenv("TZ", tzStr.c_str(), 1); tzset(); }
static uint32_t ymdNow() {
  struct tm t;
  if (!getLocalTime(&t, 0)) return 0;              // time not synced yet
  return (uint32_t)(t.tm_year + 1900) * 10000 + (uint32_t)(t.tm_mon + 1) * 100 + (uint32_t)t.tm_mday;
}
static void dailyRoll() {
  uint32_t d = ymdNow(); if (!d || d == dayToday) return;
  blkYest = blkToday; alwYest = alwToday; dayYest = dayToday;
  dayToday = d; blkToday = 0; alwToday = 0;
}
static void statsFlush(bool force) {
  uint32_t now = millis();
  if (!force && now - lastStatFlush < 300000) return;   // 5 min — NVS write wear
  lastStatFlush = now;
  prefs.begin("stats", false);
  prefs.putUInt("day", dayToday); prefs.putUInt("blk", blkToday); prefs.putUInt("alw", alwToday);
  prefs.putUInt("yday", dayYest); prefs.putUInt("yblk", blkYest); prefs.putUInt("yalw", alwYest);
  prefs.end();
}

// 24 h ring of per-hour query totals (RAM only; lost on reboot — fine for a sparkline).
// Slot index = hour of day in the device's local TZ, so the client can label 00..23.
static uint32_t hq[24] = {0}, hb[24] = {0};
static int hHour = -1;                                   // current local hour, -1 = NTP not synced yet
static void hourCount(bool blocked) { if (hHour >= 0) { hq[hHour]++; if (blocked) hb[hHour]++; } }
static void hourRoll() {
  struct tm t;
  if (!getLocalTime(&t, 0)) return;
  int h = t.tm_hour;
  if (h == hHour) return;
  if (hHour < 0) { memset(hq, 0, sizeof(hq)); memset(hb, 0, sizeof(hb)); }
  else { int k = hHour; do { k = (k + 1) % 24; hq[k] = 0; hb[k] = 0; } while (k != h); }
  hHour = h;
}

// Noisy-client detector: a client blasting >NOISY_LIMIT q/s for NOISY_SECS straight
// seconds gets a RAM-only temp ban (reboot clears it; manual bans stay). Protects
// against stray loops/chatty devices without ever persisting a false positive.
static const int NOISY_LIMIT = 100;
static const int NOISY_SECS = 5;
static const uint32_t NOISY_BAN_MS = 10UL * 60 * 1000;
static void autoBanTick() {
  uint32_t now = millis();
  for (int i = 0; i < numClients; i++) {
    Dev& c = clients[i];
    if (c.autoUntil && (int32_t)(now - c.autoUntil) >= 0) {      // temp ban expired
      c.banned = false; c.autoUntil = 0; c.noisy = 0; c.secN = 0;
      IPAddress ip(c.ip); Serial.printf("[noisy] unbanned %s (temp ban over)\n", ip.toString().c_str());
    } else if (!c.autoUntil && !c.banned && c.noisy >= NOISY_SECS) {
      c.banned = true; c.autoUntil = now + NOISY_BAN_MS;
      IPAddress ip(c.ip); Serial.printf("[noisy] %u q/s from %s -> temp ban 10 min\n", (unsigned)c.secN, ip.toString().c_str());
    }
  }
}

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// Top blocklist hits of the day: Space-Saving style summary with bounded RAM —
// K=32 slots hold (40-bit blocklist hash, count, display name). On an unknown
// domain we either insert (free slot) or bump-and-reassign the smallest count.
// Near-exact for frequent domains, error <= total/K for the tail. Reset on the
// daily rollover; reboot loses it (same as the hourly ring).
struct TopEnt { uint64_t h; uint32_t n, last; char dom[48]; };
static const int TOP_K = 32, TOP_SHOW = 10;
static TopEnt top[TOP_K];
static uint64_t fnv40(const char* s, size_t n);
static void topAdd(const char* dom) {
  size_t n = strlen(dom); uint64_t h = fnv40(dom, n);
  TopEnt* min = &top[0]; uint32_t minN = 0xFFFFFFFF; int freeSlot = -1; bool hit = false;
  for (int i = 0; i < TOP_K; i++) {
    TopEnt& e = top[i];
    if (!e.n && freeSlot < 0) freeSlot = i;
    if (e.h == h && e.n) { e.n++; e.last = millis(); hit = true; break; }
    if (e.n && e.n < minN) { minN = e.n; min = &e; }
  }
  if (hit) return;
  TopEnt& e = (freeSlot >= 0) ? top[freeSlot] : *min;
  e.h = h; e.n = (freeSlot >= 0) ? 1 : minN + 1; e.last = millis();
  strncpy(e.dom, dom, sizeof(e.dom) - 1); e.dom[sizeof(e.dom) - 1] = 0;
}

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";
uint32_t lastUpdEpoch = 0;          // NTP epoch of last OK list swap, 0 if none

// WiFi provisioning (captive portal)
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }
static bool inAllow(uint64_t h) { for (int i = 0; i < numAllow; i++) if (allowHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h) {
  if (inAllow(h)) return false;   // explicit allow beats custom + flash (order matters: no cache pollution)
  if (inCustom(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static void loadAllow() {
  numAllow = 0; File f = LittleFS.open("/allow.txt", "r"); if (!f) return;
  while (f.available() && numAllow < MAX_ALLOW) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { allowDom[numAllow] = l; allowHash[numAllow] = fnv40(l.c_str(), l.length()); numAllow++; }
  }
  f.close();
}
static void saveAllow() { File f = LittleFS.open("/allow.txt", "w"); if (!f) return; for (int i = 0; i < numAllow; i++) f.println(allowDom[i]); f.close(); }
static bool addAllow(String d) {
  d.trim(); d.toLowerCase();
  if (!d.length() || d.indexOf('.') < 0 || numAllow >= MAX_ALLOW) return false;
  for (int i = 0; i < numAllow; i++) if (allowDom[i] == d) return false;
  allowDom[numAllow] = d; allowHash[numAllow] = fnv40(d.c_str(), d.length()); numAllow++; saveAllow(); return true;
}
static void removeAllow(String d) {
  d.toLowerCase();
  for (int i = 0; i < numAllow; i++) if (allowDom[i] == d) {
    for (int j = i; j < numAllow - 1; j++) { allowDom[j] = allowDom[j+1]; allowHash[j] = allowHash[j+1]; }
    numAllow--; saveAllow(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    c->secTs = 0; c->secN = 0; c->noisy = 0; c->autoUntil = 0;
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
// Send a datagram; on transient ENOMEM stage it for txDrain() instead of
// retrying inline (inline retries block the reader and overflow the 6-slot
// lwIP recv mailbox). Returns false only if it could not even be staged.
static bool sendOrQueue(WiFiUDP& s, uint32_t ip, uint16_t port, uint8_t up,
                        const uint8_t* p, int n, uint32_t& failCtr) {
  s.beginPacket(IPAddress(ip), port);
  s.write(p, n);
  if (s.endPacket()) return true;
  failCtr++;
  return txPush(ip, port, up, p, n);
}
static bool sendReply(const IPAddress& ip, uint16_t port, int len) {
  replyTx++;
  if (sendOrQueue(dnsServer, (uint32_t)ip, port, 0, buf, len, replyTxFail)) return true;
  replyDrop++;
  return false;
}
// Forward to upstream and wait for the reply that actually belongs to THIS query.
// Issue #10: after one timeout the late reply used to sit in the socket and get relayed
// Async form of the old forwardUpstream: copy the question, stamp a fresh txid,
// and fire it upstream. The client's reply arrives later from fwdPoll().
static void fwdStart(int qlen, int qend, const IPAddress& cip, uint16_t cport) {
  int ql = qend - 12;
  if (ql <= 0 || ql > 512 || qend > qlen) return;
  PendingFwd* s = nullptr;
  for (int i = 0; i < MAX_PENDING; i++) if (!pend[i].valid) { s = &pend[i]; break; }
  if (!s) return;                                        // table full: drop, client retries
  s->ip = (uint32_t)cip; s->port = cport;
  s->qid = (uint16_t)((buf[0] << 8) | buf[1]);
  s->ql = ql; s->qh = qHash(buf + 12, ql);
  uint16_t wid = (uint16_t)esp_random();
  s->wid = wid; s->valid = 1; s->t0 = millis();
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  // queue on transient ENOMEM instead of discarding the query (client would
  // see a pure timeout); pending slot stays valid either way
  if (!sendOrQueue(upstreamCli, UPSTREAM, UPSTREAM_PORT, 1, buf, qlen, fwdTxFail)) s->valid = 0;
  else fwdSent++;
}
// Drain staged datagrams from loop(). Yields between sends so the wifi task
// empties the TX ring; gives up after 5 s (past any client's patience).
static bool txDrain() {
  bool did = false;
  for (int budget = 0; budget < 16 && txHead; budget++) {   // cap: reading resumes next pass
    OutPkt* q = txHead;
    WiFiUDP& s = q->up ? upstreamCli : dnsServer;
    s.beginPacket(IPAddress(q->ip), q->port);
    s.write((uint8_t*)(q + 1), q->len);
    if (s.endPacket()) {
      txHead = q->next; if (!txHead) txTail = nullptr;
      txCount--; txBytes -= q->len; txSentN++;
      free(q); did = true;
      continue;
    }
    if (q->up) fwdTxFail++; else replyTxFail++;
    if (millis() - q->t0 > 5000 || ++q->tries > 50) {      // hopeless: drop
      txHead = q->next; if (!txHead) txTail = nullptr;
      txCount--; txBytes -= q->len; txGiveUp++;
      free(q); continue;
    }
    // no delay here: the wifi task (prio 23) preempts loopTask anyway, and an
    // inline sleep would stall the reader (6-slot recv mbox) during a burst;
    // loop() yields on its own when there is nothing to read
    break;
  }
  return did;
}
// Called from loop(): expire stale forwards and drain a burst of upstream
// replies, relaying each match back to its client (via the dedicated reply
// socket). Capped so web/OTA still get a turn.
static bool fwdPoll() {
  uint32_t now = millis();
  // deadline 10s: this network's upstream (ISP via Keenetic DoT) answers
  // NXDOMAIN after a rock-solid 7.0s on EVERY resolver; with a 6s limit those
  // answers were dropped and clients saw DNS_PROBE_FINISHED_BAD_CONFIG.
  // Existing domains answer in <1s, so normal browsing is unaffected;
  // late answers still beat no answer (stub resolvers wait 5-15s and retry).
  for (int i = 0; i < MAX_PENDING; i++) if (pend[i].valid && now - pend[i].t0 > 10000) { pend[i].valid = 0; fwdExpired++; }
  bool did = false;
  for (int budget = 0; budget < 32; budget++) {
    int sz = upstreamCli.parsePacket();
    if (sz <= 0) break;
    did = true;
    const bool fromUp = upstreamCli.remoteIP() == UPSTREAM && upstreamCli.remotePort() == UPSTREAM_PORT;
    int n = upstreamCli.read(buf, sizeof(buf));
    upstreamCli.flush();                                 // oversized datagram can't strand rx_buffer
    if (!fromUp || n < 13) { if (fromUp) fwdUnmatched++; continue; }
    uint16_t wid = (uint16_t)((buf[0] << 8) | buf[1]);
    bool matched = false;
    for (int i = 0; i < MAX_PENDING; i++) {
      PendingFwd& s = pend[i];
      if (!s.valid || s.wid != wid) continue;
      if (n < 12 + s.ql || qHash(buf + 12, s.ql) != s.qh) continue;   // paranoid: question must echo
      matched = true;
      buf[0] = s.qid >> 8; buf[1] = s.qid & 0xFF;
      IPAddress src(s.ip);
      sendReply(src, s.port, n);
      s.valid = 0;
      fwdDone++;
      break;
    }
    if (!matched) fwdUnmatched++;   // late reply to an expired slot, or collision
  }
  return did;
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 64; budget++) {   // drain hard: recv mbox is only 6 deep
    int sz = dnsServer.parsePacket(); if (sz <= 0) { if (budget == 0) rxIdle++; break; }
    did = true;
    dnsRx++;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    if (c) {                                    // per-client query rate -> noisy detector
      uint32_t now = millis();
      if (now - c->secTs >= 1000) { c->secTs = now; c->secN = 1; }
      else if (++c->secN > NOISY_LIMIT) { if (c->noisy < 100) c->noisy++; }
      else if (c->noisy) c->noisy--;
    }
    bool ban = c && c->banned;
    bool blocked = ban || (blockingOn && dl && numHashes && isBlocked(domain));
    if (dl) qlogAdd(domain, (uint32_t)cip, blocked);
    int rlen;
    if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; blkToday++; hourCount(true); if (dl) topAdd(domain); if (c) c->blocked++; }
    else         { totalAllowed++; alwToday++; hourCount(false); if (c) c->allowed++; fwdStart(qlen, qend, cip, cport); rlen = 0; }
    if (rlen > 0) sendReply(cip, cport, rlen);
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

// Dashboard favicon (SVG): dark tile + ad banner with a red slash.
const char FAV_SVG[] PROGMEM = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\"><rect x=\"1\" y=\"1\" width=\"30\" height=\"30\" rx=\"7\" fill=\"#161b22\" stroke=\"#30363d\"/><rect x=\"8\" y=\"11\" width=\"16\" height=\"9\" rx=\"1.5\" fill=\"#c9d1d9\"/><rect x=\"11\" y=\"13.5\" width=\"9\" height=\"2\" rx=\"1\" fill=\"#8b949e\"/><rect x=\"11\" y=\"16.5\" width=\"10\" height=\"2\" rx=\"1\" fill=\"#8b949e\"/><line x1=\"7.5\" y1=\"23.5\" x2=\"24.5\" y2=\"8.5\" stroke=\"#f85149\" stroke-width=\"3\" stroke-linecap=\"round\"/></svg>";

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) +
              "\",\"uplast\":" + String(lastUpdEpoch) + "" +
             ",\"listbytes\":" + String(numHashes * HASH_BYTES) +
             ",\"fsUsed\":" + String((uint32_t)LittleFS.usedBytes()) +
             ",\"fsTotal\":" + String((uint32_t)LittleFS.totalBytes()) +
             ",\"tz\":\"" + jesc(tzStr) + "\"" +
             ",\"today\":{\"blk\":" + blkToday + ",\"alw\":" + alwToday + "}" +
             ",\"yest\":{\"blk\":" + blkYest + ",\"alw\":" + alwYest + "}" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + ",\"qps\":" + c.secN + ",\"noisy\":" + (c.noisy?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "],\"allow\":[";
  for (int i = 0; i < numAllow; i++) { j += (i ? "," : ""); j += "\"" + jesc(allowDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// c3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c3-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

// ---------- settings backup / restore ----------
// custom/allow/banned/update config live only in LittleFS — an uploadfs or a
// format-on-boot wipes them. /backup.json dumps all of it; /restore accepts
// that same file back (multipart upload, same plumbing as /upload).
static void saveUpdateCfg();   // defined with the auto-update code below
static String backupJson() {
  String j = "{\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "],\"allow\":[";
  for (int i = 0; i < numAllow; i++) { j += (i ? "," : ""); j += "\"" + jesc(allowDom[i]) + "\""; }
  j += "],\"banned\":[";
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); j += (i ? "," : ""); j += "\"" + ip.toString() + "\""; }
  j += "],\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"tz\":\"" + jesc(tzStr) + "\"}";
  return j;
}
// Minimal parser for OUR OWN flat backup format (known keys, no nesting) —
// a full JSON library isn't worth the flash here.
static int parseJsonStrArray(const String& s, int i, String* out, int maxN, int& n) {
  n = 0;
  while (i < (int)s.length() && s[i] != ']') {
    while (i < (int)s.length() && s[i] != '"' && s[i] != ']') i++;
    if (i >= (int)s.length() || s[i] == ']') break;
    String v; i++;
    while (i < (int)s.length() && s[i] != '"') {
      if (s[i] == '\\' && i + 1 < (int)s.length()) { i++; v += s[i++]; }
      else v += s[i++];
    }
    if (i < (int)s.length()) i++;                       // closing quote
    if (n < maxN) out[n++] = v;
    while (i < (int)s.length() && s[i] != '"' && s[i] != ']') i++;
  }
  return (i < (int)s.length() && s[i] == ']') ? i + 1 : -1;
}
static String jsonFindStr(const String& s, const char* key, const String& def) {
  String k = "\"" + String(key) + "\":\"";
  int i = s.indexOf(k); if (i < 0) return def;
  i += k.length(); String v;
  while (i < (int)s.length() && s[i] != '"') {
    if (s[i] == '\\' && i + 1 < (int)s.length()) { i++; v += s[i++]; }
    else v += s[i++];
  }
  return v;
}
static long jsonFindNum(const String& s, const char* key, long def) {
  String k = "\"" + String(key) + "\":";
  int i = s.indexOf(k); if (i < 0) return def;
  return s.substring(i + k.length()).toInt();
}
static bool rcvAuth = false;
static String rcvBuf;
static void handleRestoreUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      rcvAuth = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      rcvBuf = "";
      break;
    case UPLOAD_FILE_WRITE:
      if (rcvAuth && rcvBuf.length() < 16384) rcvBuf.concat((const char*)u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_ABORTED:
      rcvBuf = "";
      break;
    default:
      break;
  }
}
static void handleRestoreDone() {
  if (!rcvAuth) { web.requestAuthentication(); return; }
  static String tmp[MAX_CUSTOM];   // biggest of custom(200)/allow(64)/ban(32)
  int n = 0;
  String k = "\"custom\":[";
  int i = rcvBuf.indexOf(k);
  if (i >= 0 && parseJsonStrArray(rcvBuf, i + k.length(), tmp, MAX_CUSTOM, n) >= 0) {
    numCustom = 0;
    for (int j = 0; j < n; j++) {
      String d = tmp[j]; d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
      if (d.length() && d.indexOf('.') > 0 && numCustom < MAX_CUSTOM) {
        customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++;
      }
    }
    saveCustom();
  }
  k = "\"allow\":[";
  i = rcvBuf.indexOf(k);
  if (i >= 0 && parseJsonStrArray(rcvBuf, i + k.length(), tmp, MAX_ALLOW, n) >= 0) {
    numAllow = 0;
    for (int j = 0; j < n; j++) {
      String d = tmp[j]; d.trim(); d.toLowerCase();
      if (d.length() && d.indexOf('.') > 0 && numAllow < MAX_ALLOW) {
        allowDom[numAllow] = d; allowHash[numAllow] = fnv40(d.c_str(), d.length()); numAllow++;
      }
    }
    saveAllow();
  }
  k = "\"banned\":[";
  i = rcvBuf.indexOf(k);
  if (i >= 0 && parseJsonStrArray(rcvBuf, i + k.length(), tmp, MAX_BAN, n) >= 0) {
    // Apply directly instead of saveBanned(): a restored IP may have no client
    // entry yet, and saveBanned() rebuilds from clients[] (would drop it).
    numBanned = 0;
    for (int c = 0; c < numClients; c++) clients[c].banned = false;
    File bf = LittleFS.open("/banned.txt", "w");
    for (int j = 0; j < n; j++) {
      IPAddress ip; if (!ip.fromString(tmp[j])) continue;
      bannedIP[numBanned++] = (uint32_t)ip;
      if (bf) bf.println(ip.toString());
      for (int c = 0; c < numClients; c++) if (clients[c].ip == (uint32_t)ip) clients[c].banned = true;
    }
    if (bf) bf.close();
  }
  updateUrl = jsonFindStr(rcvBuf, "upurl", updateUrl);
  updateIntervalH = (uint32_t)jsonFindNum(rcvBuf, "upiv", updateIntervalH);
  String tz = jsonFindStr(rcvBuf, "tz", tzStr); tz.trim();
  if (tz.length() && tz.length() < 32) { tzStr = tz; applyTz(); }
  saveUpdateCfg();
  web.send(200, "text/plain", "ok: custom=" + String(numCustom) + " allow=" + String(numAllow) +
                              " banned=" + String(numBanned) + " tz=" + tzStr);
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The partition holds one list and has no room for a second copy, so the update
// is written to /blocklist.new WHILE the live list stays open and serving; only
// a fully-written, validated file replaces the live one (rename is atomic enough
// for our purposes; the fail-open window is the ~ms between remove and rename).
// A failed/interrupted write leaves the live list untouched; /blocklist.new is
// only promoted at boot if it's valid and the live file is missing.
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
}
// Remember when the live list last swapped successfully (upload or remote
// fetch both funnel through commitNewFile). We store the NTP epoch; the dashboard
// formats it in the viewer's own timezone, so the stamp always matches the clock
// of whoever is looking. Before first sync time() is 1970, so a boot-time
// recovery swap leaves the stamp at 0.
static void markUpdateOk() {
  time_t tt = time(nullptr);
  if (tt > 1600000000) {
    lastUpdEpoch = (uint32_t)tt;
    prefs.begin("stats", false); prefs.putUInt("upTs", lastUpdEpoch); prefs.end();
    Serial.printf("[ota] list updated @ %lu\n", (unsigned long)lastUpdEpoch);
  } else Serial.println("[ota] list updated (NTP not synced yet)");
}
static bool commitNewFile() {                        // validated /blocklist.new -> live
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0; if (f) f.close();
  if (sz == 0 || (sz % HASH_BYTES) != 0) { LittleFS.remove("/blocklist.new"); return false; }
  if (blocklist) blocklist.close();
  numHashes = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  if (!LittleFS.rename("/blocklist.new", BLOCKLIST_PATH)) return false;
  reopenBlocklist();
  markUpdateOk();
  return true;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static String upWhy = "empty upload";
static uint32_t upWritten = 0;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain", upOk ? "ok" : ("rejected: " + upWhy));
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START: {
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; upWritten = 0; upWhy = "empty upload";
      // The new file is written alongside the live one, so it must fit in FREE
      // space. 64 KB margin: LittleFS metadata/CTZ overhead is larger than it looks.
      long cl = web.header("Content-Length").toInt();
      size_t freeNow = LittleFS.totalBytes() - LittleFS.usedBytes();
      Serial.printf("[ota] upload start: cl=%ld free=%u\n", cl, (unsigned)freeNow);
      if (cl > 0 && (size_t)cl + 65536 > freeNow) {
        upWhy = "not enough flash: need " + String(cl / 1024) + " KB, have " + String((unsigned long)(freeNow / 1024)) + " KB";
        Serial.printf("[ota] blocklist upload refused: %s\n", upWhy.c_str());
        break;
      }
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    }
    case UPLOAD_FILE_WRITE:
      esp_task_wdt_reset();
      if (upAuthOk && upFile) upWritten += upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      if (upWritten == u.totalSize) upOk = commitNewFile();
      else {
        if (upWhy == "empty upload") upWhy = "truncated write (out of flash?) — live list untouched";
        LittleFS.remove("/blocklist.new");
      }
      if (!upOk && upWhy == "empty upload") upWhy = "empty or size not a multiple of 5 (not a blocklist.bin?)";
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new");   // live list was never touched
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  String tz = f.readStringUntil('\n'); tz.trim(); if (tz.length()) tzStr = tz;   // optional 3rd line
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.println(tzStr); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();            // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  // Refuse up front when the new file cannot fit in FREE space (the live list
  // stays untouched) — better an honest status than a truncated list. The live
  // list keeps serving during the whole download.
  int len = http.getSize();
  size_t freeNow = LittleFS.totalBytes() - LittleFS.usedBytes();
  if (len > 0 && (size_t)len + 65536 > freeNow) {   // 64 KB margin = LittleFS metadata/CTZ overhead
    http.end();
    updateStatus = "no space: need " + String(len / 1024) + " KB, have " + String((unsigned long)(freeNow / 1024)) + " KB";
    Serial.printf("[remote] %s\n", updateStatus.c_str());
    return false;
  }
  LittleFS.remove("/blocklist.new");
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; return false; }
  WiFiClient* stream = http.getStreamPtr();
  uint8_t b[1024]; size_t total = 0; uint32_t idle = millis(); bool wrFail = false;
  while (http.connected() && (len < 0 || (int)total < len)) {
    esp_task_wdt_reset();                        // download can outlive the WDT window on a slow link
    size_t availN = stream->available();
    if (availN) {
      int n = stream->readBytes(b, availN > sizeof(b) ? sizeof(b) : availN);
      if (n > 0) { if (f.write(b, n) != (size_t)n) { wrFail = true; break; } total += n; idle = millis(); }
    }
    else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  bool ok;
  if (wrFail) { LittleFS.remove("/blocklist.new"); ok = false; }   // live list was never touched
  else ok = commitNewFile();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains")
                    : (wrFail ? "write failed (out of flash?) — live list untouched"
                              : "bad data — live list untouched");
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting");
  { esp_reset_reason_t rr = esp_reset_reason();
    if (rr == ESP_RST_TASK_WDT || rr == ESP_RST_INT_WDT) Serial.println("[boot] watchdog reset (loop was stalled)"); }
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  // Recover from an update that died in the rename window: promote a fully
  // written valid /blocklist.new (legacy fallback: a parked /blocklist.old).
  if (!LittleFS.exists(BLOCKLIST_PATH)) {
    size_t nsz = 0;
    { File tf = LittleFS.open("/blocklist.new", "r"); nsz = tf ? tf.size() : 0; }
    if (nsz > 0 && (nsz % HASH_BYTES) == 0) {
      LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
      Serial.printf("[boot] promoted completed blocklist.new (%u domains)\n", (unsigned)(nsz / HASH_BYTES));
    } else if (LittleFS.exists("/blocklist.old")) {
      LittleFS.rename("/blocklist.old", BLOCKLIST_PATH);
      Serial.println("[boot] restored parked blocklist (legacy)");
    }
  }
  LittleFS.remove("/blocklist.new");   // stale partial from an interrupted update
  LittleFS.remove("/blocklist.old");   // legacy leftover from the park-era firmware
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %u domains\n", numHashes);
    buildFlashIndex();
  }
  loadCustom(); loadAllow(); loadBanned(); loadUpdateCfg();
  prefs.begin("stats", true);                      // daily counters survive reboots
  dayToday = prefs.getUInt("day", 0); blkToday = prefs.getUInt("blk", 0); alwToday = prefs.getUInt("alw", 0);
  dayYest = prefs.getUInt("yday", 0); blkYest = prefs.getUInt("yblk", 0); alwYest = prefs.getUInt("yalw", 0);
  lastUpdEpoch = prefs.getUInt("upTs", 0);
  prefs.end();
  Serial.printf("custom: %d, allow: %d, banned: %d\n", numCustom, numAllow, numBanned);

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
#if CONFIG_IDF_TARGET_ESP32C3
  const int BOOT_PIN = 9;     // C3 BOOT button
#else
  const int BOOT_PIN = 0;     // classic ESP32 BOOT button (GPIO9 is a flash pin there)
#endif
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  // Point our own outbound resolver away from the router: once the router hands
  // the whole LAN (incl. us) 192.168.1.85 as DNS, the board's own lwip lookups
  // would loop back through the router (board -> router -> board -> ...). Public
  // resolvers keep remote auto-update and NTP working in that configuration.
  WiFi.config(INADDR_NONE, INADDR_NONE, INADDR_NONE, IPAddress(8, 8, 8, 8), IPAddress(1, 1, 1, 1));
  configTzTime(tzStr.c_str(), "pool.ntp.org", "time.google.com", "ru.pool.ntp.org");  // sets TZ + starts SNTP in one call
  for (int i = 0; i < 100 && ymdNow() == 0; i++) delay(100);   // up to 10 s for first sync (non-fatal)
  dailyRoll();
  Serial.printf("date: %u tz=%s\n", (unsigned)ymdNow(), tzStr.c_str());
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
  { const char* hdrs[] = { CSRF_HEADER, "Content-Length" }; web.collectHeaders(hdrs, 2); }  // CSRF for requireAuth(), CL for upload space check
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/favicon.svg", []() { web.send_P(200, "image/svg+xml", FAV_SVG); });
  web.on("/stats.json", handleStats);
  web.on("/health", []() {                          // read-only, unauthenticated (like /stats.json) — for Uptime Kuma/HA
    char h[220];
    snprintf(h, sizeof(h),
             "{\"status\":\"ok\",\"uptime_s\":%lu,\"uptime\":%lu,\"blocked_today\":%lu,\"allowed_today\":%lu,\"domains\":%u,\"temp\":%.1f,\"heap\":%u,\"rssi\":%d,\"fs_used\":%u,\"fs_total\":%u,\"blocking\":%s}",
             (unsigned long)(millis() / 1000), (unsigned long)(millis() / 1000), (unsigned long)blkToday,
             (unsigned long)alwToday, numHashes, temperatureRead(), (unsigned)ESP.getFreeHeap(), WiFi.RSSI(),
             (uint32_t)LittleFS.usedBytes(), (uint32_t)LittleFS.totalBytes(), blockingOn ? "true" : "false");
    web.send(200, "application/json", h);
  });
  web.on("/hourly", []() {                          // 24 per-hour query totals for the dashboard sparkline
    String j = "{\"q\":[";
    for (int i = 0; i < 24; i++) { j += (i ? "," : ""); j += String(hq[i]); }
    j += "],\"b\":[";
    for (int i = 0; i < 24; i++) { j += (i ? "," : ""); j += String(hb[i]); }
    j += "],\"last\":" + String(hHour) + "}";
    web.send(200, "application/json", j);
  });
  web.on("/topd.json", []() {                       // top blocked domains today (Space-Saving snapshot)
    TopEnt srt[TOP_K]; int ns = 0;
    for (int i = 0; i < TOP_K; i++) if (top[i].n) srt[ns++] = top[i];
    for (int a = 0; a < ns; a++) for (int b = a + 1; b < ns; b++) if (srt[b].n > srt[a].n) { TopEnt t = srt[a]; srt[a] = srt[b]; srt[b] = t; }
    String j = "{\"t\":[";
    for (int i = 0; i < ns && i < TOP_SHOW; i++) { j += (i ? "," : ""); j += "{\"d\":\"" + jesc(String(srt[i].dom)) + "\",\"n\":" + String(srt[i].n) + "}"; }
    j += "]}";
    web.send(200, "application/json", j);
  });
  web.on("/ban", handleBan);
  web.on("/addblock", []() { if (!requireAuth()) return; addCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { if (!requireAuth()) return; removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/addallow", []() { if (!requireAuth()) return; addAllow(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/delallow", []() { if (!requireAuth()) return; removeAllow(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/qlog.json", []() {                      // recent-query ring (auth: it's a query history)
    if (!requireAuth()) return;
    uint32_t now = millis();
    String j = "{\"total\":" + String(qlogTot) + ",\"entries\":[";
    int n = 0;
    for (int k = 0; k < QLOG_N; k++) {             // oldest -> newest
      int i = (qlogI + k) % QLOG_N;
      if (!qlog[i].dom[0]) continue;
      if (n++) j += ",";
      j += "{\"d\":\"" + jesc(String(qlog[i].dom)) + "\",\"ip\":\"" + IPAddress(qlog[i].ip).toString() +
           "\",\"b\":" + (qlog[i].blocked ? "1" : "0") + ",\"age\":" + (now - qlog[i].t) / 1000 + "}";
    }
    j += "]}";
    web.send(200, "application/json", j);
  });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    if (web.hasArg("tz")) { String t = web.arg("tz"); t.trim(); if (t.length() && t.length() < 32) { tzStr = t; applyTz(); } }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.on("/backup.json", []() {
    if (!requireAuth()) return;
    web.sendHeader("Content-Disposition", "attachment; filename=adblock-backup.json");
    web.send(200, "application/json", backupJson());
  });
  web.on("/restore", HTTP_POST, handleRestoreDone, handleRestoreUpload);
  web.begin();
  esp_task_wdt_init(60, true);   // reboot if loop() stalls 60 s (slow TLS/redirect fetches stay under)
  esp_task_wdt_add(NULL);
  ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  esp_task_wdt_reset();
  static uint32_t lt0 = millis();
  passN++;
  uint32_t lnow = millis();
  if (lnow - lt0 > 1200) Serial.printf("[loop] stall %u ms rssi=%d heap=%u\n", lnow - lt0, WiFi.RSSI(), (unsigned)ESP.getFreeHeap());
  lt0 = lnow;
  static uint32_t lday = 0;
  if (lnow - lday > 5000) { lday = lnow; uint32_t dPrev = dayToday; dailyRoll(); statsFlush(false); if (dayToday != dPrev) { for (int i = 0; i < TOP_K; i++) top[i].n = 0; Serial.println("[top] day rolled - counters reset"); } }
  static uint32_t lhr = 0;
  if (lnow - lhr > 1000) { lhr = lnow; hourRoll(); autoBanTick(); }
  static uint32_t lr = 0;
  if (lnow - lr > 10000) { lr = lnow; int act = 0; for (int i = 0; i < MAX_PENDING; i++) act += pend[i].valid ? 1 : 0;
    Serial.printf("[wifi] rssi=%d active=%d rx=%u idle=%u pass=%u sent=%u txfail=%u done=%u exp=%u unmt=%u replyTx=%u replyFail=%u drop=%u | txq n=%d staged=%u sent=%u giveup=%u qdrop=%u heap=%u big=%u\n",
                  WiFi.RSSI(), act, dnsRx, rxIdle, passN, fwdSent, fwdTxFail, fwdDone, fwdExpired, fwdUnmatched, replyTx, replyTxFail, replyDrop,
                  txCount, txStaged, txSentN, txGiveUp, txDropQ, (unsigned)ESP.getFreeHeap(),
                  (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)); }
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
  if (fwdPoll()) busy = true;
  if (txDrain()) busy = true;
  // NB: pending tx queue alone must NOT suppress the idle sleep — a paused
  // pass is what lets the wifi task drain TX buffers between retry attempts
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
