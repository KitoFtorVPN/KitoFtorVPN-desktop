const { app, BrowserWindow, ipcMain, shell, dialog, Tray, Menu, nativeImage, screen, Notification, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const { execFile, execFileSync, spawn } = require('child_process');
const net = require('net');
const dns = require('dns').promises;
const crypto = require('crypto');
// electron-updater is a runtime dep of the packaged app. In dev (npm start)
// the module may not be installed yet — fail soft so dev still works.
let autoUpdater = null;
try { autoUpdater = require('electron-updater').autoUpdater; } catch(e) {}

// Secret storage.
//
// Secrets (the session token and the WireGuard config, which contains the
// private key) are encrypted with Electron's built-in safeStorage, which on
// Windows is DPAPI scoped to the current user account — the same protection
// keytar's Credential Manager entries had.
//
// This replaces keytar, which was a native module: it had to be rebuilt for
// every Electron ABI, and the `try { require } catch {}` around it meant a
// failed rebuild would degrade to plaintext-on-disk *silently*. It also
// replaces the old dpapi-encrypt/-decrypt round trip through
// kitoftor-tunnel.exe, which spawned a process for every read and write.
// Microsoft archived keytar in 2023; there will be no further releases.
//
// keytar is still loaded here, but only to migrate existing users' secrets
// out of Credential Manager on first launch after the update — without it
// everyone would be silently logged out. It can be dropped from
// package.json one release from now.
let keytar = null;
try { keytar = require('keytar'); } catch(e) {}

const KEYTAR_SERVICE = 'fun.kitoftorvpn.desktop';
const KEYTAR_TOKEN_ACCOUNT = 'session_token';
const KEYTAR_CONFIG_ACCOUNT = 'wireguard_config';

// Reading and writing a safeStorage-encrypted file. Values are stored
// base64-encoded so the files stay plain text, same as before.
function secretWrite(file, plaintext) {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('safeStorage unavailable');
  }
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const enc = safeStorage.encryptString(String(plaintext));
  fs.writeFileSync(file, enc.toString('base64'), 'utf-8');
}

function secretRead(file) {
  if (!fs.existsSync(file)) return null;
  const raw = fs.readFileSync(file, 'utf-8').trim();
  if (!raw) return null;
  try {
    return safeStorage.decryptString(Buffer.from(raw, 'base64')) || null;
  } catch(e) {
    // Written by an older version through the tunnel's DPAPI helper, or
    // corrupted. The caller falls back to the legacy path.
    return null;
  }
}

function secretDelete(file) {
  try { fs.unlinkSync(file); } catch(e) {}
}

// One-shot migration of a keytar entry into a safeStorage file.
async function migrateFromKeytar(account, file) {
  if (!keytar) return null;
  try {
    const val = await keytar.getPassword(KEYTAR_SERVICE, account);
    if (!val) return null;
    secretWrite(file, val);
    keytar.deletePassword(KEYTAR_SERVICE, account).catch(() => {});
    return val;
  } catch(e) {
    console.error('migrateFromKeytar error:', e);
    return null;
  }
}

const API_BASE = 'https://my.kitoftorvpn.fun';
const TUNNEL_EXE = app.isPackaged
  ? path.join(process.resourcesPath, 'bin', 'kitoftor-tunnel.exe')
  : path.join(__dirname, 'bin', 'kitoftor-tunnel.exe');
const DATA_DIR = app.getPath('userData');
const TOKEN_FILE = path.join(DATA_DIR, 'session.dat');
const CONFIG_FILE = path.join(DATA_DIR, 'config.dat');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const CONNECT_TIME_FILE = path.join(DATA_DIR, 'connect_time.dat');
const GUEST_FILE = path.join(DATA_DIR, 'guest_mode.dat');
const BYPASS_CACHE_FILE = path.join(DATA_DIR, 'bypass_cache.json');
const TASK_NAME = 'KitoFtorVPNAutostart';

// Notifications are unconditional. They used to be suppressed whenever the
// main window happened to be visible, which sounds reasonable until you pair
// it with autostart: the app launches, the window is on screen, the tunnel
// comes up — and the one notification confirming it is swallowed precisely in
// the situation where the user is least likely to be watching the window.
function showNotification(title, body) {
  if (!Notification.isSupported()) return;
  const icon = (typeof APP_ICON !== 'undefined') ? APP_ICON : undefined;
  new Notification({ title, body, icon, silent: true }).show();
}

// Required for Windows toast notifications to work (both dev and packaged).
app.setAppUserModelId('fun.kitoftorvpn.desktop');

// ─── Guaranteed teardown on system shutdown/restart ──────
//
// Windows-only app, so there is exactly one thing to get right here.
//
// before-quit (further down) is not enough on its own: when Windows itself
// is shutting down, the app doesn't get the usual leisurely quit sequence
// — it gets a short grace period and is then killed. If teardown hadn't
// finished by then, the tunnel and its routes were left running, which is
// the whole bug this fixes.
//
// The one notification Windows gives us is app's 'session-end'. It cannot
// be cancelled or delayed, and — crucially — nothing async started inside
// it will ever be awaited: Windows tears the process down without
// servicing the event loop again. So that path has to be synchronous.
//
// (For the record, since this cost us a startup crash once: neither
// powerMonitor.setShutdownHandler() nor the powerMonitor 'shutdown' event
// exists on Windows — both are macOS/Linux-only. setShutdownHandler is
// literally undefined here, hence the old "is not a function" on launch.
// Don't reintroduce either of them.)
//
// Two teardown paths, one shared guard flag so they can't both run:
//   • stopTunnelOnExit()     — async, for normal quits (tray "Выход",
//                              Alt+F4), where we can take our time.
//   • stopTunnelOnExitSync() — blocking, for session-end.
// Both end in the same two tunnel commands so they can't drift apart.
let tunnelStopped = false;
let sessionEnding = false;

async function stopTunnelOnExit() {
  if (tunnelStopped) return;
  tunnelStopped = true;
  stopBypassRefresh();
  // Hard cap: if the tunnel exe is somehow stuck (antivirus scanning it,
  // disk thrashing, whatever) we must not hang forever waiting on it.
  // Better to bail and let the next boot's stale-marker cleanup
  // (kitoftor-tunnel service, see hadUncleanPriorRun) finish the job.
  await Promise.race([
    (async () => {
      try { await tunnelExec('stop'); } catch (e) {}
      try { await tunnelExec('service-stop'); } catch (e) {}
    })(),
    new Promise((resolve) => setTimeout(resolve, 4000)),
  ]);
  deleteConnectTime();
}

// Blocking twin of the above, for 'session-end' only. execFileSync holds
// the main thread until the tunnel is actually down — the only way to
// guarantee teardown on a path where the event loop won't run again.
// Same 4s-per-command cap, same reasoning: Windows' patience is finite,
// and a hung shutdown is worse than a stale marker.
function stopTunnelOnExitSync() {
  if (tunnelStopped) return;
  tunnelStopped = true;
  stopBypassRefresh();
  const opts = { timeout: 4000, windowsHide: true, stdio: 'ignore' };
  try { execFileSync(TUNNEL_EXE, ['stop'], opts); } catch (e) {}
  try { execFileSync(TUNNEL_EXE, ['service-stop'], opts); } catch (e) {}
  try { deleteConnectTime(); } catch (e) {}
}

// Called from app.whenReady() further down rather than at module
// top-level, so the app is fully initialised before we attach to it.
function registerShutdownHandler() {
  app.on('session-end', () => {
    sessionEnding = true;
    stopTunnelOnExitSync();
    app.exit(0);
  });
}

// Prevent multiple instances
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) { app.quit(); }

let mainWindow = null;
let settingsWindow = null;
let whitelistWindow = null;
let tray = null;
let authServer = null;
let authPort = 0;
let cachedToken = null;
let isGuest = false;
let isQuitting = false;
// Set when the user lands back on the login screen (logout, guest exit, or a
// session the server rejected) so a queued autoconnect doesn't fire behind it.
let autoconnectCancelled = false;

// ─── Settings ────────────────────────────────────────────

function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      const loaded = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf-8'));
      return {
        autostart: false, autoconnect: false, startMinimized: false, whitelist: [],
        updateSkipPrompt: false, updatePendingVersion: null,
        ...loaded,
      };
    }
  } catch(e) {}
  return { autostart: false, autoconnect: false, startMinimized: false, whitelist: [], updateSkipPrompt: false, updatePendingVersion: null };
}

function saveSettings(settings) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf-8');
  } catch(e) {
    console.error('saveSettings error:', e);
  }
}

// ─── Whitelist (split tunneling via bypass routes) ────────
//
// How this works now, and why it changed.
//
// Before: the whitelist was resolved to IPs, each IP was widened to its /24,
// and those blocks were *subtracted* from the peer's "AllowedIPs = 0.0.0.0/0"
// before the config was handed to the tunnel. Three problems came out of that,
// and they were the reason whitelisted sites still went through the VPN:
//
//   1. AllowedIPs is only read when the WireGuard device is created, so every
//      whitelist edit meant a full disconnect/reconnect — and nothing could be
//      corrected while a connection was live.
//   2. Carving N holes out of 0.0.0.0/0 needs roughly 24 CIDRs per hole. A
//      list of 30 domains became 600+ routes. That is what made connecting
//      slow enough to need fixing in the first place.
//   3. Worst of all, the addresses were resolved *before* connecting, using
//      the ISP's resolver, while the browser afterwards resolves through the
//      tunnel's DNS (1.1.1.1) and gets entirely different addresses back for
//      anything on a CDN. The list was carving holes at addresses the browser
//      never visited.
//
// Now: the config is passed through untouched (AllowedIPs stays 0.0.0.0/0,
// i.e. two routes) and the whitelist is sent separately to the tunnel service
// as a list of addresses to route around it. Since that list can be updated on
// a live tunnel, resolution happens *after* connecting, through the same DNS
// the browser will use, and is refreshed on a timer so addresses that rotate
// get picked up without the user noticing anything.

const RESOLVE_TIMEOUT_MS = 3000;
// How often the whitelist is re-resolved while connected. CDN records rotate
// on the order of minutes, so a minute keeps up without being noisy.
const BYPASS_REFRESH_MS = 60 * 1000;
// An address stays routed around the tunnel for this long after it was last
// seen in a DNS answer. Without a grace period, a large site that answers
// with a rotating subset of its pool each time would have addresses added and
// pulled from under open connections every refresh.
const BYPASS_IP_TTL_MS = 30 * 60 * 1000;
// Hard ceiling on installed bypass routes, so a pathological list (or a
// domain fronted by a very large pool) can't grow the routing table without
// bound. Oldest entries are dropped first.
const BYPASS_MAX_IPS = 4000;

// entry -> { ips: Set<string>, at: number }
const _resolveCache = new Map();
// ip -> last time it appeared in an answer. This is the authoritative set of
// what should be bypassed; it is persisted so a reconnect can install the
// previous session's addresses immediately instead of leaving whitelisted
// sites going through the tunnel until the first resolve completes.
const _bypassIPs = new Map();

let bypassTimer = null;

// Cleans a whitelist entry: strips protocol, path, port — returns bare domain or IP.
function cleanWhitelistEntry(raw) {
  let entry = (raw || '').trim();
  if (!entry || entry.startsWith('#')) return null;
  for (const prefix of ['https://', 'http://', 'ftp://']) {
    if (entry.toLowerCase().startsWith(prefix)) {
      entry = entry.slice(prefix.length);
      break;
    }
  }
  entry = entry.split('/')[0].split('?')[0].split('#')[0];
  // Strip a trailing port. Only meaningful for hostnames and IPv4 here;
  // bracketed IPv6 is left alone (and rejected further down anyway, since the
  // tunnel blocks IPv6 outright rather than routing it).
  if (entry.includes(':') && !entry.startsWith('[')) {
    entry = entry.split(':')[0];
  }
  entry = entry.trim().replace(/\.$/, '').toLowerCase();
  return entry || null;
}

// Returns true if the string looks like a plain IPv4 address or CIDR.
function isIpOrCidr(s) {
  return /^[\d./]+$/.test(s);
}

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms)),
  ]);
}

// Reads the DNS servers out of the stored config, so the whitelist can be
// resolved through exactly the resolver the rest of the system is using once
// the tunnel is up. This is the piece that makes the whitelist match reality:
// asking a different resolver than the browser does gives different addresses
// for anything CDN-hosted, and then the bypass routes cover addresses nobody
// ever connects to.
function extractDnsServers(confText) {
  const out = [];
  const re = /^\s*DNS\s*=\s*(.+)$/gim;
  let m;
  while ((m = re.exec(confText || '')) !== null) {
    for (const part of m[1].split(',')) {
      const v = part.trim();
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) out.push(v);
    }
  }
  return out;
}

let _tunnelResolver = null;
let _tunnelResolverServers = '';

function tunnelResolver(servers) {
  if (!servers || servers.length === 0) return null;
  const key = servers.join(',');
  if (_tunnelResolver && _tunnelResolverServers === key) return _tunnelResolver;
  try {
    const r = new dns.Resolver({ timeout: RESOLVE_TIMEOUT_MS, tries: 1 });
    r.setServers(servers);
    _tunnelResolver = r;
    _tunnelResolverServers = key;
    return r;
  } catch(e) {
    return null;
  }
}

// Resolves one hostname, asking both the VPN's own DNS servers and the system
// resolver and merging the answers. Two resolvers rather than one because
// which of them the browser ends up using depends on things outside this app
// (DNS-over-HTTPS in the browser, Windows' own multi-adapter resolution
// order); covering both means the bypass list holds whichever answer the
// browser acts on.
async function resolveOne(name, resolver) {
  const found = new Set();
  const attempts = [];

  if (resolver) {
    attempts.push(withTimeout(resolver.resolve4(name), RESOLVE_TIMEOUT_MS).catch(() => []));
  }
  attempts.push(withTimeout(dns.resolve4(name), RESOLVE_TIMEOUT_MS).catch(() => []));
  attempts.push(
    withTimeout(dns.lookup(name, { all: true, family: 4 }), RESOLVE_TIMEOUT_MS)
      .then(rs => rs.map(r => r.address))
      .catch(() => [])
  );

  const results = await Promise.all(attempts);
  for (const list of results) {
    for (const ip of list || []) {
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) found.add(ip);
    }
  }
  return found;
}

// Expands a user's entry into the names actually worth resolving. Someone who
// types "sberbank.ru" means the site, and the site is very often served from
// "www.sberbank.ru" with a different address — leaving that out is a large
// share of "I added it to the list and it still goes through the VPN".
function expandHostVariants(entry) {
  const names = [entry];
  const labels = entry.split('.');
  if (labels.length === 2) {
    names.push('www.' + entry);
  } else if (labels[0] === 'www' && labels.length === 3) {
    names.push(labels.slice(1).join('.'));
  }
  return names;
}

// Resolves the whole whitelist and folds the result into _bypassIPs.
// Literal addresses and CIDRs are passed through as written.
async function refreshBypassSet(entries, dnsServers) {
  const now = Date.now();
  const literals = [];
  const hosts = new Set();

  for (const raw of entries || []) {
    const entry = cleanWhitelistEntry(raw);
    if (!entry) continue;
    if (isIpOrCidr(entry)) {
      literals.push(entry);
      continue;
    }
    for (const name of expandHostVariants(entry)) hosts.add(name);
  }

  const resolver = tunnelResolver(dnsServers);
  const names = [...hosts];
  const results = await Promise.all(names.map(async (name) => {
    const cached = _resolveCache.get(name);
    // A short cache only exists to avoid hammering the resolver when several
    // things trigger a refresh at once; it is far shorter than the refresh
    // interval so it never masks a genuine address change.
    if (cached && (now - cached.at) < 15000) return cached.ips;
    const ips = await resolveOne(name, resolver);
    _resolveCache.set(name, { ips, at: now });
    return ips;
  }));

  for (const ips of results) {
    for (const ip of ips) _bypassIPs.set(ip, now);
  }
  for (const lit of literals) _bypassIPs.set(lit, now);

  // Drop addresses nothing has resolved to in a long while.
  for (const [ip, seen] of _bypassIPs) {
    if (now - seen > BYPASS_IP_TTL_MS) _bypassIPs.delete(ip);
  }
  // And trim the oldest if the list somehow still ran away.
  if (_bypassIPs.size > BYPASS_MAX_IPS) {
    const ordered = [..._bypassIPs.entries()].sort((a, b) => a[1] - b[1]);
    for (let i = 0; i < ordered.length - BYPASS_MAX_IPS; i++) {
      _bypassIPs.delete(ordered[i][0]);
    }
  }

  saveBypassCache();
  return [..._bypassIPs.keys()];
}

// The resolved set survives restarts purely so that the moment a tunnel comes
// up, last session's addresses can be pushed to it straight away. Whitelisted
// sites are then bypassed from the first second rather than from whenever the
// first DNS round completes.
function saveBypassCache() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(BYPASS_CACHE_FILE, JSON.stringify([..._bypassIPs.entries()]), 'utf-8');
  } catch(e) {}
}

function loadBypassCache() {
  try {
    if (!fs.existsSync(BYPASS_CACHE_FILE)) return;
    const parsed = JSON.parse(fs.readFileSync(BYPASS_CACHE_FILE, 'utf-8'));
    if (!Array.isArray(parsed)) return;
    const now = Date.now();
    for (const pair of parsed) {
      if (!Array.isArray(pair) || pair.length !== 2) continue;
      const [ip, seen] = pair;
      if (typeof ip !== 'string' || typeof seen !== 'number') continue;
      if (now - seen > BYPASS_IP_TTL_MS) continue;
      _bypassIPs.set(ip, seen);
    }
  } catch(e) {}
}

// Removes from the bypass set exactly the addresses that belonged to entries
// the user just deleted, leaving everything else installed and untouched.
//
// The address -> entry link comes from _resolveCache. If it isn't there (the
// app was restarted since the last resolve, so nothing was cached) there is no
// way to tell which addresses belonged to what, and the old blunt behaviour is
// the only correct fallback: drop everything and let the immediate re-resolve
// rebuild the set.
function dropRemovedFromBypass(previous, current) {
  const kept = new Set();
  for (const raw of current || []) {
    const e = cleanWhitelistEntry(raw);
    if (e) kept.add(e);
  }

  const goneNames = [];
  const goneLiterals = [];
  for (const raw of previous || []) {
    const e = cleanWhitelistEntry(raw);
    if (!e || kept.has(e)) continue;
    if (isIpOrCidr(e)) goneLiterals.push(e);
    else goneNames.push(...expandHostVariants(e));
  }

  if (goneNames.length === 0 && goneLiterals.length === 0) return;

  for (const name of goneNames) {
    const cached = _resolveCache.get(name);
    if (!cached) {
      // Unknown addresses for a removed domain — can't be surgical.
      _resolveCache.clear();
      _bypassIPs.clear();
      return;
    }
    for (const ip of cached.ips || []) _bypassIPs.delete(ip);
    _resolveCache.delete(name);
  }
  for (const lit of goneLiterals) _bypassIPs.delete(lit);
}

// Hands the current list to the tunnel service, which installs the routes.
// An empty list is still worth sending — that is how routes get removed after
// the user clears the whitelist.
async function pushBypassToTunnel(ips) {
  try {
    await tunnelBypassStdin((ips || []).join('\n'));
  } catch(e) {
    console.error('pushBypassToTunnel error:', e.message);
  }
}

// Resolve + push, in that order. Called right after connecting and then on a
// timer, and directly whenever the user edits the list.
async function applyWhitelistNow() {
  const settings = loadSettings();
  const entries = Array.isArray(settings.whitelist) ? settings.whitelist : [];
  if (entries.length === 0) {
    _bypassIPs.clear();
    saveBypassCache();
    await pushBypassToTunnel([]);
    return 0;
  }
  let dnsServers = [];
  try {
    const conf = await loadConfig();
    dnsServers = extractDnsServers(conf);
  } catch(e) {}
  const ips = await refreshBypassSet(entries, dnsServers);
  await pushBypassToTunnel(ips);
  return ips.length;
}

// Starts the refresh loop and does the immediate first pass. The cached set is
// pushed synchronously first so there is no window where the whitelist isn't
// in effect yet.
function startBypassRefresh() {
  stopBypassRefresh();
  const settings = loadSettings();
  const entries = Array.isArray(settings.whitelist) ? settings.whitelist : [];
  if (entries.length === 0) return;

  // Cached addresses first, then the fresh resolve — chained rather than
  // fired together, so two bypass updates never contend for the service's
  // single control channel at the moment the tunnel has just come up.
  (async () => {
    if (_bypassIPs.size > 0) {
      await pushBypassToTunnel([..._bypassIPs.keys()]);
    }
    await applyWhitelistNow();
  })().catch(e => console.error('bypass first pass:', e));

  bypassTimer = setInterval(() => {
    applyWhitelistNow().catch(e => console.error('bypass refresh:', e));
  }, BYPASS_REFRESH_MS);
}

function stopBypassRefresh() {
  if (bypassTimer) { clearInterval(bypassTimer); bypassTimer = null; }
}

// ─── Autostart (Registry) ────────────────────────────────

// Builds the Task Scheduler job as a full XML definition rather than the
// shorthand schtasks /Create /TR ... form.
//
// The shorthand works, but every setting it doesn't mention is filled in by
// Windows with a default, and two of those defaults are actively wrong for a
// VPN client that lives in the tray:
//
//   • DisallowStartIfOnBatteries / StopIfGoingOnBatteries default to true. On
//     a laptop that means autostart simply doesn't happen unless the machine
//     is plugged in at logon — and that the app gets stopped the moment it's
//     unplugged. Nobody expects their VPN to switch off when they pick up
//     their laptop.
//   • ExecutionTimeLimit defaults to three days, after which the scheduler
//     terminates the task. For anything that runs continuously that's a
//     process being killed on a timer, with no message and no obvious cause —
//     on a machine that isn't rebooted, the VPN would vanish every third day.
//
// PT0S is the scheduler's way of saying "no time limit".
function buildAutostartXml(exePath, hidden) {
  const esc = (v) => String(v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const user = process.env.USERDOMAIN
    ? `${process.env.USERDOMAIN}\\${process.env.USERNAME}`
    : (process.env.USERNAME || '');
  const args = hidden ? '\n      <Arguments>--hidden</Arguments>' : '';
  // Element order inside <Settings> is fixed by the task schema — the
  // scheduler rejects the file outright if they're rearranged.
  return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>KitoFtorVPN</Author>
    <Description>Автозапуск KitoFtorVPN при входе в Windows</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>${esc(user)}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>${esc(user)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <WakeToRun>false</WakeToRun>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>${esc(exePath)}</Command>${args}
    </Exec>
  </Actions>
</Task>
`;
}

function setAutostart(enabled, hidden) {
  const exePath = process.execPath;
  const { execFileSync } = require('child_process');
  try {
    // Delete first either way: /Create /F would overwrite, but removing it
    // unconditionally keeps the disable path and the rewrite path identical.
    try { execFileSync('schtasks', ['/Delete', '/TN', TASK_NAME, '/F'], { stdio: 'pipe' }); } catch(e) {}
    if (!enabled) return;

    // Task Scheduler rather than HKCU\Run because the app runs elevated
    // (requestedExecutionLevel in package.json), and a Run key entry cannot
    // raise UAC — it would fail silently at every logon.
    const xmlPath = path.join(app.getPath('temp'), 'kitoftorvpn-autostart.xml');
    // The scheduler expects the file in UTF-16, matching the declaration in
    // the header above.
    fs.writeFileSync(xmlPath, '\ufeff' + buildAutostartXml(exePath, hidden), 'utf16le');
    try {
      execFileSync('schtasks', ['/Create', '/TN', TASK_NAME, '/XML', xmlPath, '/F'], { stdio: 'pipe' });
    } finally {
      try { fs.unlinkSync(xmlPath); } catch(e) {}
    }
  } catch(e) {
    console.error('setAutostart error:', e);
    // If the scheduler refused the XML for any reason, fall back to the
    // shorthand form. Its defaults are worse, but an autostart with bad
    // defaults beats no autostart at all.
    if (enabled) {
      try {
        execFileSync('schtasks', [
          '/Create', '/TN', TASK_NAME,
          '/TR', hidden ? `"${exePath}" --hidden` : `"${exePath}"`,
          '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/F',
        ], { stdio: 'pipe' });
      } catch(e2) {
        console.error('setAutostart fallback error:', e2);
      }
    }
  }
}

let _autostartCache = null;

// Returns { enabled, hidden, current }. Reading the registered task as XML,
// rather than just checking that it exists, is what lets the startup re-sync
// notice two kinds of drift: the "запускать свёрнутым" setting changed but the
// task still carries the old command line, and — via `current` — the task was
// registered by an older build that left Windows' battery and run-time-limit
// defaults in place. Either way it gets rewritten.
function getAutostartState() {
  if (_autostartCache !== null) return _autostartCache;
  try {
    const { execFileSync } = require('child_process');
    const xml = String(execFileSync('schtasks', ['/Query', '/TN', TASK_NAME, '/XML', 'ONE'], {
      stdio: 'pipe', encoding: 'utf16le',
    }));
    _autostartCache = {
      enabled: true,
      hidden: /--hidden/.test(xml),
      current: /<DisallowStartIfOnBatteries>false</.test(xml)
        && /<ExecutionTimeLimit>PT0S</.test(xml),
    };
  } catch(e) {
    _autostartCache = { enabled: false, hidden: false, current: false };
  }
  return _autostartCache;
}

function getAutostartEnabled() {
  return getAutostartState().enabled;
}

// ─── DPAPI via Go helper ─────────────────────────────────

// Only dpapiDecrypt remains: it is needed to read secrets written by
// versions before safeStorage, and nothing writes in that format anymore.
function dpapiDecrypt(base64data) {
  return new Promise((resolve, reject) => {
    const child = spawn(TUNNEL_EXE, ['dpapi-decrypt']);
    let out = '', err = '';
    child.stdout.on('data', (d) => out += d);
    child.stderr.on('data', (d) => err += d);
    child.on('close', (code) => {
      if (code === 0) resolve(out);
      else reject(new Error(err || 'dpapi-decrypt failed'));
    });
    child.stdin.write(base64data);
    child.stdin.end();
  });
}

// ─── Token storage (DPAPI) ───────────────────────────────

async function saveToken(token) {
  try {
    secretWrite(TOKEN_FILE, token);
  } catch(e) {
    console.error('saveToken error:', e);
  }
}

async function loadToken() {
  try {
    // Current format.
    const val = secretRead(TOKEN_FILE);
    if (val) return val;

    // Legacy 1: keytar / Credential Manager.
    const migrated = await migrateFromKeytar(KEYTAR_TOKEN_ACCOUNT, TOKEN_FILE);
    if (migrated) return migrated;

    // Legacy 2: DPAPI blob written by the tunnel helper. Re-encrypt with
    // safeStorage so this path is only ever taken once.
    if (fs.existsSync(TOKEN_FILE)) {
      const encrypted = fs.readFileSync(TOKEN_FILE, 'utf-8').trim();
      if (encrypted) {
        const plain = await dpapiDecrypt(encrypted).catch(() => null);
        if (plain) {
          try { secretWrite(TOKEN_FILE, plain); } catch(e) {}
          return plain;
        }
      }
    }
    return null;
  } catch(e) {
    console.error('loadToken error:', e);
    return null;
  }
}

function deleteToken() {
  if (keytar) {
    keytar.deletePassword(KEYTAR_SERVICE, KEYTAR_TOKEN_ACCOUNT).catch(() => {});
  }
  secretDelete(TOKEN_FILE);
}

// ─── Config storage (DPAPI) ──────────────────────────────

async function saveConfig(confText) {
  try {
    secretWrite(CONFIG_FILE, confText);
    return true;
  } catch(e) {
    console.error('saveConfig error:', e);
    return false;
  }
}

async function loadConfig() {
  try {
    const val = secretRead(CONFIG_FILE);
    if (val) return val;

    // Legacy 1: keytar / Credential Manager.
    const migrated = await migrateFromKeytar(KEYTAR_CONFIG_ACCOUNT, CONFIG_FILE);
    if (migrated) return migrated;

    // Legacy 2: DPAPI blob written by the tunnel helper.
    if (fs.existsSync(CONFIG_FILE)) {
      const encrypted = fs.readFileSync(CONFIG_FILE, 'utf-8').trim();
      if (encrypted) {
        const plain = await dpapiDecrypt(encrypted).catch(() => null);
        if (plain) {
          try { secretWrite(CONFIG_FILE, plain); } catch(e) {}
          return plain;
        }
      }
    }
    return null;
  } catch(e) {
    console.error('loadConfig error:', e);
    return null;
  }
}

// Now that the config lives in a file again rather than in Credential
// Manager, "is there a config?" is a plain file check — no async call, no
// _keytarConfigCached flag that four different places had to remember to
// keep in sync.
function hasConfig() {
  try { return fs.existsSync(CONFIG_FILE); } catch(e) { return false; }
}

function deleteConfigFile() {
  if (keytar) {
    keytar.deletePassword(KEYTAR_SERVICE, KEYTAR_CONFIG_ACCOUNT).catch(() => {});
  }
  secretDelete(CONFIG_FILE);
}

// ─── Tray ────────────────────────────────────────────────

let vpnStateForTray = 'off'; // tracked for tray icon/menu updates

// Icon files live in `build/` for packaged app and dev alike.
// In packaged app, __dirname points inside app.asar; extraResources unpack to process.resourcesPath.
const ICON_DIR = app.isPackaged
  ? path.join(process.resourcesPath, 'build')
  : path.join(__dirname, 'build');

const TRAY_ICON_ON  = path.join(ICON_DIR, 'tray-on.ico');
const TRAY_ICON_OFF = path.join(ICON_DIR, 'tray-off.ico');
const APP_ICON      = path.join(ICON_DIR, 'icon.ico');

function createTrayIcon(state) {
  // 'on' — connected; 'off' and 'connecting' share the disconnected icon
  // (connecting state is signalled via tooltip/menu label, not a separate .ico).
  const file = state === 'on' ? TRAY_ICON_ON : TRAY_ICON_OFF;
  try {
    const img = nativeImage.createFromPath(file);
    if (!img.isEmpty()) return img;
  } catch(e) {}
  // Fallback: if .ico files are missing, generate a minimal SVG icon so
  // the app doesn't crash on startup.
  const color = state === 'on' ? '#10b981' : '#475569';
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6" fill="${color}"/></svg>`;
  return nativeImage.createFromBuffer(Buffer.from(svg), { width: 16, height: 16 });
}

function updateTrayMenu() {
  if (!tray) return;

  const isOn = vpnStateForTray === 'on';
  const isConnecting = vpnStateForTray === 'connecting';
  const statusLabel = isOn ? 'Подключено' : isConnecting ? 'Подключение...' : 'Отключено';

  const contextMenu = Menu.buildFromTemplate([
    { label: 'KitoFtorVPN', enabled: false },
    { type: 'separator' },
    { label: statusLabel, enabled: false },
    {
      label: isOn ? 'Отключиться' : 'Подключиться',
      // Connecting from the tray used to skip the subscription check the main
      // window applies, so an expired subscription could still be connected
      // from here. Same gate on both paths now.
      enabled: !isConnecting && (isOn || canConnectNow()),
      click: async () => {
        if (isOn) {
          updateTrayIcon('connecting');
          if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('vpn:autoconnecting', { reason: 'disconnecting' });
          try { await disconnectVpn(); } catch(e) { updateTrayIcon('off'); }
          showNotification('KitoFtorVPN', 'VPN отключён');
          if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('vpn:autoconnected', { ok: false });
        } else {
          updateTrayIcon('connecting');
          if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('vpn:autoconnecting');
          try {
            await connectVpn();
            showNotification('KitoFtorVPN', 'VPN подключён');
            if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('vpn:autoconnected', { ok: true });
          } catch(e) {
            updateTrayIcon('off');
            showNotification('KitoFtorVPN', friendlyTunnelError(e.message));
            if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('vpn:autoconnected', { ok: false, error: friendlyTunnelError(e.message) });
          }
        }
      }
    },
    { type: 'separator' },
    { label: 'Открыть', click: () => showMainWindow() },
    { label: 'Настройки', click: () => openSettings() },
    { type: 'separator' },
    { label: 'Выход', click: () => quitApp() }
  ]);

  tray.setContextMenu(contextMenu);
  tray.setToolTip(`KitoFtorVPN — ${statusLabel}`);
}

function updateTrayIcon(state) {
  vpnStateForTray = state;
  if (!tray) return;
  try {
    const icon = createTrayIcon(state);
    tray.setImage(icon);
  } catch(e) {}
  updateTrayMenu();
}

function showMainWindow() {
  if (mainWindow) {
    mainWindow.show();
    mainWindow.focus();
  }
}

async function quitApp() {
  isQuitting = true;
  stopBypassRefresh();
  // Stop the VPN tunnel first — tears down routes/adapter cleanly.
  try {
    await tunnelExec('stop');
  } catch(e) {
    // Ignore — either tunnel wasn't running or already stopped.
  }
  // Then stop the persistent background Windows service itself. Normal
  // connect/disconnect leaves this service running on purpose (that's what
  // makes the next "Подключиться" instant), but a full app exit via tray
  // "Выход" should leave nothing behind in Task Manager / Services.
  try {
    await tunnelExec('service-stop');
  } catch(e) {
    console.error('quitApp: service-stop failed:', e.message);
  }
  deleteConnectTime();
  if (tray) { tray.destroy(); tray = null; }
  app.quit();
}

// ─── Window ──────────────────────────────────────────────

const LOGIN_SIZE = { width: 310, height: 520 };
const MAIN_SIZE = { width: 310, height: 500 };

function resizeWindowFor(page) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const size = page === 'login' ? LOGIN_SIZE : MAIN_SIZE;
  const bounds = mainWindow.getBounds();
  const centerX = bounds.x + Math.round(bounds.width / 2);
  const centerY = bounds.y + Math.round(bounds.height / 2);
  mainWindow.setBounds({
    x: centerX - Math.round(size.width / 2),
    y: centerY - Math.round(size.height / 2),
    width: size.width,
    height: size.height,
  }, true);
}

async function createWindow() {
  const startHidden = process.argv.includes('--hidden');

  // Pre-decide which page so we can size the window correctly from the start.
  cachedToken = await loadToken();
  isGuest = !cachedToken && loadGuestMode();
  const startsOnMain = !!cachedToken || isGuest;
  const size = startsOnMain ? MAIN_SIZE : LOGIN_SIZE;

  mainWindow = new BrowserWindow({
    width: size.width,
    height: size.height,
    resizable: false,
    frame: false,
    transparent: false,
    backgroundColor: '#0b1120',
    show: !startHidden,
    icon: APP_ICON,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  // X button minimizes to tray instead of closing
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      // Close child windows before hiding to tray.
      if (whitelistWindow && !whitelistWindow.isDestroyed()) { whitelistWindow.destroy(); whitelistWindow = null; }
      if (settingsWindow && !settingsWindow.isDestroyed()) { settingsWindow.destroy(); settingsWindow = null; }
      mainWindow.hide();
    }
  });

  // Create tray
  const trayIcon = createTrayIcon('off');
  tray = new Tray(trayIcon);
  tray.on('click', () => showMainWindow());
  updateTrayMenu();

  // Load page
  if (startsOnMain) {
    mainWindow.loadFile('ui/main.html');
  } else {
    mainWindow.loadFile('ui/login.html');
  }

  const settings = loadSettings();

  // Auto-connect. Everything that decides whether that is allowed lives in
  // runAutoconnect() — see the note there.
  if (settings.autoconnect && (cachedToken || isGuest)) {
    // Tell the renderer we intend to connect as soon as it can show it, so
    // the window doesn't sit on "Не подключено" while we check.
    mainWindow.webContents.once('did-finish-load', () => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('vpn:autoconnecting');
      }
    });
    setTimeout(() => { runAutoconnect().catch(e => console.error('autoconnect:', e)); }, 2000);
  }
}

// ─── Subscription gate ───────────────────────────────────
//
// The main window has always known whether the subscription is active — it
// fetches /api/sub to draw the status card. The main process didn't, which is
// why two things could connect regardless of it: autoconnect at startup, and
// the tray's "Подключиться". Both are here now, and both consult the same
// answer the window shows.
//
// 'unknown' is a distinct outcome from 'expired' on purpose: it means the
// server couldn't be reached, not that the subscription is bad.
let subStatus = 'unknown'; // 'active' | 'expired' | 'none' | 'test_ended' | 'unknown'

// The window reports every /api/sub result it gets, so the tray stays correct
// as the subscription changes during a session (including expiring while the
// app is open).
ipcMain.handle('sub:report', (event, status) => {
  if (typeof status === 'string' && status) subStatus = status;
  updateTrayMenu();
  return { ok: true };
});

// A guest has no account and therefore no subscription to check — that's the
// whole point of guest mode, and it's how a manually issued config is used.
function canConnectNow() {
  if (!hasConfig()) return false;
  if (isGuest) return true;
  return subStatus === 'active';
}

// Raw GET against the API with the session cookie. Same request the renderer
// makes through api:fetch, available to the main process.
function apiGet(endpoint) {
  return new Promise((resolve) => {
    if (!cachedToken) return resolve({ error: 'no_token' });
    const url = buildApiUrl(endpoint);
    if (!url) return resolve({ error: 'bad_endpoint' });
    const req = https.get(url, { headers: { 'Cookie': `cabinet_session=${cachedToken}` } }, (res) => {
      let data = '';
      res.on('data', (c) => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { resolve({ error: res.statusCode === 401 ? 'unauthorized' : 'parse_error' }); }
      });
    });
    req.on('error', (e) => resolve({ error: e.message }));
    req.setTimeout(10000, () => { req.destroy(); resolve({ error: 'timeout' }); });
  });
}

// Checks the subscription, retrying a few times on network failure.
//
// The retries are not optional politeness: with autostart the app is running
// seconds after logon, when the adapter may still be coming up and DNS isn't
// answering yet. A single failed request there would look identical to "the
// server says no", and the user would be told their subscription couldn't be
// verified every single boot.
async function fetchSubStatus(attempts = 3) {
  for (let i = 0; i < attempts; i++) {
    const sub = await apiGet('/api/sub');
    if (sub && !sub.error && typeof sub.status === 'string') {
      subStatus = sub.status;
      return sub;
    }
    if (sub && sub.error === 'unauthorized') {
      subStatus = 'unknown';
      return sub;
    }
    if (i < attempts - 1) await new Promise(r => setTimeout(r, 4000));
  }
  subStatus = 'unknown';
  return { error: 'unreachable' };
}

// Autoconnect, with the three refusals that were missing.
//
// Previously this checked only that a token or guest flag existed, then
// connected. So it would happily bring the tunnel up with no config (the
// window sat on "Подключение..." until it gave up), or with an expired
// subscription — where the tunnel comes up against a peer the server has
// already removed, producing a connection that carries no traffic. The window
// meanwhile disabled its own power button because the subscription was
// expired, leaving no way to switch off the thing that had just broken the
// user's internet except the tray menu.
//
// Autostart itself is unaffected by all of this: the app still launches, it
// just doesn't connect, and says why.
async function runAutoconnect() {
  if (autoconnectCancelled) return;
  const notifyAndStop = (message) => {
    updateTrayIcon('off');
    if (message) showNotification('KitoFtorVPN', message);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('vpn:autoconnected', { ok: false, notice: message || null });
    }
  };

  try {
    // A tunnel that survived a Fast Startup "shutdown" is adopted rather than
    // torn down and rebuilt identically.
    const already = await tunnelStatusFull();
    if (already.state === 'RUNNING') {
      if (already.connectStartMs) saveConnectTime(already.connectStartMs);
      updateTrayIcon('on');
      startBypassRefresh();
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('vpn:autoconnected', { ok: true });
      }
      return;
    }

    if (!hasConfig()) {
      return notifyAndStop('Автоподключение отменено: не загружен файл конфигурации');
    }

    if (!isGuest) {
      const sub = await fetchSubStatus();
      if (sub.error === 'unauthorized') {
        return notifyAndStop('Автоподключение отменено: требуется вход в аккаунт');
      }
      if (sub.error) {
        return notifyAndStop('Автоподключение отменено: не удалось проверить подписку');
      }
      if (sub.status !== 'active') {
        return notifyAndStop('Автоподключение отменено: подписка неактивна');
      }
    }

    updateTrayIcon('connecting');
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('vpn:autoconnecting');
    }
    await connectVpn();
    showNotification('KitoFtorVPN', 'VPN подключён');
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('vpn:autoconnected', { ok: true });
    }
  } catch(e) {
    console.error('autoconnect error:', e);
    updateTrayIcon('off');
    const msg = friendlyTunnelError(e.message);
    showNotification('KitoFtorVPN', msg);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('vpn:autoconnected', { ok: false, error: msg });
    }
  }
}

let updateWindow = null;

// stage: 'available' (шаг 1 — "Доступна версия X, Обновить/Позже")
//     or 'downloaded' (шаг 2 — "Скачано, установить?")
function openUpdateWindow(version, stage) {
  if (updateWindow && !updateWindow.isDestroyed()) {
    updateWindow.webContents.send('update:setStage', { stage, version });
    updateWindow.focus();
    return;
  }

  const mainBounds = mainWindow ? mainWindow.getBounds() : { x: 500, y: 200, width: 380, height: 560 };
  const w = 420, h = 460;
  const x = mainBounds.x + Math.round((mainBounds.width - w) / 2);
  const y = mainBounds.y + Math.round((mainBounds.height - h) / 2);

  updateWindow = new BrowserWindow({
    width: w, height: h,
    x, y,
    resizable: false,
    frame: false,
    transparent: false,
    backgroundColor: '#0b1120',
    icon: APP_ICON,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  updateWindow.loadFile('ui/update.html', { query: { version: version || '', stage: stage || 'available' } });
  updateWindow.on('closed', () => { updateWindow = null; });
}

// Отправляет прогресс скачивания в уже открытое окно обновления (если оно
// открыто) — окно само решает, как его отрисовать (полоска внизу шага 1).
function sendUpdateProgress(percent) {
  if (updateWindow && !updateWindow.isDestroyed()) {
    updateWindow.webContents.send('update:progress', { percent });
  }
}

// Останавливает VPN-туннель и фоновую службу — то же самое, что делает
// tray "Выход" (quitApp()) — перед тем как отдать управление установщику.
// Нужно, чтобы свежескачанный инсталлятор не наткнулся на "VPN запущен,
// закройте вручную" и чтобы ничего не висело в Диспетчере задач/Службах.
async function stopTunnelForInstall() {
  stopBypassRefresh();
  try { await tunnelExec('stop'); } catch(e) { /* не был запущен — ок */ }
  try { await tunnelExec('service-stop'); } catch(e) {
    console.error('stopTunnelForInstall: service-stop failed:', e.message);
  }
}

// Шаг 2 → «Да, установить». Закрывает окно обновления, гасит VPN и службу
// полностью, очищает "висящую" версию из настроек (раз ставим — она
// больше не pending) и передаёт управление NSIS-инсталлятору. Сам визард
// NSIS не меняем — после этого вызова дальше показывается стандартное
// окно установки Windows со своей финальной страницей "Запустить".
ipcMain.handle('update:install', async () => {
  isQuitting = true;
  if (updateWindow && !updateWindow.isDestroyed()) { updateWindow.close(); }
  await stopTunnelForInstall();
  try {
    const s = loadSettings();
    saveSettings({ ...s, updatePendingVersion: null });
  } catch(e) {}
  setImmediate(() => autoUpdater && autoUpdater.quitAndInstall());
});

// Шаг 1 → «Обновить». Начинает реальное скачивание (autoDownload=false,
// так что до этого клика ничего не льётся по сети). download-progress и
// update-downloaded дальше обрабатываются в подписках ниже и форвардятся
// в окно через sendUpdateProgress / openUpdateWindow(..., 'downloaded').
ipcMain.handle('update:download', async () => {
  if (!autoUpdater) return { error: 'updater unavailable' };
  try {
    await autoUpdater.downloadUpdate();
    return { ok: true };
  } catch(e) {
    return { error: e && e.message || String(e) };
  }
});

// «Позже» (шаг 1) или «Нет» (шаг 2) — а также чекбокс «не спрашивать»,
// который может быть отмечен на любом из двух шагов.
ipcMain.handle('update:skip', (event, { dontAskAgain } = {}) => {
  if (updateWindow && !updateWindow.isDestroyed()) updateWindow.close();
  if (dontAskAgain) {
    const s = loadSettings();
    saveSettings({ ...s, updateSkipPrompt: true });
  }
});

// Настройки → кнопка «Проверить обновление». Игнорирует updateSkipPrompt —
// это явный запрос пользователя, флаг автопроверки на него не действует.
ipcMain.handle('update:checkManual', async () => {
  if (!app.isPackaged || !autoUpdater) return { upToDate: true };
  try {
    const result = await autoUpdater.checkForUpdates();
    if (!result || !result.updateInfo) return { upToDate: true };
    const latest = result.updateInfo.version;
    if (latest && latest !== app.getVersion()) {
      await maybeShowUpdateWindow(latest);
      return { upToDate: false, version: latest };
    }
    return { upToDate: true };
  } catch(e) {
    return { error: e && e.message || String(e) };
  }
});

app.on('second-instance', () => showMainWindow());

// Решает, какой шаг показать для найденной версии `latest`:
//  - если это та же версия, что пользователь уже видел скачанной и отложил
//    (settings.updatePendingVersion === latest) — тихо дозапрашиваем
//    скачивание (мгновенно из кеша electron-updater, без сети) и открываем
//    окно сразу на шаге 2, без промежуточного мигания шагом 1/прогрессом;
//  - иначе — это версия, которую пользователь ещё не видел (либо вышла
//    более новая, пока старая лежала отложенной) — показываем шаг 1.
async function maybeShowUpdateWindow(latest) {
  const s = loadSettings();
  if (s.updatePendingVersion && s.updatePendingVersion === latest) {
    try {
      await autoUpdater.downloadUpdate();
      // update-downloaded подписка ниже сама откроет окно на шаге 2.
    } catch(e) {
      // Кеш оказался не валиден (например, файл удалили вручную) —
      // откатываемся к обычному показу шага 1.
      openUpdateWindow(latest, 'available');
    }
  } else {
    openUpdateWindow(latest, 'available');
  }
}

app.whenReady().then(createWindow).then(() => {
  // Register as early as possible once the app is ready — see the note
  // next to registerShutdownHandler's definition for why this can't be
  // done at module top-level.
  try { registerShutdownHandler(); } catch (e) { console.error('registerShutdownHandler:', e); }

  // Re-sync autostart with the saved setting on every launch. After an
  // app update (NSIS replaces the .exe and can wipe/relocate the Task
  // Scheduler entry), the saved "autostart: true" setting would otherwise
  // sit there doing nothing until the user manually flipped the toggle
  // off and on again. Comparing against the actual current state and only
  // touching the registration when it's out of sync also avoids needless
  // schtasks calls (and their UAC-adjacent overhead) on every normal start.
  try {
    const s = loadSettings();
    const wantAutostart = !!s.autostart;
    const wantHidden = !!s.startMinimized;
    const actual = getAutostartState();
    if (wantAutostart !== actual.enabled
        || (wantAutostart && (wantHidden !== actual.hidden || !actual.current))) {
      setAutostart(wantAutostart, wantHidden);
      _autostartCache = null;
    }
  } catch(e) {
    console.error('autostart re-sync error:', e);
  }

  // Anything the previous session resolved is loaded up front, so if the
  // tunnel is already up (adopted below) or comes up shortly, the whitelist
  // is in force immediately rather than after the first DNS round.
  loadBypassCache();

  // Warm up the background tunnel service right away. The service is now
  // persistent (created once, stays running) instead of being recreated on
  // every connect — this call makes sure it's already up by the time the
  // user clicks "Connect", so the very first connect of a session is fast
  // too, not just subsequent ones. Failures here are silent on purpose:
  // if this fails (e.g. somehow not elevated), the normal connect flow
  // will retry the same install-and-start logic anyway.
  tunnelExec('status').catch(() => {});

  // Check for updates only in packaged app — in dev there's no published
  // release to compare against, and electron-updater throws on dev_app_update.yml missing.
  if (!app.isPackaged || !autoUpdater) return;

  // Пользователь поставил «не спрашивать об обновлениях» — автопроверка
  // при старте полностью выключена. Узнать про новую версию можно только
  // через кнопку «Проверить обновление» в настройках (она не смотрит на
  // этот флаг — это явный запрос, а не фоновая проверка).
  if (loadSettings().updateSkipPrompt) return;

  // TEMP DIAGNOSTIC: console.error is invisible once packaged (no terminal
  // attached), so write updater events to a plain file we can read directly
  // — this is the only way to see what's actually happening on the user's
  // machine instead of guessing.
  const updateLogPath = path.join(DATA_DIR, 'update-debug.log');
  const logUpdate = (msg) => {
    try { fs.appendFileSync(updateLogPath, `[${new Date().toISOString()}] ${msg}\n`); } catch(e) {}
  };
  try {
    // Ничего не скачивается само и не ставится само при выходе — весь
    // процесс теперь требует явного клика пользователя на каждом шаге
    // (см. update:download / update:install выше).
    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = false;
    logUpdate(`init: current app version = ${app.getVersion()}`);
    autoUpdater.on('error', (err) => { console.error('updater:', err && err.message); logUpdate(`ERROR: ${err && err.stack || err}`); });
    autoUpdater.on('checking-for-update', () => logUpdate('checking-for-update'));
    autoUpdater.on('update-available', (info) => {
      logUpdate(`update-available: ${JSON.stringify(info)}`);
      maybeShowUpdateWindow(info && info.version ? info.version : '').catch(e => logUpdate(`maybeShowUpdateWindow error: ${e}`));
    });
    autoUpdater.on('update-not-available', (info) => logUpdate(`update-not-available: ${JSON.stringify(info)}`));
    autoUpdater.on('download-progress', (p) => {
      logUpdate(`download-progress: ${p.percent}%`);
      sendUpdateProgress(p.percent);
    });
    autoUpdater.on('update-downloaded', (info) => {
      logUpdate(`update-downloaded: ${JSON.stringify(info)}`);
      const version = info && info.version ? info.version : '';
      try {
        const s = loadSettings();
        saveSettings({ ...s, updatePendingVersion: version });
      } catch(e) {}
      openUpdateWindow(version, 'downloaded');
    });
    // С автозапуском и автоподключением VPN сеть/DNS на старте может быть
    // ещё не готова (адаптер поднимается, маршруты и DNS перестраиваются),
    // и checkForUpdates() падает с ERR_NAME_NOT_RESOLVED / ERR_INTERNET_DISCONNECTED
    // ещё до того, как туннель встал. Поэтому: 1) увеличенная начальная
    // задержка, 2) автоматический повтор именно на сетевые ошибки, с паузами
    // между попытками, чтобы дать VPN время подняться.
    const NETWORK_ERROR_CODES = ['ERR_NAME_NOT_RESOLVED', 'ERR_INTERNET_DISCONNECTED', 'ERR_NETWORK_CHANGED', 'ERR_CONNECTION_RESET', 'ERR_PROXY_CONNECTION_FAILED', 'ERR_CONNECTION_TIMED_OUT'];
    const isNetworkError = (e) => {
      const msg = (e && (e.message || e.toString())) || '';
      return NETWORK_ERROR_CODES.some(code => msg.includes(code));
    };
    const MAX_UPDATE_CHECK_RETRIES = 4;
    const RETRY_DELAY_MS = 10000; // 10 сек между попытками
    const attemptCheckForUpdates = (attempt) => {
      logUpdate(`calling checkForUpdates() (attempt ${attempt}/${MAX_UPDATE_CHECK_RETRIES})`);
      autoUpdater.checkForUpdates().catch(e => {
        console.error('updater check:', e);
        logUpdate(`checkForUpdates rejected: ${e && e.stack || e}`);
        if (isNetworkError(e) && attempt < MAX_UPDATE_CHECK_RETRIES) {
          logUpdate(`network error detected, retrying in ${RETRY_DELAY_MS}ms`);
          setTimeout(() => attemptCheckForUpdates(attempt + 1), RETRY_DELAY_MS);
        }
      });
    };
    // Delay a bit so the UI renders first (and VPN autoconnect has a head start), then check.
    setTimeout(() => attemptCheckForUpdates(1), 15000);
  } catch(e) {
    console.error('updater init:', e);
    logUpdate(`init throw: ${e && e.stack || e}`);
  }
});
app.on('window-all-closed', (e) => {
  // Don't quit — tray keeps running
});

// Guarantee tunnel stops on any exit path (Alt+F4 on a non-hidden window,
// tray "Выход", external kill). System shutdown/restart is handled
// separately by registerShutdownHandler() above (session-end on Windows,
// setShutdownHandler on macOS/Linux), since Windows doesn't reliably wait
// for before-quit to finish in that case — this handler covers the
// remaining "app is quitting but Windows itself isn't" paths, going
// through the same stopTunnelOnExit() so both can't drift.
let beforeQuitHandled = false;
app.on('before-quit', (event) => {
  if (beforeQuitHandled) return;
  beforeQuitHandled = true;
  // During a Windows session-end the teardown already ran synchronously in
  // the session-end handler. Calling preventDefault() here would only stall
  // a quit Windows is not going to wait for anyway.
  if (sessionEnding) return;
  event.preventDefault();
  stopTunnelOnExit().then(() => app.exit(0));
});

// ─── Settings window ─────────────────────────────────────

function openSettings() {
  if (settingsWindow) {
    settingsWindow.focus();
    return;
  }

  // Position to the left of main window with 12px gap, clamped to work area.
  const mainBounds = mainWindow ? mainWindow.getBounds() : { x: 500, y: 200, width: 380, height: 560 };
  const settingsWidth = 340;
  const settingsHeight = 672; // grew by one row when "запускать свёрнутым" was added
  const gap = 12;
  const display = screen.getDisplayNearestPoint({ x: mainBounds.x, y: mainBounds.y });
  const wa = display.workArea;
  let sx = mainBounds.x - settingsWidth - gap;
  let sy = mainBounds.y + Math.round((mainBounds.height - settingsHeight) / 2);
  sx = Math.min(Math.max(sx, wa.x), wa.x + wa.width - settingsWidth);
  sy = Math.min(Math.max(sy, wa.y), wa.y + wa.height - settingsHeight);

  settingsWindow = new BrowserWindow({
    width: settingsWidth,
    height: settingsHeight,
    x: sx,
    y: sy,
    resizable: false,
    frame: false,
    transparent: false,
    backgroundColor: '#0b1120',
    icon: APP_ICON,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  settingsWindow.loadFile('ui/settings.html');
  settingsWindow.on('closed', () => {
    settingsWindow = null;
    // Return focus to main window without changing its z-order.
    if (mainWindow && !mainWindow.isDestroyed() && mainWindow.isVisible()) {
      mainWindow.focus();
    }
  });
}

function openWhitelist() {
  if (whitelistWindow) {
    whitelistWindow.focus();
    return;
  }

  // Position to the right of main window, mirroring settings (which sits
  // on the left with a 12px gap). Clamped to work area so it never goes off-screen.
  const mainBounds = mainWindow ? mainWindow.getBounds() : { x: 500, y: 200, width: 380, height: 560 };
  const w = 460;
  const h = 540;
  const gap = 12;
  const display = screen.getDisplayNearestPoint({ x: mainBounds.x, y: mainBounds.y });
  const wa = display.workArea;
  let wx = mainBounds.x + mainBounds.width + gap;
  let wy = mainBounds.y + Math.round((mainBounds.height - h) / 2);
  wx = Math.min(Math.max(wx, wa.x), wa.x + wa.width - w);
  wy = Math.min(Math.max(wy, wa.y), wa.y + wa.height - h);

  whitelistWindow = new BrowserWindow({
    width: w,
    height: h,
    x: wx,
    y: wy,
    resizable: false,
    frame: false,
    transparent: false,
    backgroundColor: '#0b1120',
    icon: APP_ICON,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  whitelistWindow.loadFile('ui/whitelist.html');
  whitelistWindow.on('closed', () => {
    whitelistWindow = null;
    // Return focus to settings if open, otherwise to main — without sinking either window.
    const target = (settingsWindow && !settingsWindow.isDestroyed() && settingsWindow.isVisible())
      ? settingsWindow
      : (mainWindow && !mainWindow.isDestroyed() && mainWindow.isVisible() ? mainWindow : null);
    if (target) target.focus();
  });
}

// ─── Auth: browser + local callback ─────────────────────

function findFreePort() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

// The callback server used to accept /callback?token=... from anyone who
// could reach the port. A cross-origin GET from any web page the user has
// open needs no preflight, so a malicious site could scan localhost ports
// and plant *its* session token in the app — after which the user is
// silently working under the attacker's account and config.
//
// Three things close that: a random state that the site cannot know,
// generated here and echoed back by our own backend; a Sec-Fetch-Site
// check, which browsers set on cross-site requests and cannot be forged by
// page script; and a lifetime cap, so the server isn't left listening
// forever when a login is abandoned halfway.
let authState = null;
let authTimer = null;

function closeAuthServer() {
  if (authTimer) { clearTimeout(authTimer); authTimer = null; }
  if (authServer) { authServer.close(); authServer = null; }
  authState = null;
}

async function startAuthServer() {
  if (authServer) return authPort;
  authPort = await findFreePort();
  authState = crypto.randomBytes(32).toString('hex');

  if (authTimer) clearTimeout(authTimer);
  authTimer = setTimeout(() => { closeAuthServer(); }, 5 * 60 * 1000);

  return new Promise((resolve) => {
    authServer = http.createServer(async (req, res) => {
      const url = new URL(req.url, `http://localhost:${authPort}`);
      if (url.pathname === '/callback') {
        // Browsers set these themselves and page script cannot forge them.
        //
        // Checking Sec-Fetch-Site for "not cross-site" was wrong: the real
        // login is a redirect from my.kitoftorvpn.fun to localhost, which IS
        // cross-site, so the legitimate flow got a 403.
        //
        // What actually separates a login from an attack is the *kind* of
        // request. A real callback is a top-level navigation — the browser
        // going to an address. An attack from another site would be a
        // background fetch/XHR/image load, which carries mode=cors|no-cors
        // and dest=empty|image, never navigate/document.
        //
        // The primary defence remains the state parameter below; this check
        // just removes the easiest class of attempt.
        const mode = req.headers['sec-fetch-mode'];
        const dest = req.headers['sec-fetch-dest'];
        if ((mode && mode !== 'navigate') || (dest && dest !== 'document')) {
          console.error('auth callback: rejected non-navigation request', mode, dest);
          res.writeHead(403);
          res.end('Forbidden');
          return;
        }
        const token = url.searchParams.get('token');
        const state = url.searchParams.get('state');
        if (!authState || state !== authState) {
          // Reached either by a forged callback (the point of the check) or
          // because the backend didn't pass ?state= through to the redirect.
          // The message names the second case explicitly: it is the one a
          // real user can hit, and "Invalid state" alone would send them
          // hunting in the wrong place.
          console.error('auth callback: state mismatch (backend must echo the state parameter back)');
          res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(`
            <html><body style="background:#0b1120;color:#f1f5f9;font-family:-apple-system,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
              <div style="text-align:center;max-width:420px">
                <h2 style="color:#ef4444;font-size:20px;margin-bottom:8px">Не удалось завершить вход</h2>
                <p style="color:#94a3b8;font-size:14px">Запрос не прошёл проверку безопасности. Закройте эту вкладку и попробуйте войти заново.</p>
              </div>
            </body></html>
          `);
          return;
        }
        if (token) {
          cachedToken = token;
          await saveToken(token);
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(`
            <html><body style="background:#0b1120;color:#f1f5f9;font-family:-apple-system,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
              <div style="text-align:center">
                <div style="font-size:40px;margin-bottom:12px">&#10003;</div>
                <h2 style="color:#10b981;font-size:20px;margin-bottom:8px">Авторизация успешна</h2>
                <p style="color:#94a3b8;font-size:14px">Можете закрыть эту вкладку и вернуться в приложение.</p>
              </div>
            </body></html>
          `);
          if (mainWindow) {
            resizeWindowFor('main');
            mainWindow.loadFile('ui/main.html');
            mainWindow.show();
            mainWindow.focus();
          }
          setTimeout(() => { closeAuthServer(); }, 2000);
        } else {
          res.writeHead(400);
          res.end('Missing token');
        }
      } else {
        res.writeHead(404);
        res.end('Not found');
      }
    });
    authServer.listen(authPort, '127.0.0.1', () => resolve(authPort));
  });
}

// ─── IPC: Auth ───────────────────────────────────────────

ipcMain.handle('app:getVersion', () => app.getVersion());

ipcMain.handle('auth:login', async () => {
  const port = await startAuthServer();
  shell.openExternal(`${API_BASE}/login?desktop=1&port=${port}&state=${authState}`);
  return { ok: true };
});

ipcMain.handle('auth:register', async () => {
  const port = await startAuthServer();
  shell.openExternal(`${API_BASE}/register?desktop=1&port=${port}&state=${authState}`);
  return { ok: true };
});

ipcMain.handle('auth:google', async () => {
  const port = await startAuthServer();
  shell.openExternal(`${API_BASE}/auth/google?desktop=1&port=${port}&state=${authState}`);
  return { ok: true };
});

ipcMain.handle('auth:telegram', async () => {
  const port = await startAuthServer();
  shell.openExternal(`${API_BASE}/auth/telegram?desktop=1&port=${port}&state=${authState}`);
  return { ok: true };
});

ipcMain.handle('auth:logout', async () => {
  cachedToken = null;
  isGuest = false;
  subStatus = 'unknown';
  autoconnectCancelled = true;
  deleteToken();
  deleteGuestMode();
  try { await disconnectVpn(); } catch(e) { updateTrayIcon('off'); }
  if (mainWindow) {
    resizeWindowFor('login');
    mainWindow.loadFile('ui/login.html');
  }
  return { ok: true };
});

// Session expired — show login screen WITHOUT deleting the saved token.
// The token stays on disk so if the server was temporarily unavailable,
// the next launch won't force a full re-login.
ipcMain.handle('auth:sessionExpired', async () => {
  cachedToken = null;
  isGuest = false;
  subStatus = 'unknown';
  // The pending autoconnect has to be cancelled here, not just left to fail.
  // It runs on a timer set at startup, and the session check that lands the
  // user back on the login screen finishes well before that timer fires — so
  // the tunnel came up two seconds after the app had decided the user wasn't
  // logged in, leaving a connected VPN behind a login screen.
  autoconnectCancelled = true;
  try { await disconnectVpn(); } catch(e) { updateTrayIcon('off'); }
  if (mainWindow) {
    resizeWindowFor('login');
    mainWindow.loadFile('ui/login.html');
  }
  return { ok: true };
});

// Guest login — skip auth/subscription, go straight to main window.
ipcMain.handle('auth:guestLogin', async () => {
  isGuest = true;
  cachedToken = null;
  saveGuestMode();
  if (mainWindow) {
    resizeWindowFor('main');
    mainWindow.loadFile('ui/main.html');
  }
  return { ok: true };
});

// Leave guest mode — back to login screen.
ipcMain.handle('auth:exitGuest', async () => {
  isGuest = false;
  autoconnectCancelled = true;
  deleteGuestMode();
  try { await disconnectVpn(); } catch(e) { updateTrayIcon('off'); }
  if (mainWindow) {
    resizeWindowFor('login');
    mainWindow.loadFile('ui/login.html');
  }
  return { ok: true };
});

ipcMain.handle('auth:isGuest', () => isGuest);
ipcMain.handle('auth:getToken', () => cachedToken || null);

// ─── IPC: API proxy (subscription status) ────────────────

// The session cookie is attached to this request, so `endpoint` must not be
// able to change which host it goes to. String-concatenating it onto
// API_BASE used to allow exactly that: an endpoint of "@evil.com/x" produces
// "https://my.kitoftorvpn.fun@evil.com/x", where everything before the "@"
// is userinfo and the real host is evil.com — handing the user's session
// token to whoever asked. Require a plain absolute path, then verify the
// parsed host really is ours before sending anything.
function buildApiUrl(endpoint) {
  if (typeof endpoint !== 'string') return null;
  if (!endpoint.startsWith('/') || endpoint.startsWith('//')) return null;
  if (endpoint.includes('@') || endpoint.includes('\\')) return null;
  let u;
  try { u = new URL(API_BASE + endpoint); } catch(e) { return null; }
  if (u.origin !== new URL(API_BASE).origin) return null;
  return u.toString();
}

ipcMain.handle('api:fetch', async (event, endpoint) => {
  if (!cachedToken) return { error: 'no_token' };
  const url = buildApiUrl(endpoint);
  if (!url) return { error: 'bad_endpoint' };
  try {
    return new Promise((resolve) => {
      const req = https.get(url, {
        headers: { 'Cookie': `cabinet_session=${cachedToken}` }
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch(e) {
            if (res.statusCode === 401) resolve({ error: 'unauthorized' });
            else resolve({ error: 'parse_error', raw: data.substring(0, 200) });
          }
        });
      });
      req.on('error', (e) => resolve({ error: e.message }));
      req.setTimeout(10000, () => { req.destroy(); resolve({ error: 'timeout' }); });
    });
  } catch(e) {
    return { error: e.message };
  }
});

// ─── IPC: Config import ──────────────────────────────────

ipcMain.handle('config:import', async () => {
  const parentWin = settingsWindow || mainWindow;
  const result = await dialog.showOpenDialog(parentWin, {
    title: 'Выберите файл конфигурации',
    filters: [{ name: 'WireGuard/AWG Config', extensions: ['conf'] }],
    properties: ['openFile'],
  });
  if (result.canceled || !result.filePaths.length) return { canceled: true };
  try {
    const confText = fs.readFileSync(result.filePaths[0], 'utf-8');
    if (!confText.includes('[Interface]') || !confText.includes('[Peer]')) {
      return { error: 'Неверный формат файла. Нужен .conf файл из личного кабинета.' };
    }

    // If the tunnel is already up, it was started with the *old* config's
    // contents (passed once via stdin, not re-read live) — just overwriting
    // the file on disk wouldn't actually change what's running. Stop it
    // first so the switch is real, then bring it back up with the new one
    // once it's saved.
    let wasRunning = false;
    try {
      const full = await tunnelStatusFull();
      wasRunning = full.state === 'RUNNING';
    } catch(e) {}
    if (wasRunning) {
      try { await disconnectVpn(); } catch(e) { updateTrayIcon('off'); }
      notifyConfigChanged({ vpnState: 'off' });
    }

    const saved = await saveConfig(confText);
    if (!saved) return { error: 'Не удалось сохранить конфигурацию.' };

    if (wasRunning) {
      try {
        await connectVpn();
        notifyConfigChanged({ hasConfig: true, vpnState: 'on' });
        return { ok: true, reconnected: true };
      } catch(e) {
        updateTrayIcon('off');
        notifyConfigChanged({ hasConfig: true, vpnState: 'off' });
        // Config itself saved fine — just tell the user the automatic
        // reconnect with it didn't work, they can hit connect manually.
        return { ok: true, reconnected: false, reconnectError: friendlyTunnelError(e.message) };
      }
    }

    notifyConfigChanged({ hasConfig: true });
    return { ok: true };
  } catch(e) {
    return { error: 'Не удалось прочитать файл.' };
  }
});

ipcMain.handle('config:exists', async () => {
  // A file check now — but any secret still sitting in Credential Manager
  // has to be migrated first, or a returning user looks like they never
  // imported a config.
  if (!hasConfig()) await migrateFromKeytar(KEYTAR_CONFIG_ACCOUNT, CONFIG_FILE);
  return hasConfig();
});

ipcMain.handle('config:delete', async () => {
  try { await disconnectVpn(); } catch(e) { updateTrayIcon('off'); }
  deleteConfigFile();
  notifyConfigChanged({ hasConfig: false, vpnState: 'off' });
  return { ok: true };
});

// ─── IPC: Settings ───────────────────────────────────────

ipcMain.handle('settings:get', () => loadSettings());

ipcMain.handle('settings:set', (event, newSettings) => {
  const current = loadSettings();
  const merged = { ...current, ...newSettings };
  saveSettings(merged);

  // Autostart and "start minimized" are one registration: the second is just
  // an argument on the command line the first registers, so a change to
  // either has to rewrite the task.
  if (newSettings.autostart !== undefined || newSettings.startMinimized !== undefined) {
    setAutostart(!!merged.autostart, !!merged.startMinimized);
    _autostartCache = null; // invalidate cache after change
  }

  return merged;
});

ipcMain.handle('settings:openWindow', () => {
  openSettings();
  return { ok: true };
});

ipcMain.handle('settings:closeWindow', () => {
  if (settingsWindow) settingsWindow.close();
  return { ok: true };
});

// ─── IPC: Whitelist window ───────────────────────────────

ipcMain.handle('whitelist:openWindow', () => {
  openWhitelist();
  return { ok: true };
});

ipcMain.handle('whitelist:closeWindow', () => {
  if (whitelistWindow) whitelistWindow.close();
  return { ok: true };
});

ipcMain.handle('whitelist:get', () => {
  const s = loadSettings();
  return Array.isArray(s.whitelist) ? s.whitelist : [];
});

ipcMain.handle('whitelist:save', async (event, list) => {
  if (!Array.isArray(list)) list = [];
  const seen = new Set();
  const cleaned = [];
  for (const raw of list) {
    const v = (raw || '').trim();
    if (!v || seen.has(v.toLowerCase())) continue;
    seen.add(v.toLowerCase());
    cleaned.push(v);
  }
  const current = loadSettings();
  const previous = Array.isArray(current.whitelist) ? current.whitelist : [];
  saveSettings({ ...current, whitelist: cleaned });

  // Saving the list no longer restarts the tunnel. It used to have to: the
  // whitelist was compiled into the peer's AllowedIPs, and that is only read
  // when the WireGuard device is created. Bypass routes are installed on the
  // live tunnel instead, so this is now a routing-table update measured in
  // milliseconds, with no drop in connectivity and no "Применение..." state to
  // sit through.
  // An edit is an explicit instruction, so a domain the user just *removed*
  // has to lose its addresses now rather than aging out over the normal
  // 30-minute lifetime.
  //
  // Only the removed entries' addresses are dropped, though — not the whole
  // set. Wiping everything meant every edit re-resolved all ~30 domains from
  // scratch, and any host that happened to time out in that round lost its
  // routes until the next refresh. Now that route changes also reset the
  // connections sitting on them (see applyBypass on the Go side), that
  // churn would be felt directly as sites dropping for no reason.
  dropRemovedFromBypass(previous, cleaned);
  saveBypassCache();

  try {
    const st = await tunnelStatus().catch(() => 'STOPPED');
    if (st === 'RUNNING') {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('vpn:reconnecting', { reason: 'whitelist' });
      }
      await applyWhitelistNow();
      startBypassRefresh();
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('vpn:reconnected', { ok: true });
      }
    }
  } catch(e) {
    console.error('whitelist:save apply error:', e);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('vpn:reconnected', { ok: true });
    }
  }

  return { ok: true, count: cleaned.length };
});

// ─── Connect time persistence ────────────────────────────

function saveGuestMode() {
  try { fs.writeFileSync(GUEST_FILE, '1', 'utf-8'); } catch(e) {}
}

function loadGuestMode() {
  try { return fs.existsSync(GUEST_FILE); } catch(e) { return false; }
}

function deleteGuestMode() {
  try { fs.unlinkSync(GUEST_FILE); } catch(e) {}
}

function saveConnectTime(timestampMs) {
  try {
    const t = Number.isFinite(timestampMs) ? timestampMs : Date.now();
    fs.writeFileSync(CONNECT_TIME_FILE, t.toString(), 'utf-8');
  } catch(e) {}
}

function loadConnectTime() {
  try {
    if (!fs.existsSync(CONNECT_TIME_FILE)) return null;
    const t = parseInt(fs.readFileSync(CONNECT_TIME_FILE, 'utf-8').trim());
    return isNaN(t) ? null : t;
  } catch(e) { return null; }
}

function deleteConnectTime() {
  try { fs.unlinkSync(CONNECT_TIME_FILE); } catch(e) {}
}

let statusMissStreak = 0;

// ─── IPC: Tunnel management ──────────────────────────────

// Technical errors from the tunnel process (Go/Windows API) come back in
// English (e.g. "SCM connect failed", "CreateTUN failed: ..."). Showing
// that directly in the UI looks broken to a non-technical user. This maps
// the few cases we can give useful advice for, and otherwise replaces the
// raw text with one calm, generic message in Russian — the real text is
// still logged to debug.log for support purposes.
function friendlyTunnelError(message) {
  const text = String(message || '');
  if (/Конфигурация повреждена или не найдена/.test(text)) {
    return text;
  }
  if (/need admin|access is denied|отказано в доступе/i.test(text)) {
    return 'Недостаточно прав. Запустите приложение от имени администратора.';
  }
  if (/CreateTUN|wintun/i.test(text)) {
    return 'Не удалось создать сетевой адаптер VPN. Попробуйте перезапустить приложение или компьютер.';
  }
  if (/timeout|timed out/i.test(text)) {
    return 'Подключение занимает слишком много времени. Проверьте интернет-соединение и попробуйте снова.';
  }
  if (/parse failed/i.test(text)) {
    return 'Файл конфигурации повреждён. Загрузите .conf файл заново.';
  }
  console.error('tunnel error (raw):', text);
  return 'Не удалось подключиться. Попробуйте ещё раз или перезапустите приложение.';
}

// kitoftor-tunnel.exe is a console program, so every one of these calls makes
// Windows create a console window for it. Even though it lives for a few
// milliseconds, that window is created, painted and destroyed on the desktop —
// which reads exactly like a right-click "Refresh": the whole desktop blinks,
// and the cursor flips to "busy" for an instant. With the status poll running
// every three seconds it never stops. windowsHide keeps the console off the
// screen; the process itself and its output are unaffected.
function tunnelExec(command, arg) {
  return new Promise((resolve, reject) => {
    const args = arg ? [command, arg] : [command];
    execFile(TUNNEL_EXE, args, { timeout: 40000, windowsHide: true }, (error, stdout, stderr) => {
      if (error) reject(new Error(stderr || stdout || error.message));
      else resolve(stdout.trim());
    });
  });
}

// kitoftor-tunnel's Windows service keeps a small control channel open on a
// named pipe (see kitoftor-tunnel/main.go, pipeName). The CLI's own "status"
// command connects to that same pipe, sends "STATUS <base64>\n" and prints
// back whatever it gets ("RUNNING <ts>" or "STOPPED").
//
// This was a loopback TCP port until the pipe replaced it — the port was
// reachable by every process on the machine, including unprivileged ones,
// with no authentication at all. The pipe's DACL grants access to SYSTEM and
// Administrators only; this app qualifies because it runs elevated.
//
// The renderer polls vpn:status every 3s (ui/main.html, pollVPN) to keep the
// connect/disconnect button and the tray icon in sync. Previously every one
// of those polls went through tunnelExec('status'), i.e. spawning a brand
// new kitoftor-tunnel.exe process just to make that same call — visible on
// Windows as a recurring "app is busy" cursor every few seconds even while
// sitting on the desktop with the VPN window minimized. Talking to the
// control channel directly from Node (same protocol, no extra process)
// removes that spawn entirely. Falls back to the old execFile path only if
// the direct call fails, so behaviour stays identical on the error path.
const CONTROL_PIPE = '\\\\.\\pipe\\KitoFtorVPNTunnel';

// One attempt at the control channel, for any command. Rejected-because-busy
// is a normal, transient outcome, not a failure — see tunnelPipeCommand below.
//
// Wire format is the same one the Go CLI uses (see sendCommand in
// kitoftor-tunnel/main.go): "<COMMAND> <base64-body>\n" out, one line back.
// Base64 is what lets a WireGuard config, newlines and all, travel as a single
// line.
function tunnelPipeAttempt(cmd, body, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: CONTROL_PIPE });
    let buf = '';
    let settled = false;

    const finish = (fn, val) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      fn(val);
    };

    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => finish(reject, new Error('timeout')));
    socket.on('error', (e) => finish(reject, e));

    socket.on('connect', () => {
      const encoded = Buffer.from(body || '', 'utf-8').toString('base64');
      socket.write(`${cmd} ${encoded}\n`);
    });

    socket.on('data', (chunk) => {
      buf += chunk.toString('utf-8');
      if (buf.includes('\n')) {
        finish(resolve, buf.split('\n')[0].trim());
      }
    });

    socket.on('end', () => {
      // Service closes the connection right after writing the reply; if we
      // got a full line in 'data' we've already resolved above, this is
      // just the no-trailing-newline edge case.
      if (!settled) finish(resolve, buf.trim());
    });
  });
}

// Retries a couple of times before giving up on the control channel.
//
// Windows refuses a named-pipe connection with ERROR_PIPE_BUSY when every
// instance is occupied, which happens naturally whenever another caller is
// mid-conversation. The Go CLI has always retried through that. This side
// didn't: one refusal and it fell through to spawning kitoftor-tunnel.exe,
// which is the process-per-poll this channel exists to replace. Worse, each
// spawned process is itself another client, so a burst of contention kept
// itself going — the log showed a status process every three seconds for a
// minute after each connect.
//
// The service now keeps four instances waiting, so collisions should be rare;
// these retries make them harmless when they do happen.
async function tunnelPipeCommand(cmd, body, timeoutMs = 5000) {
  let lastErr;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await tunnelPipeAttempt(cmd, body, timeoutMs);
    } catch (e) {
      lastErr = e;
      const code = e && e.code;
      // ENOENT here means "no free instance right now", not "no such pipe" —
      // Windows reports both the same way through libuv. ECONNRESET and EOF
      // are the shapes a reply that got discarded on the service side arrives
      // in; that race is fixed there, but retrying costs nothing and is far
      // cheaper than the process spawn this otherwise falls back to. Anything
      // else (an actual timeout, a closed service) isn't worth retrying.
      if (code !== 'EBUSY' && code !== 'ENOENT' && code !== 'EPIPE'
          && code !== 'ECONNRESET' && code !== 'EOF') break;
      await new Promise(r => setTimeout(r, 60 * (attempt + 1)));
    }
  }
  throw lastErr || new Error('control channel unreachable');
}

async function tunnelStatusDirect(timeoutMs = 5000) {
  return parseStatusLine(await tunnelPipeCommand('STATUS', '', timeoutMs));
}

// Parses the control channel's "RUNNING <unix_seconds>" / "STOPPED" reply.
// The timestamp here is the Go service's own connectStart (kitoftor-tunnel/
// main.go, tunnelState.connectStart) — i.e. ground truth for when the
// *actual* tunnel came up, independent of anything Electron has cached
// locally. Returning it lets callers resync connect_time.dat against it
// instead of trusting a local file that can go stale (e.g. if the app
// didn't get to clear it before a shutdown — see stopTunnelOnExit).
function parseStatusLine(line) {
  if (line.startsWith('RUNNING')) {
    const parts = line.split(/\s+/);
    const sec = parts.length > 1 ? parseInt(parts[1], 10) : NaN;
    return { state: 'RUNNING', connectStartMs: Number.isFinite(sec) ? sec * 1000 : null };
  }
  return { state: 'STOPPED', connectStartMs: null };
}

// Same contract as tunnelExec('status'): resolves to 'RUNNING' or 'STOPPED',
// never throws for "service not running" (mirrors tunnelStatus() in Go,
// which treats an unreachable control channel as STOPPED, not an error).
// Kept for the existing `=== 'RUNNING'` call sites; use tunnelStatusFull()
// where the connect timestamp is also needed.
async function tunnelStatus() {
  return (await tunnelStatusFull()).state;
}

// Records why the control channel refused, the first few times it happens.
//
// The fallback path is silent by design — it works, so nothing surfaces — and
// console.error is invisible in a packaged app with no terminal attached. That
// left "the app spawns a process for every status poll" visible in the tunnel
// log while the actual reason stayed unknowable. This writes it down instead
// of guessing. Capped, so a permanently broken channel can't grow a file
// unbounded.
let _pipeFailuresLogged = 0;
function logPipeFailure(e) {
  if (_pipeFailuresLogged >= 20) return;
  _pipeFailuresLogged++;
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const line = `[${new Date().toISOString()}] code=${e && e.code} errno=${e && e.errno} syscall=${e && e.syscall} msg=${e && e.message}\n`;
    fs.appendFileSync(path.join(DATA_DIR, 'pipe-debug.log'), line, 'utf-8');
  } catch(err) {}
}

async function tunnelStatusFull() {
  try {
    return await tunnelStatusDirect();
  } catch (e) {
    // Control channel not reachable (service not installed/started yet) or
    // some unexpected hiccup — fall back to the CLI exactly like before.
    logPipeFailure(e);
    try {
      const out = await tunnelExec('status');
      return parseStatusLine(out.trim());
    } catch (e2) {
      return { state: 'STOPPED', connectStartMs: null };
    }
  }
}

// Hands the split-tunneling list to the service. Separate from the config on
// purpose: it can be sent at any time, including repeatedly on a live tunnel,
// which is what allows whitelisted addresses to be re-resolved without a
// reconnect.
//
// Straight down the control channel, because this is the one call that repeats
// on its own schedule. Going through kitoftor-tunnel.exe meant a process every
// sixty seconds — and a console process, so Windows created a conhost.exe for
// it and painted a window. That window is what the desktop "blink" was:
// briefly, something is on screen, everything behind it repaints, and the
// cursor flips to busy. windowsHide didn't stop it. No process, no window.
async function tunnelBypassStdin(listText) {
  let reply;
  try {
    reply = await tunnelPipeCommand('BYPASS', listText || '', 20000);
  } catch (e) {
    // Couldn't reach the service at all — that, and only that, is worth
    // falling back for.
    logPipeFailure(e);
    return tunnelBypassViaExe(listText);
  }
  // It answered and said no. Running the exe would relay the same refusal
  // through a second process, so this goes straight back to the caller.
  if (!reply.startsWith('OK')) throw new Error(reply || 'bypass failed');
  return reply;
}

// The original path, kept for when the channel isn't there — most often right
// after install, before the service has been created and started for the first
// time.
function tunnelBypassViaExe(listText) {
  return new Promise((resolve, reject) => {
    const child = spawn(TUNNEL_EXE, ['bypass'], { timeout: 20000, windowsHide: true });
    let out = '', err = '';
    child.stdout.on('data', (d) => out += d);
    child.stderr.on('data', (d) => err += d);
    child.on('close', (code) => {
      if (code === 0 && out.trim().startsWith('OK')) resolve(out.trim());
      else reject(new Error(err || out || 'bypass failed'));
    });
    child.on('error', (e) => reject(e));
    child.stdin.write(listText || '');
    child.stdin.end();
  });
}

// Connect goes through the channel too. It isn't on a timer, so it wasn't
// part of the blinking, but there is no reason to pay for a process here
// either — and the fallback below is what covers the one case the channel
// can't: a service that doesn't exist yet. Running the exe is what creates
// and starts it (ensureServiceRunning in main.go), so that path has to stay.
async function tunnelStartStdin(configContent) {
  let reply;
  try {
    reply = await tunnelPipeCommand('CONNECT', configContent, 40000);
  } catch (e) {
    logPipeFailure(e);
    return tunnelStartViaExe(configContent);
  }
  if (!reply.startsWith('OK')) throw new Error(reply || 'start-stdin failed');
  return 'OK';
}

function tunnelStartViaExe(configContent) {
  return new Promise((resolve, reject) => {
    const child = spawn(TUNNEL_EXE, ['start-stdin'], { timeout: 40000, windowsHide: true });
    let out = '', err = '';
    child.stdout.on('data', (d) => out += d);
    child.stderr.on('data', (d) => err += d);
    child.on('close', (code) => {
      if (code === 0 && out.trim() === 'OK') resolve('OK');
      else reject(new Error(err || out || 'start-stdin failed'));
    });
    child.on('error', (e) => reject(e));
    child.stdin.write(configContent);
    child.stdin.end();
  });
}

// Shared by vpn:connect and by config:import's auto-reconnect (when the
// user swaps their config while already connected, we tear down and bring
// the tunnel back up with the *new* config instead of leaving the old one
// running under the old one).
async function connectVpn() {
  const conf = await loadConfig();
  if (!conf) throw new Error('Конфигурация повреждена или не найдена. Загрузите .conf файл заново.');

  updateTrayIcon('connecting');
  statusMissStreak = 0; // fresh connection: forget any earlier missed polls
  // The config goes to the tunnel exactly as issued — the whitelist is no
  // longer baked into it. That is what makes this call fast regardless of how
  // many sites are whitelisted: the tunnel installs two routes, not several
  // hundred.
  const result = await tunnelStartStdin(conf);
  saveConnectTime();
  updateTrayIcon('on');
  // Split tunneling is applied on top of the live tunnel, and kept current
  // from here on by the refresh loop.
  startBypassRefresh();
  return result;
}

// Everything that takes the tunnel down goes through here, so the refresh
// loop can't outlive the connection it belongs to.
async function disconnectVpn() {
  stopBypassRefresh();
  statusMissStreak = 0;
  const result = await tunnelStop();
  deleteConnectTime();
  updateTrayIcon('off');
  return result;
}

// Same shape as the two above: channel first, exe only if the channel isn't
// there. Note this is DISCONNECT (tear down the tunnel), not service-stop
// (shut the background service down entirely) — the latter has to keep going
// through the exe, since it talks to the Service Control Manager rather than
// to the service's own control channel.
async function tunnelStop() {
  let reply;
  try {
    reply = await tunnelPipeCommand('DISCONNECT', '', 20000);
  } catch (e) {
    logPipeFailure(e);
    return tunnelExec('stop');
  }
  if (!reply.startsWith('OK')) throw new Error(reply || 'stop failed');
  return reply;
}

// Settings/whitelist windows can change config/VPN state behind the main
// window's back — it has its own cached hasConf/vpnState that only get
// re-read at startup otherwise. This pushes a refresh so it updates live
// instead of requiring an app restart to notice.
function notifyConfigChanged(payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('config:changed', payload);
  }
  if (settingsWindow && !settingsWindow.isDestroyed()) {
    settingsWindow.webContents.send('config:changed', payload);
  }
}

ipcMain.handle('vpn:connect', async () => {
  try {
    const result = await connectVpn();
    showNotification('KitoFtorVPN', 'VPN подключён');
    return { ok: true, result };
  } catch(e) {
    updateTrayIcon('off');
    const msg = friendlyTunnelError(e.message);
    showNotification('KitoFtorVPN', msg);
    return { error: msg };
  }
});

ipcMain.handle('vpn:disconnect', async () => {
  try {
    const result = await disconnectVpn();
    showNotification('KitoFtorVPN', 'VPN отключён');
    return { ok: true, result };
  } catch(e) {
    // The tunnel is considered down either way: leaving the UI showing
    // "Подключено" after a failed stop is worse than being optimistic here,
    // since the status poll will correct it within seconds if it's wrong.
    stopBypassRefresh();
    deleteConnectTime();
    updateTrayIcon('off');
    return { error: friendlyTunnelError(e.message) };
  }
});

// A single unanswered status poll is not proof the tunnel died.
//
// It was treated as proof, and that produced a "VPN отключён" notification and
// a red tray icon while the tunnel was up and working — then green again three
// seconds later when the next poll got through. The service side no longer
// stalls status behind other work, which removes the cause; this counter is
// the belt to that pair of braces. Two consecutive misses are required before
// a running tunnel is declared down, so any future hiccup costs three extra
// seconds of stale state instead of a false alarm.

ipcMain.handle('vpn:status', async () => {
  let full;
  try {
    full = await tunnelStatusFull();
  } catch(e) {
    full = { state: 'STOPPED', connectStartMs: null };
  }

  const reportedOff = full.state !== 'RUNNING';

  if (reportedOff && vpnStateForTray === 'on') {
    statusMissStreak++;
    if (statusMissStreak < 2) {
      // Unconfirmed. Report the last known good state and change nothing —
      // no notification, no icon change, and crucially no deleteConnectTime(),
      // which would reset the session timer on a false alarm.
      return { status: 'RUNNING' };
    }
  } else {
    statusMissStreak = 0;
  }

  const state = reportedOff ? 'off' : 'on';

  if (state === 'off') {
    deleteConnectTime();
  } else if (full.connectStartMs) {
    // Resync against the service's own connectStart rather than trusting
    // whatever's in connect_time.dat: the service is ground truth, the file is
    // a local cache so the renderer can tick without a round-trip each second.
    const cached = loadConnectTime();
    if (cached !== full.connectStartMs) saveConnectTime(full.connectStartMs);
  }

  // A poll landing mid-connect must not touch the tray. It used to: the tunnel
  // isn't up yet, so the poll saw "off", overwrote the "connecting" icon, and
  // re-enabled "Подключиться" in the tray menu — from which a second connect
  // could be started on top of the one already in flight.
  if (state !== vpnStateForTray && vpnStateForTray !== 'connecting') {
    if (vpnStateForTray === 'on' && state === 'off') {
      stopBypassRefresh();
      showNotification('KitoFtorVPN', 'VPN отключён');
    }
    updateTrayIcon(state);
  }

  return { status: reportedOff ? 'STOPPED' : 'RUNNING' };
});

ipcMain.handle('vpn:getConnectTime', () => loadConnectTime());

// ─── IPC: Subscription expiry notification ───────────────

let subExpiryNotifShown = false; // show once per app session

// Takes seconds remaining, not days.
//
// It used to take days, computed in the renderer as Math.ceil(seconds/86400),
// and that rounding made the message wrong at exactly the point it matters
// most. Three hours left became ceil(0.125) = 1 → "заканчивается завтра". And
// since ceil() of anything positive is at least 1, the "истекает сегодня"
// branch could never be reached at all. Counting whole days down here fixes
// both: under a day is today, under two days is tomorrow.
ipcMain.handle('notify:subExpiring', (event, secondsLeft) => {
  if (subExpiryNotifShown) return;
  const sec = Number(secondsLeft);
  if (!Number.isFinite(sec)) return;
  subExpiryNotifShown = true;

  const days = Math.floor(sec / 86400);
  let msg;
  if (sec <= 0) {
    msg = 'Подписка истекла';
  } else if (days === 0) {
    msg = 'Подписка истекает сегодня';
  } else if (days === 1) {
    msg = 'Подписка заканчивается завтра';
  } else {
    // 2-4 дня / 5+ дней — the plural has to be picked, not hardcoded.
    const mod10 = days % 10, mod100 = days % 100;
    const word = (mod100 >= 11 && mod100 <= 14) ? 'дней'
      : mod10 >= 2 && mod10 <= 4 ? 'дня'
      : mod10 === 1 ? 'день' : 'дней';
    msg = `Подписка заканчивается через ${days} ${word}`;
  }
  showNotification('KitoFtorVPN', msg);
});

// ─── IPC: Window controls ────────────────────────────────

ipcMain.handle('window:minimize', () => { if (mainWindow) mainWindow.minimize(); });
ipcMain.handle('window:close', () => {
  if (whitelistWindow && !whitelistWindow.isDestroyed()) { whitelistWindow.destroy(); whitelistWindow = null; }
  if (settingsWindow && !settingsWindow.isDestroyed()) { settingsWindow.destroy(); settingsWindow = null; }
  if (mainWindow) mainWindow.hide();
});

// ─── IPC: External links ─────────────────────────────────

// shell.openExternal hands the URL to whatever Windows has registered for
// that scheme. Since this app runs elevated (requireAdministrator), an
// unchecked URL from the renderer would let any injected script launch a
// local protocol handler as administrator. Only http/https get through.
ipcMain.handle('app:openExternal', (event, url) => {
  try {
    const u = new URL(String(url));
    if (u.protocol !== 'https:' && u.protocol !== 'http:') {
      console.error('openExternal: blocked scheme', u.protocol);
      return;
    }
    shell.openExternal(u.toString());
  } catch(e) {
    console.error('openExternal: invalid url');
  }
});
