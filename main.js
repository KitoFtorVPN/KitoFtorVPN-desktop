const { app, BrowserWindow, ipcMain, shell, dialog, Tray, Menu, nativeImage, screen, Notification, powerMonitor } = require('electron');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const { execFile, spawn } = require('child_process');
const net = require('net');
const dns = require('dns').promises;
// electron-updater is a runtime dep of the packaged app. In dev (npm start)
// the module may not be installed yet — fail soft so dev still works.
let autoUpdater = null;
try { autoUpdater = require('electron-updater').autoUpdater; } catch(e) {}

// keytar — native OS credential store (Windows Credential Manager).
// Eliminates the need to spawn tunnel.exe for DPAPI on every startup.
// Falls back to legacy DPAPI-via-tunnel if not available.
let keytar = null;
try { keytar = require('keytar'); } catch(e) {}

const KEYTAR_SERVICE = 'fun.kitoftorvpn.desktop';
const KEYTAR_TOKEN_ACCOUNT = 'session_token';
const KEYTAR_CONFIG_ACCOUNT = 'wireguard_config';

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
const TASK_NAME = 'KitoFtorVPNAutostart';

function showNotification(title, body, onlyWhenHidden = false) {
  if (!Notification.isSupported()) return;
  if (onlyWhenHidden && mainWindow && !mainWindow.isDestroyed() && mainWindow.isVisible()) return;
  const icon = (typeof APP_ICON !== 'undefined') ? APP_ICON : undefined;
  new Notification({ title, body, icon, silent: true }).show();
}

// Required for Windows toast notifications to work (both dev and packaged).
app.setAppUserModelId('fun.kitoftorvpn.desktop');

// ─── Guaranteed teardown on system shutdown/restart ──────
//
// before-quit (further down) is NOT enough on its own: Windows only gives
// a normal foreground app a few seconds to react to WM_QUERYENDSESSION
// before it either shows "this app is preventing shutdown" or just kills
// the process outright. If tunnelExec hadn't finished yet at that point,
// the tunnel and its routes were left running — which is the whole bug
// this fixes.
//
// powerMonitor.setShutdownHandler (Windows-only) is different: returning
// a Promise from it actually makes Windows wait for that promise before
// continuing the shutdown, the same mechanism a real "block shutdown"
// app uses. Registering it this early (before whenReady) matters per
// Electron's own docs — it has to be in place before the shutdown sequence
// can start, not added later once the window exists.
//
// stopTunnelOnExit() is shared with before-quit further down so both
// paths (user clicks "Выход" vs. Windows shutting the whole machine down)
// go through the exact same teardown and can't drift apart again.
let tunnelStopped = false;
async function stopTunnelOnExit() {
  if (tunnelStopped) return;
  tunnelStopped = true;
  // Hard cap: Windows' own patience for setShutdownHandler is finite too
  // (a few seconds in practice) — if tunnelExec is somehow stuck (killed
  // antivirus scan on the exe, disk thrashing, whatever), we must not hang
  // the whole machine's shutdown forever waiting on it. Better to return
  // and let the next boot's stale-marker cleanup (kitoftor-tunnel service,
  // see hadUncleanPriorRun) finish the job than to block a shutdown
  // indefinitely.
  await Promise.race([
    (async () => {
      try { await tunnelExec('stop'); } catch (e) {}
      try { await tunnelExec('service-stop'); } catch (e) {}
    })(),
    new Promise((resolve) => setTimeout(resolve, 4000)),
  ]);
  deleteConnectTime();
}

// NOTE: registering this inside app.whenReady() (further down) instead of
// here at top-level — some Electron builds throw/misbehave ("...is not a
// function") if powerMonitor is touched before the app 'ready' event, per
// Electron's own docs ("you cannot require or use this module until the
// ready event of the app module is emitted").
function registerShutdownHandler() {
  if (process.platform === 'win32') {
    powerMonitor.setShutdownHandler(async () => {
      await stopTunnelOnExit();
      return true; // tell Windows it's fine to continue shutting down now
    });
  }
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

// ─── Settings ────────────────────────────────────────────

function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      const loaded = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf-8'));
      return {
        autostart: false, autoconnect: false, whitelist: [],
        updateSkipPrompt: false, updatePendingVersion: null,
        ...loaded,
      };
    }
  } catch(e) {}
  return { autostart: false, autoconnect: false, whitelist: [], updateSkipPrompt: false, updatePendingVersion: null };
}

function saveSettings(settings) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf-8');
  } catch(e) {
    console.error('saveSettings error:', e);
  }
}

// ─── Whitelist (split tunneling via AllowedIPs subtraction) ────

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
  // Strip port (but not IPv6 brackets).
  if (entry.includes(':') && !entry.startsWith('[')) {
    entry = entry.split(':').slice(0, -1).join(':') || entry;
    // Above is wrong for hostnames; keep it simple:
    entry = entry.split(':')[0];
  }
  entry = entry.trim().replace(/\.$/, '');
  return entry || null;
}

// Returns true if the string looks like a plain IP or CIDR (no letters).
function isIpOrCidr(s) {
  return /^[\d./]+$/.test(s);
}

// PERFORMANCE NOTE: this used to resolve every whitelist domain one at a
// time (for...await), with no per-lookup timeout. A single slow/unreachable
// domain (no A record, slow upstream resolver, etc.) could stall for
// several seconds, and with ~30 domains in the list that easily added up
// to the 20-30s connect/disconnect times. Two fixes, same output:
//   1. All domains are resolved concurrently (Promise.all) instead of
//      sequentially — wall time becomes "the slowest single lookup"
//      instead of "the sum of every lookup".
//   2. Each lookup gets a hard timeout (RESOLVE_TIMEOUT_MS) so one bad
//      domain can't drag the whole whitelist down; it's just skipped,
//      same as today's "resolve failed" case already does.
// A short in-memory cache also avoids re-resolving the same domains on
// every connect/disconnect within a short window (domains here are static
// service whitelists, not something that needs resolving fresh every time).
const RESOLVE_TIMEOUT_MS = 3000;
const RESOLVE_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const _resolveCache = new Map(); // entry -> { resolved: Set<ip>, at: number }

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms)),
  ]);
}

async function resolveDomainCached(entry) {
  const cached = _resolveCache.get(entry);
  if (cached && (Date.now() - cached.at) < RESOLVE_CACHE_TTL_MS) {
    return cached.resolved;
  }

  let resolved = new Set();
  try {
    const addrs = await withTimeout(dns.resolve4(entry), RESOLVE_TIMEOUT_MS);
    for (const a of addrs) resolved.add(a);
  } catch(e) {
    // Fallback: dns.lookup (uses system resolver).
    try {
      const all = await withTimeout(dns.lookup(entry, { all: true, family: 4 }), RESOLVE_TIMEOUT_MS);
      for (const r of all) resolved.add(r.address);
    } catch(e2) {
      console.error(`whitelist: resolve ${entry} failed`);
    }
  }

  _resolveCache.set(entry, { resolved, at: Date.now() });
  return resolved;
}

// Resolves whitelist entries to a Set of IPs/CIDRs. For domains with multiple IPs
// (typical for CDN), expands each IP to its /24 subnet — matches VPN.py behaviour.
async function resolveWhitelistEntries(entries) {
  const ips = new Set();
  const domains = [];

  for (const raw of entries) {
    const entry = cleanWhitelistEntry(raw);
    if (!entry) continue;

    if (isIpOrCidr(entry)) {
      ips.add(entry);
      continue;
    }
    domains.push(entry);
  }

  // Resolve every domain concurrently instead of one at a time.
  const results = await Promise.all(domains.map(d => resolveDomainCached(d)));

  for (const resolved of results) {
    // Expand every resolved IP to its /24 subnet. This helps with CDNs where
    // a hostname resolves to a rotating set of IPs within the same /24 block.
    for (const ip of resolved) {
      const parts = ip.split('.');
      if (parts.length === 4) {
        ips.add(`${parts[0]}.${parts[1]}.${parts[2]}.0/24`);
      }
    }
  }
  return ips;
}

// Parses "a.b.c.d/nn" or "a.b.c.d" into { ip: BigInt, bits: number }.
// Returns null on invalid input.
function parseCidr(s) {
  const [ipStr, bitsStr] = s.split('/');
  const parts = ipStr.split('.');
  if (parts.length !== 4) return null;
  let ip = 0n;
  for (const p of parts) {
    const n = parseInt(p, 10);
    if (isNaN(n) || n < 0 || n > 255) return null;
    ip = (ip << 8n) | BigInt(n);
  }
  let bits = bitsStr === undefined ? 32 : parseInt(bitsStr, 10);
  if (isNaN(bits) || bits < 0 || bits > 32) return null;
  // Normalise: zero out host bits.
  const mask = bits === 0 ? 0n : ((1n << 32n) - 1n) ^ ((1n << BigInt(32 - bits)) - 1n);
  return { ip: ip & mask, bits };
}

function cidrToString({ ip, bits }) {
  const a = Number((ip >> 24n) & 0xffn);
  const b = Number((ip >> 16n) & 0xffn);
  const c = Number((ip >> 8n) & 0xffn);
  const d = Number(ip & 0xffn);
  return `${a}.${b}.${c}.${d}/${bits}`;
}

// Splits a CIDR into two halves (one bit more specific).
function splitCidr({ ip, bits }) {
  if (bits >= 32) return null;
  const childBits = bits + 1;
  const halfSize = 1n << BigInt(32 - childBits);
  return [
    { ip: ip, bits: childBits },
    { ip: ip + halfSize, bits: childBits },
  ];
}

// True if `a` fully contains `b`.
function cidrContains(a, b) {
  if (a.bits > b.bits) return false;
  const mask = a.bits === 0 ? 0n : ((1n << 32n) - 1n) ^ ((1n << BigInt(32 - a.bits)) - 1n);
  return (b.ip & mask) === a.ip;
}

// Subtracts `excluded` (array of CIDRs) from `network` (CIDR).
// Returns array of CIDRs that cover `network` minus all `excluded`.
// Mirrors Python's ipaddress.address_exclude().
function subtractCidrs(network, excluded) {
  let result = [network];
  for (const exc of excluded) {
    const next = [];
    for (const n of result) {
      if (!cidrContains(n, exc) && !cidrContains(exc, n)) {
        // No overlap.
        next.push(n);
        continue;
      }
      if (cidrContains(exc, n)) {
        // exc fully covers n → n disappears.
        continue;
      }
      // n contains exc — split n in halves, recurse by pushing back.
      let queue = [n];
      while (queue.length) {
        const cur = queue.pop();
        if (cur.ip === exc.ip && cur.bits === exc.bits) {
          // Exactly equals the excluded block → drop.
          continue;
        }
        if (!cidrContains(cur, exc)) {
          // The half doesn't contain exc → keep it whole.
          next.push(cur);
          continue;
        }
        // The half still contains exc → split further.
        const halves = splitCidr(cur);
        if (!halves) { next.push(cur); continue; }
        queue.push(halves[0], halves[1]);
      }
    }
    result = next;
  }
  // Sort by numeric IP for stable output.
  result.sort((a, b) => (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0));
  return result;
}

// Extracts Endpoint IPs from a config so we never accidentally exclude the
// VPN server itself (tunnel would fail to connect).
function extractEndpointIPs(confText) {
  const ips = [];
  const re = /^\s*Endpoint\s*=\s*([^\s:]+)/gim;
  let m;
  while ((m = re.exec(confText)) !== null) {
    if (m[1] && /^[\d.]+$/.test(m[1])) ips.push(m[1]);
  }
  return ips;
}

// Modifies .conf text: subtracts resolved whitelist IPs from AllowedIPs = 0.0.0.0/0.
// Returns modified text, or original if nothing to do / on error.
async function applyWhitelistToConfig(confText, whitelistEntries) {
  if (!whitelistEntries || whitelistEntries.length === 0) return confText;

  const excludedSet = await resolveWhitelistEntries(whitelistEntries);
  if (excludedSet.size === 0) return confText;

  // Never exclude the VPN endpoint itself.
  const endpointIPs = extractEndpointIPs(confText);
  for (const ep of endpointIPs) excludedSet.delete(ep);

  // Parse to CIDR objects.
  const excluded = [];
  for (const s of excludedSet) {
    const c = parseCidr(s.includes('/') ? s : `${s}/32`);
    if (c) excluded.push(c);
  }
  if (excluded.length === 0) return confText;

  // Replace AllowedIPs lines containing 0.0.0.0/0.
  const lines = confText.split(/\r?\n/);
  let modified = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const stripped = line.trim();
    if (!/^allowedips\s*=/i.test(stripped)) continue;
    const value = stripped.split('=', 2)[1] || '';
    const nets = value.split(',').map(n => n.trim()).filter(Boolean);

    const out = [];
    for (const n of nets) {
      if (n === '0.0.0.0/0') {
        const sub = subtractCidrs(parseCidr('0.0.0.0/0'), excluded);
        out.push(...sub.map(cidrToString));
        modified = true;
      } else {
        out.push(n);
      }
    }
    lines[i] = 'AllowedIPs = ' + out.join(', ');
  }
  if (!modified) return confText;
  return lines.join('\n');
}

// ─── Autostart (Registry) ────────────────────────────────

function setAutostart(enabled) {
  const exePath = process.execPath;
  try {
    if (enabled) {
      // Task Scheduler is required because the app runs as Administrator
      // (requireAdministrator in package.json). Registry HKCU\Run cannot
      // elevate UAC, so the app would silently fail to start on boot.
      const { execFileSync } = require('child_process');
      // Delete first to avoid "already exists" error.
      try { execFileSync('schtasks', ['/Delete', '/TN', TASK_NAME, '/F'], { stdio: 'pipe' }); } catch(e) {}
      execFileSync('schtasks', [
        '/Create',
        '/TN', TASK_NAME,
        '/TR', `"${exePath}"`,
        '/SC', 'ONLOGON',
        '/RL', 'HIGHEST',
        '/F',
      ], { stdio: 'pipe' });
    } else {
      const { execFileSync } = require('child_process');
      try { execFileSync('schtasks', ['/Delete', '/TN', TASK_NAME, '/F'], { stdio: 'pipe' }); } catch(e) {}
    }
  } catch(e) {
    console.error('setAutostart error:', e);
  }
}

let _autostartCache = null;

function getAutostartEnabled() {
  if (_autostartCache !== null) return _autostartCache;
  try {
    const { execFileSync } = require('child_process');
    execFileSync('schtasks', ['/Query', '/TN', TASK_NAME], { stdio: 'pipe' });
    _autostartCache = true;
  } catch(e) {
    _autostartCache = false;
  }
  return _autostartCache;
}

// ─── DPAPI via Go helper ─────────────────────────────────

function dpapiEncrypt(plaintext) {
  return new Promise((resolve, reject) => {
    const child = spawn(TUNNEL_EXE, ['dpapi-encrypt']);
    let out = '', err = '';
    child.stdout.on('data', (d) => out += d);
    child.stderr.on('data', (d) => err += d);
    child.on('close', (code) => {
      if (code === 0) resolve(out.trim());
      else reject(new Error(err || 'dpapi-encrypt failed'));
    });
    child.stdin.write(plaintext);
    child.stdin.end();
  });
}

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
    if (keytar) {
      await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_TOKEN_ACCOUNT, token);
      // Remove legacy file if it exists
      try { fs.unlinkSync(TOKEN_FILE); } catch(e) {}
    } else {
      const encrypted = await dpapiEncrypt(token);
      fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.writeFileSync(TOKEN_FILE, encrypted, 'utf-8');
    }
  } catch(e) {
    console.error('saveToken error:', e);
  }
}

async function loadToken() {
  try {
    if (keytar) {
      // Try keytar first
      const val = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_TOKEN_ACCOUNT);
      if (val) return val;
      // Migrate from legacy DPAPI file
      if (fs.existsSync(TOKEN_FILE)) {
        const encrypted = fs.readFileSync(TOKEN_FILE, 'utf-8').trim();
        if (encrypted) {
          const plain = await dpapiDecrypt(encrypted);
          if (plain) {
            await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_TOKEN_ACCOUNT, plain);
            try { fs.unlinkSync(TOKEN_FILE); } catch(e) {}
            return plain;
          }
        }
      }
      return null;
    } else {
      if (!fs.existsSync(TOKEN_FILE)) return null;
      const encrypted = fs.readFileSync(TOKEN_FILE, 'utf-8').trim();
      if (!encrypted) return null;
      return (await dpapiDecrypt(encrypted)) || null;
    }
  } catch(e) {
    console.error('loadToken error:', e);
    return null;
  }
}

function deleteToken() {
  if (keytar) {
    keytar.deletePassword(KEYTAR_SERVICE, KEYTAR_TOKEN_ACCOUNT).catch(() => {});
  }
  try { fs.unlinkSync(TOKEN_FILE); } catch(e) {}
}

// ─── Config storage (DPAPI) ──────────────────────────────

async function saveConfig(confText) {
  try {
    if (keytar) {
      await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_CONFIG_ACCOUNT, confText);
      try { fs.unlinkSync(CONFIG_FILE); } catch(e) {}
    } else {
      const encrypted = await dpapiEncrypt(confText);
      fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.writeFileSync(CONFIG_FILE, encrypted, 'utf-8');
    }
    return true;
  } catch(e) {
    console.error('saveConfig error:', e);
    return false;
  }
}

async function loadConfig() {
  try {
    if (keytar) {
      const val = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_CONFIG_ACCOUNT);
      if (val) return val;
      // Migrate from legacy DPAPI file
      if (fs.existsSync(CONFIG_FILE)) {
        const encrypted = fs.readFileSync(CONFIG_FILE, 'utf-8').trim();
        if (encrypted) {
          const plain = await dpapiDecrypt(encrypted);
          if (plain) {
            await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_CONFIG_ACCOUNT, plain);
            try { fs.unlinkSync(CONFIG_FILE); } catch(e) {}
            return plain;
          }
        }
      }
      return null;
    } else {
      if (!fs.existsSync(CONFIG_FILE)) return null;
      const encrypted = fs.readFileSync(CONFIG_FILE, 'utf-8').trim();
      if (!encrypted) return null;
      return (await dpapiDecrypt(encrypted)) || null;
    }
  } catch(e) {
    console.error('loadConfig error:', e);
    return null;
  }
}

function hasConfig() {
  if (keytar) {
    // Can't check synchronously — caller must use loadConfig() !== null.
    // For the sync check we fall back to file existence as a hint.
    // The real check happens in config:exists IPC (made async below).
    return fs.existsSync(CONFIG_FILE) || _keytarConfigCached;
  }
  return fs.existsSync(CONFIG_FILE);
}

let _keytarConfigCached = false; // set after first successful loadConfig()

function deleteConfigFile() {
  if (keytar) {
    keytar.deletePassword(KEYTAR_SERVICE, KEYTAR_CONFIG_ACCOUNT).catch(() => {});
    _keytarConfigCached = false;
  }
  try { fs.unlinkSync(CONFIG_FILE); } catch(e) {}
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
      enabled: !isConnecting && hasConfig(),
      click: async () => {
        if (isOn) {
          updateTrayIcon('connecting');
          if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('vpn:autoconnecting', { reason: 'disconnecting' });
          try { await tunnelExec('stop'); } catch(e) {}
          deleteConnectTime();
          updateTrayIcon('off');
          showNotification('KitoFtorVPN', 'VPN отключён', true);
          if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('vpn:autoconnected', { ok: false });
        } else {
          updateTrayIcon('connecting');
          if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('vpn:autoconnecting');
          try {
            let conf = await loadConfig();
            if (conf) {
              const s = loadSettings();
              if (Array.isArray(s.whitelist) && s.whitelist.length > 0) {
                try { conf = await applyWhitelistToConfig(conf, s.whitelist); } catch(e) {}
              }
              await tunnelStartStdin(conf);
              saveConnectTime();
              updateTrayIcon('on');
              showNotification('KitoFtorVPN', 'VPN подключён', true);
              if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('vpn:autoconnected', { ok: true });
            }
          } catch(e) {
            updateTrayIcon('off');
            if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('vpn:autoconnected', { ok: false, error: e.message });
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

  // Auto-connect if setting enabled.
  // NOTE: we deliberately do NOT use the synchronous hasConfig() helper here.
  // When configs are stored via keytar (the normal path), hasConfig() relies
  // on _keytarConfigCached, which is only warmed up after the renderer calls
  // config:exists — i.e. *after* this point on a fresh start. That made
  // autoconnect silently never fire even with a real saved config and both
  // toggles correctly enabled. loadConfig() itself awaits keytar directly,
  // so we check the actual config up front instead.
  if (settings.autoconnect && (cachedToken || isGuest)) {
    // Notify renderer as soon as the window is ready so it shows "Подключение..."
    // immediately — before the tunnel actually starts.
    mainWindow.webContents.once('did-finish-load', () => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('vpn:autoconnecting');
      }
    });

    setTimeout(async () => {
      try {
        // If the service already has a tunnel up (e.g. it survived a
        // Windows Fast Startup "shutdown" that didn't actually tear the
        // session down — the whole reason this got fixed), don't tear it
        // down just to bring up an identical one. Just adopt its real
        // connectStart and reflect "on" in the UI.
        const already = await tunnelStatusFull();
        if (already.state === 'RUNNING') {
          if (already.connectStartMs) saveConnectTime(already.connectStartMs);
          updateTrayIcon('on');
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('vpn:autoconnected', { ok: true });
          }
          return;
        }

        let conf = await loadConfig();
        if (conf) {
          _keytarConfigCached = true; // we just confirmed a config exists — keep hasConfig() in sync
          if (Array.isArray(settings.whitelist) && settings.whitelist.length > 0) {
            try { conf = await applyWhitelistToConfig(conf, settings.whitelist); } catch(e) {}
          }
          updateTrayIcon('connecting');
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('vpn:autoconnecting');
          }
          await tunnelStartStdin(conf);
          saveConnectTime();
          updateTrayIcon('on');
          showNotification('KitoFtorVPN', 'VPN подключён', true);
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('vpn:autoconnected', { ok: true });
          }
        } else {
          // No config to connect with — tell the renderer to fall back to
          // the normal "off" state instead of being stuck on "Подключение...".
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('vpn:autoconnected', { ok: false });
          }
        }
      } catch(e) {
        console.error('autoconnect error:', e);
        updateTrayIcon('off');
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('vpn:autoconnected', { ok: false, error: e.message });
        }
      }
    }, 2000);
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
    const actuallyEnabled = getAutostartEnabled();
    if (wantAutostart !== actuallyEnabled) {
      setAutostart(wantAutostart);
      _autostartCache = null;
    }
  } catch(e) {
    console.error('autostart re-sync error:', e);
  }

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
// separately above by powerMonitor.setShutdownHandler, since Windows
// doesn't reliably wait for before-quit to finish in that case — this
// handler covers the remaining "app is quitting but Windows itself isn't"
// paths, going through the same stopTunnelOnExit() so both can't drift.
let beforeQuitHandled = false;
app.on('before-quit', (event) => {
  if (beforeQuitHandled) return;
  beforeQuitHandled = true;
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
  const settingsHeight = 615;
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

async function startAuthServer() {
  if (authServer) return authPort;
  authPort = await findFreePort();

  return new Promise((resolve) => {
    authServer = http.createServer(async (req, res) => {
      const url = new URL(req.url, `http://localhost:${authPort}`);
      if (url.pathname === '/callback') {
        const token = url.searchParams.get('token');
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
          setTimeout(() => {
            if (authServer) { authServer.close(); authServer = null; }
          }, 2000);
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
  shell.openExternal(`${API_BASE}/login?desktop=1&port=${port}`);
  return { ok: true };
});

ipcMain.handle('auth:register', async () => {
  const port = await startAuthServer();
  shell.openExternal(`${API_BASE}/register?desktop=1&port=${port}`);
  return { ok: true };
});

ipcMain.handle('auth:google', async () => {
  const port = await startAuthServer();
  shell.openExternal(`${API_BASE}/auth/google?desktop=1&port=${port}`);
  return { ok: true };
});

ipcMain.handle('auth:telegram', async () => {
  const port = await startAuthServer();
  shell.openExternal(`${API_BASE}/auth/telegram?desktop=1&port=${port}`);
  return { ok: true };
});

ipcMain.handle('auth:logout', async () => {
  cachedToken = null;
  isGuest = false;
  deleteToken();
  deleteGuestMode();
  try { await tunnelExec('stop'); } catch(e) {}
  updateTrayIcon('off');
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
  try { await tunnelExec('stop'); } catch(e) {}
  updateTrayIcon('off');
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
  deleteGuestMode();
  try { await tunnelExec('stop'); } catch(e) {}
  updateTrayIcon('off');
  if (mainWindow) {
    resizeWindowFor('login');
    mainWindow.loadFile('ui/login.html');
  }
  return { ok: true };
});

ipcMain.handle('auth:isGuest', () => isGuest);
ipcMain.handle('auth:getToken', () => cachedToken || null);

// ─── IPC: API proxy (subscription status) ────────────────

ipcMain.handle('api:fetch', async (event, endpoint) => {
  if (!cachedToken) return { error: 'no_token' };
  try {
    return new Promise((resolve) => {
      const url = `${API_BASE}${endpoint}`;
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
    const saved = await saveConfig(confText);
    if (!saved) return { error: 'Не удалось сохранить конфигурацию.' };
    _keytarConfigCached = true;
    return { ok: true };
  } catch(e) {
    return { error: 'Не удалось прочитать файл.' };
  }
});

ipcMain.handle('config:exists', async () => {
  if (keytar) {
    const val = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_CONFIG_ACCOUNT).catch(() => null);
    _keytarConfigCached = !!val;
    return _keytarConfigCached;
  }
  return hasConfig();
});

ipcMain.handle('config:delete', async () => {
  try { await tunnelExec('stop'); } catch(e) {}
  deleteConfigFile();
  updateTrayIcon('off');
  return { ok: true };
});

// ─── IPC: Settings ───────────────────────────────────────

ipcMain.handle('settings:get', () => loadSettings());

ipcMain.handle('settings:set', (event, newSettings) => {
  const current = loadSettings();
  const merged = { ...current, ...newSettings };
  saveSettings(merged);

  // Apply autostart change
  if (newSettings.autostart !== undefined) {
    setAutostart(newSettings.autostart);
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
  const merged = { ...current, whitelist: cleaned };
  saveSettings(merged);

  let restarted = false;
  try {
    const st = await tunnelStatus().catch(() => 'STOPPED');
    if (st === 'RUNNING') {
      // Notify renderer so it can show a busy state and disable the button.
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('vpn:reconnecting', { reason: 'whitelist' });
      }
      updateTrayIcon('connecting');

      await tunnelExec('stop').catch(() => {});
      let conf = await loadConfig();
      if (conf) {
        if (cleaned.length > 0) {
          try { conf = await applyWhitelistToConfig(conf, cleaned); } catch(e) {}
        }
        await tunnelStartStdin(conf);
        saveConnectTime();
        updateTrayIcon('on');
        restarted = true;
      } else {
        updateTrayIcon('off');
      }

      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('vpn:reconnected', { ok: restarted });
      }
    }
  } catch(e) {
    console.error('whitelist:save restart error:', e);
    updateTrayIcon('off');
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('vpn:reconnected', { ok: false, error: e.message });
    }
  }

  return { ok: true, count: cleaned.length, restarted };
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

// ─── IPC: Tunnel management ──────────────────────────────

// Technical errors from the tunnel process (Go/Windows API) come back in
// English (e.g. "SCM connect failed", "CreateTUN failed: ..."). Showing
// that directly in the UI looks broken to a non-technical user. This maps
// the few cases we can give useful advice for, and otherwise replaces the
// raw text with one calm, generic message in Russian — the real text is
// still logged to debug.log for support purposes.
function friendlyTunnelError(message) {
  const text = String(message || '');
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

function tunnelExec(command, arg) {
  return new Promise((resolve, reject) => {
    const args = arg ? [command, arg] : [command];
    execFile(TUNNEL_EXE, args, { timeout: 40000 }, (error, stdout, stderr) => {
      if (error) reject(new Error(stderr || stdout || error.message));
      else resolve(stdout.trim());
    });
  });
}

// kitoftor-tunnel's Windows service keeps a small control channel open on
// 127.0.0.1:47291 (see kitoftor-tunnel/main.go, controlAddr). The CLI's own
// "status" command just opens a TCP connection to that same port, sends
// "STATUS <base64>\n" and prints back whatever it gets ("RUNNING <ts>" or
// "STOPPED").
//
// The renderer polls vpn:status every 3s (ui/main.html, pollVPN) to keep the
// connect/disconnect button and the tray icon in sync. Previously every one
// of those polls went through tunnelExec('status'), i.e. spawning a brand
// new kitoftor-tunnel.exe process just to make that same TCP call — visible
// on Windows as a recurring "app is busy" cursor every few seconds even
// while sitting on the desktop with the VPN window minimized. Talking to
// the control port directly from Node (same protocol, no extra process)
// removes that spawn entirely. Falls back to the old execFile path only if
// the raw socket call fails (e.g. for some reason the port handshake
// changes) so behaviour stays identical on the error path.
const CONTROL_HOST = '127.0.0.1';
const CONTROL_PORT = 47291;

function tunnelStatusDirect(timeoutMs = 2500) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: CONTROL_HOST, port: CONTROL_PORT });
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
      // Empty body, same as the CLI: base64("") === "".
      socket.write('STATUS \n');
    });

    socket.on('data', (chunk) => {
      buf += chunk.toString('utf-8');
      if (buf.includes('\n')) {
        const line = buf.split('\n')[0].trim();
        finish(resolve, parseStatusLine(line));
      }
    });

    socket.on('end', () => {
      // Service closes the connection right after writing the reply; if we
      // got a full line in 'data' we've already resolved above, this is
      // just the no-trailing-newline edge case.
      if (!settled) finish(resolve, parseStatusLine(buf.trim()));
    });
  });
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

async function tunnelStatusFull() {
  try {
    return await tunnelStatusDirect();
  } catch (e) {
    // Control channel not reachable (service not installed/started yet) or
    // some unexpected hiccup — fall back to the CLI exactly like before.
    try {
      const out = await tunnelExec('status');
      return parseStatusLine(out.trim());
    } catch (e2) {
      return { state: 'STOPPED', connectStartMs: null };
    }
  }
}

// Extract endpoint IP from .conf content (e.g. "Endpoint = 1.2.3.4:49792" -> "1.2.3.4")
function tunnelStartStdin(configContent) {
  return new Promise((resolve, reject) => {
    const child = spawn(TUNNEL_EXE, ['start-stdin'], { timeout: 40000 });
    let out = '', err = '';
    child.stdout.on('data', (d) => out += d);
    child.stderr.on('data', (d) => err += d);
    child.on('close', (code) => {
      if (code === 0 && out.trim() === 'OK') resolve('OK');
      else reject(new Error(err || out || 'start-stdin failed'));
    });
    child.stdin.write(configContent);
    child.stdin.end();
  });
}

ipcMain.handle('vpn:connect', async () => {
  try {
    let conf = await loadConfig();
    if (!conf) return { error: 'Конфигурация повреждена или не найдена. Загрузите .conf файл заново.' };

    // Apply whitelist (split tunneling) if enabled.
    const settings = loadSettings();
    if (Array.isArray(settings.whitelist) && settings.whitelist.length > 0) {
      try {
        conf = await applyWhitelistToConfig(conf, settings.whitelist);
      } catch(e) {
        console.error('whitelist apply error:', e);
      }
    }

    updateTrayIcon('connecting');
    const result = await tunnelStartStdin(conf);
    saveConnectTime();
    updateTrayIcon('on');
    return { ok: true, result };
  } catch(e) {
    updateTrayIcon('off');
    return { error: friendlyTunnelError(e.message) };
  }
});

ipcMain.handle('vpn:disconnect', async () => {
  try {
    const result = await tunnelExec('stop');
    deleteConnectTime();
    updateTrayIcon('off');
    return { ok: true, result };
  } catch(e) {
    return { error: friendlyTunnelError(e.message) };
  }
});

ipcMain.handle('vpn:status', async () => {
  try {
    const full = await tunnelStatusFull();
    const state = full.state === 'RUNNING' ? 'on' : 'off';
    if (state === 'off') {
      deleteConnectTime();
    } else {
      // Resync against the service's own connectStart on every poll
      // (every 3s from the renderer) instead of trusting whatever's
      // sitting in connect_time.dat. This is what makes the timer
      // self-correct even if a previous shutdown didn't get a chance to
      // clear the file: the service is ground truth, the file is just a
      // local cache of it for the renderer to read without a service
      // round-trip on every tick.
      if (full.connectStartMs) {
        const cached = loadConnectTime();
        if (cached !== full.connectStartMs) saveConnectTime(full.connectStartMs);
      }
    }
    if (state !== vpnStateForTray) {
      // Unexpected drop — was running, now stopped
      if (vpnStateForTray === 'on' && state === 'off') {
        showNotification('KitoFtorVPN', 'VPN отключён', true);
      }
      updateTrayIcon(state);
    }
    return { status: full.state };
  } catch(e) {
    deleteConnectTime();
    if (vpnStateForTray !== 'off') {
      showNotification('KitoFtorVPN', 'VPN отключён', true);
      updateTrayIcon('off');
    }
    return { status: 'STOPPED' };
  }
});

ipcMain.handle('vpn:getConnectTime', () => loadConnectTime());

// ─── IPC: Subscription expiry notification ───────────────

let subExpiryNotifShown = false; // show once per app session

ipcMain.handle('notify:subExpiring', (event, daysLeft) => {
  if (subExpiryNotifShown) return;
  subExpiryNotifShown = true;
  const msg = daysLeft <= 0 ? 'Подписка истекает сегодня'
    : daysLeft === 1 ? 'Подписка заканчивается завтра'
    : `Подписка заканчивается через ${daysLeft} дн.`;
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

ipcMain.handle('app:openExternal', (event, url) => { shell.openExternal(url); });
