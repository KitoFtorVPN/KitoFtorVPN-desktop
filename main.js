const { app, BrowserWindow, ipcMain, shell, dialog, Tray, Menu, nativeImage, screen, Notification } = require('electron');
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

const API_BASE = 'https://my.kitoftorvpn.fun';
const TUNNEL_EXE = app.isPackaged
  ? path.join(process.resourcesPath, 'bin', 'kitoftor-tunnel.exe')
  : path.join(__dirname, 'bin', 'kitoftor-tunnel.exe');
const DATA_DIR = app.getPath('userData');
const TOKEN_FILE = path.join(DATA_DIR, 'session.dat');
const CONFIG_FILE = path.join(DATA_DIR, 'config.dat');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const CONNECT_TIME_FILE = path.join(DATA_DIR, 'connect_time.dat');
const TASK_NAME = 'KitoFtorVPNAutostart';

function showNotification(title, body, onlyWhenHidden = false) {
  if (!Notification.isSupported()) return;
  if (onlyWhenHidden && mainWindow && !mainWindow.isDestroyed() && mainWindow.isVisible()) return;
  const icon = (typeof APP_ICON !== 'undefined') ? APP_ICON : undefined;
  new Notification({ title, body, icon, silent: true }).show();
}

// Required for Windows toast notifications to work (both dev and packaged).
app.setAppUserModelId('fun.kitoftorvpn.desktop');

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
      return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf-8'));
    }
  } catch(e) {}
  return { autostart: false, autoconnect: false, whitelist: [] };
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

// Resolves whitelist entries to a Set of IPs/CIDRs. For domains with multiple IPs
// (typical for CDN), expands each IP to its /24 subnet — matches VPN.py behaviour.
async function resolveWhitelistEntries(entries) {
  const ips = new Set();
  for (const raw of entries) {
    const entry = cleanWhitelistEntry(raw);
    if (!entry) continue;

    if (isIpOrCidr(entry)) {
      ips.add(entry);
      continue;
    }

    // Domain — resolve A records (IPv4 only for now).
    let resolved = new Set();
    try {
      const addrs = await dns.resolve4(entry);
      for (const a of addrs) resolved.add(a);
    } catch(e) {
      // Fallback: dns.lookup (uses system resolver).
      try {
        const all = await dns.lookup(entry, { all: true, family: 4 });
        for (const r of all) resolved.add(r.address);
      } catch(e2) {
        console.error(`whitelist: resolve ${entry} failed`);
      }
    }

    if (resolved.size === 0) continue;

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

function getAutostartEnabled() {
  try {
    const { execFileSync } = require('child_process');
    execFileSync('schtasks', ['/Query', '/TN', TASK_NAME], { stdio: 'pipe' });
    return true;
  } catch(e) {
    return false;
  }
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
    const encrypted = await dpapiEncrypt(token);
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(TOKEN_FILE, encrypted, 'utf-8');
  } catch(e) {
    console.error('saveToken error:', e);
  }
}

async function loadToken() {
  try {
    if (!fs.existsSync(TOKEN_FILE)) return null;
    const encrypted = fs.readFileSync(TOKEN_FILE, 'utf-8').trim();
    if (!encrypted) return null;
    return (await dpapiDecrypt(encrypted)) || null;
  } catch(e) {
    console.error('loadToken error:', e);
    return null;
  }
}

function deleteToken() {
  try { fs.unlinkSync(TOKEN_FILE); } catch(e) {}
}

// ─── Config storage (DPAPI) ──────────────────────────────

async function saveConfig(confText) {
  try {
    const encrypted = await dpapiEncrypt(confText);
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(CONFIG_FILE, encrypted, 'utf-8');
    return true;
  } catch(e) {
    console.error('saveConfig error:', e);
    return false;
  }
}

async function loadConfig() {
  try {
    if (!fs.existsSync(CONFIG_FILE)) return null;
    const encrypted = fs.readFileSync(CONFIG_FILE, 'utf-8').trim();
    if (!encrypted) return null;
    return (await dpapiDecrypt(encrypted)) || null;
  } catch(e) {
    console.error('loadConfig error:', e);
    return null;
  }
}

function hasConfig() {
  return fs.existsSync(CONFIG_FILE);
}

function deleteConfigFile() {
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
  // Stop the VPN tunnel before exiting — otherwise the Windows service
  // keeps running in the background and the user's traffic still goes
  // through VPN even though the app is closed.
  try {
    await tunnelExec('stop');
  } catch(e) {
    // Ignore — either tunnel wasn't running or already stopped.
  }
  deleteConnectTime();
  if (tray) { tray.destroy(); tray = null; }
  app.quit();
}

// ─── Window ──────────────────────────────────────────────

const LOGIN_SIZE = { width: 400, height: 520 };
const MAIN_SIZE = { width: 380, height: 560 };

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
  const startsOnMain = !!cachedToken;
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

  // Auto-connect if setting enabled
  if (settings.autoconnect && cachedToken && hasConfig()) {
    // Notify renderer as soon as the window is ready so it shows "Подключение..."
    // immediately — before the tunnel actually starts.
    mainWindow.webContents.once('did-finish-load', () => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('vpn:autoconnecting');
      }
    });

    setTimeout(async () => {
      try {
        let conf = await loadConfig();
        if (conf) {
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

// Second instance — show existing window
app.on('second-instance', () => showMainWindow());

app.whenReady().then(createWindow).then(() => {
  // Check for updates only in packaged app — in dev there's no published
  // release to compare against, and electron-updater throws on dev_app_update.yml missing.
  if (!app.isPackaged || !autoUpdater) return;
  try {
    autoUpdater.autoDownload = true;
    autoUpdater.autoInstallOnAppQuit = true;
    autoUpdater.on('error', (err) => console.error('updater:', err && err.message));
    autoUpdater.on('update-downloaded', (info) => {
      // Offer immediate restart; otherwise it installs on quit.
      dialog.showMessageBox(mainWindow, {
        type: 'info',
        buttons: ['Перезапустить сейчас', 'Позже'],
        defaultId: 0,
        cancelId: 1,
        title: 'Обновление готово',
        message: `Доступна новая версия ${info && info.version ? info.version : ''}`,
        detail: 'Обновление скачано. Перезапустите приложение, чтобы установить его.',
      }).then((r) => {
        if (r.response === 0) {
          isQuitting = true;
          setImmediate(() => autoUpdater.quitAndInstall());
        }
      }).catch(() => {});
    });
    // Delay a bit so the UI renders first, then check.
    setTimeout(() => {
      autoUpdater.checkForUpdatesAndNotify().catch(e => console.error('updater check:', e));
    }, 5000);
  } catch(e) {
    console.error('updater init:', e);
  }
});
app.on('window-all-closed', (e) => {
  // Don't quit — tray keeps running
});

// Guarantee tunnel stops on any exit path (Alt+F4 on a non-hidden window,
// OS shutdown, external kill). Normally quitApp() handles this, but this
// handler is the safety net.
let beforeQuitHandled = false;
app.on('before-quit', (event) => {
  if (beforeQuitHandled) return;
  beforeQuitHandled = true;
  event.preventDefault();
  (async () => {
    try { await tunnelExec('stop'); } catch(e) {}
    deleteConnectTime();
    app.exit(0);
  })();
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
  const settingsHeight = 600;
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
  if (mainWindow) {
    resizeWindowFor('main');
    mainWindow.loadFile('ui/main.html');
  }
  return { ok: true };
});

// Leave guest mode — back to login screen.
ipcMain.handle('auth:exitGuest', async () => {
  isGuest = false;
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
    return { ok: true };
  } catch(e) {
    return { error: 'Не удалось прочитать файл.' };
  }
});

ipcMain.handle('config:exists', () => hasConfig());

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
    const st = await tunnelExec('status').catch(() => 'STOPPED');
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

function saveConnectTime() {
  try {
    fs.writeFileSync(CONNECT_TIME_FILE, Date.now().toString(), 'utf-8');
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

function tunnelExec(command, arg) {
  return new Promise((resolve, reject) => {
    const args = arg ? [command, arg] : [command];
    execFile(TUNNEL_EXE, args, { timeout: 40000 }, (error, stdout, stderr) => {
      if (error) reject(new Error(stderr || stdout || error.message));
      else resolve(stdout.trim());
    });
  });
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
    return { error: e.message };
  }
});

ipcMain.handle('vpn:disconnect', async () => {
  try {
    const result = await tunnelExec('stop');
    deleteConnectTime();
    updateTrayIcon('off');
    return { ok: true, result };
  } catch(e) {
    return { error: e.message };
  }
});

ipcMain.handle('vpn:status', async () => {
  try {
    const result = await tunnelExec('status');
    const state = result === 'RUNNING' ? 'on' : 'off';
    if (state === 'off') deleteConnectTime();
    if (state !== vpnStateForTray) {
      // Unexpected drop — was running, now stopped
      if (vpnStateForTray === 'on' && state === 'off') {
        showNotification('KitoFtorVPN', 'VPN отключён', true);
      }
      updateTrayIcon(state);
    }
    return { status: result };
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
