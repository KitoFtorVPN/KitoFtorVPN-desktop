const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  // Auth
  login: () => ipcRenderer.invoke('auth:login'),
  register: () => ipcRenderer.invoke('auth:register'),
  google: () => ipcRenderer.invoke('auth:google'),
  telegram: () => ipcRenderer.invoke('auth:telegram'),
  logout: () => ipcRenderer.invoke('auth:logout'),
  sessionExpired: () => ipcRenderer.invoke('auth:sessionExpired'),
  guestLogin: () => ipcRenderer.invoke('auth:guestLogin'),
  exitGuest: () => ipcRenderer.invoke('auth:exitGuest'),
  isGuest: () => ipcRenderer.invoke('auth:isGuest'),
  getToken: () => ipcRenderer.invoke('auth:getToken'),

  // API (subscription status)
  fetch: (endpoint) => ipcRenderer.invoke('api:fetch', endpoint),

  // Config
  importConfig: () => ipcRenderer.invoke('config:import'),
  configExists: () => ipcRenderer.invoke('config:exists'),
  deleteConfig: () => ipcRenderer.invoke('config:delete'),

  // Settings
  getSettings: () => ipcRenderer.invoke('settings:get'),
  setSettings: (s) => ipcRenderer.invoke('settings:set', s),
  openSettings: () => ipcRenderer.invoke('settings:openWindow'),
  closeSettings: () => ipcRenderer.invoke('settings:closeWindow'),

  // Whitelist
  openWhitelist: () => ipcRenderer.invoke('whitelist:openWindow'),
  closeWhitelist: () => ipcRenderer.invoke('whitelist:closeWindow'),
  getWhitelist: () => ipcRenderer.invoke('whitelist:get'),
  saveWhitelist: (list) => ipcRenderer.invoke('whitelist:save', list),

  // VPN
  connect: () => ipcRenderer.invoke('vpn:connect'),
  disconnect: () => ipcRenderer.invoke('vpn:disconnect'),
  vpnStatus: () => ipcRenderer.invoke('vpn:status'),
  getConnectTime: () => ipcRenderer.invoke('vpn:getConnectTime'),

  // Window
  minimize: () => ipcRenderer.invoke('window:minimize'),
  close: () => ipcRenderer.invoke('window:close'),

  // External links
  openExternal: (url) => ipcRenderer.invoke('app:openExternal', url),
  // App info
  getVersion: () => ipcRenderer.invoke('app:getVersion'),
  notifySubExpiring: (days) => ipcRenderer.invoke('notify:subExpiring', days),

  // VPN events (main → renderer)
  onReconnecting: (cb) => {
    const listener = (_e, p) => cb(p);
    ipcRenderer.on('vpn:reconnecting', listener);
    return () => ipcRenderer.removeListener('vpn:reconnecting', listener);
  },
  onReconnected: (cb) => {
    const listener = (_e, p) => cb(p);
    ipcRenderer.on('vpn:reconnected', listener);
    return () => ipcRenderer.removeListener('vpn:reconnected', listener);
  },
  onAutoConnecting: (cb) => {
    const listener = (_e, p) => cb(p);
    ipcRenderer.on('vpn:autoconnecting', listener);
    return () => ipcRenderer.removeListener('vpn:autoconnecting', listener);
  },
  onAutoConnected: (cb) => {
    const listener = (_e, p) => cb(p);
    ipcRenderer.on('vpn:autoconnected', listener);
    return () => ipcRenderer.removeListener('vpn:autoconnected', listener);
  },
});
