'use strict';

const { contextBridge, ipcRenderer } = require('electron');

// Безопасный мост: UI вызывает только эти методы, прямого доступа к Node нет.
contextBridge.exposeInMainWorld('lab', {
  scanAll: (url, opts) => ipcRenderer.invoke('scan:all', url, opts),
  scanHeaders: (url, opts) => ipcRenderer.invoke('scan:headers', url, opts),
  scanTls: (url, opts) => ipcRenderer.invoke('scan:tls', url, opts),
  scanXss: (url, opts) => ipcRenderer.invoke('scan:xss', url, opts),
  scanExposed: (url, opts) => ipcRenderer.invoke('scan:exposed', url, opts),
  scanCookies: (url, opts) => ipcRenderer.invoke('scan:cookies', url, opts),
  scanSqli: (url, opts) => ipcRenderer.invoke('scan:sqli', url, opts),
  scanPorts: (url, opts) => ipcRenderer.invoke('scan:ports', url, opts),
  scanAdmin: (url, opts) => ipcRenderer.invoke('scan:admin', url, opts),
  scanFingerprint: (url, opts) => ipcRenderer.invoke('scan:fingerprint', url, opts),
});
