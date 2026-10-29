'use strict';

const { contextBridge, ipcRenderer } = require('electron');

// Безопасный мост: UI вызывает только эти методы, прямого доступа к Node нет.
contextBridge.exposeInMainWorld('lab', {
  scanAll: (url, opts) => ipcRenderer.invoke('scan:all', url, opts),
  scanHeaders: (url) => ipcRenderer.invoke('scan:headers', url),
  scanTls: (url) => ipcRenderer.invoke('scan:tls', url),
  scanXss: (url, opts) => ipcRenderer.invoke('scan:xss', url, opts),
  scanExposed: (url) => ipcRenderer.invoke('scan:exposed', url),
  scanCookies: (url) => ipcRenderer.invoke('scan:cookies', url),
  scanSqli: (url, opts) => ipcRenderer.invoke('scan:sqli', url, opts),
  scanPorts: (url) => ipcRenderer.invoke('scan:ports', url),
  scanAdmin: (url, opts) => ipcRenderer.invoke('scan:admin', url, opts),
  scanFingerprint: (url, opts) => ipcRenderer.invoke('scan:fingerprint', url, opts),
});
