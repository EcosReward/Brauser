'use strict';

const { app, BrowserWindow, ipcMain, session } = require('electron');
const path = require('path');
const scanners = require('./scanners');

const LAB_PARTITION = 'persist:lab';
let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1500,
    height: 950,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: '#0a0f1d',
    title: 'Brauser — лаборатория безопасности',
    // Тёмная системная полоска с кнопками свернуть/закрыть под дизайн.
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#0a0f1d',
      symbolColor: '#94a3b8',
      height: 40,
    },
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: true,
      sandbox: false,
      backgroundThrottling: false,
      spellcheck: false,
    },
  });

  mainWindow.setMenuBarVisibility(false);
  mainWindow.loadFile(path.join(__dirname, 'src', 'index.html'));
}

// HTTP через сессию webview: cookie после прохождения ddosfilter/Cloudflare.
function installSessionHttpClient() {
  const ses = session.fromPartition(LAB_PARTITION);

  scanners.setHttpClient(async (targetUrl, options = {}) => {
    const started = Date.now();
    const maxRedirects = options.maxRedirects === undefined ? 5 : options.maxRedirects;
    const limit = options.maxBytes || 512 * 1024;
    let current = targetUrl;
    let redirects = [];

    for (let hop = 0; hop <= maxRedirects; hop++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), options.timeout || 7000);
      let res;
      try {
        res = await ses.fetch(current, {
          method: options.method || 'GET',
          headers: {
            'User-Agent':
              'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8',
            ...(options.headers || {}),
          },
          body: options.body || undefined,
          redirect: 'manual',
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timer);
      }

      const headers = {};
      res.headers.forEach((value, key) => {
        const k = key.toLowerCase();
        if (headers[k]) {
          if (Array.isArray(headers[k])) headers[k].push(value);
          else headers[k] = [headers[k], value];
        } else {
          headers[k] = value;
        }
      });

      if ([301, 302, 303, 307, 308].includes(res.status) && headers.location && hop < maxRedirects) {
        const next = new URL(headers.location, current).toString();
        redirects.push(next);
        current = next;
        continue;
      }

      const buf = Buffer.from(await res.arrayBuffer());
      const sliced = buf.length > limit ? buf.subarray(0, limit) : buf;
      return {
        url: targetUrl,
        finalUrl: current,
        status: res.status,
        headers,
        body: sliced.toString('utf8'),
        bytes: buf.length,
        elapsed: Date.now() - started,
        redirectChain: redirects.length ? redirects : null,
      };
    }

    throw new Error('Слишком много редиректов');
  });
}

function wrap(fn) {
  return async (_event, ...args) => {
    try {
      return { ok: true, data: await fn(...args) };
    } catch (err) {
      return { ok: false, error: err && err.message ? err.message : String(err) };
    }
  };
}

ipcMain.handle('scan:all', wrap((url, opts) => scanners.scanAll(url, opts || {})));
ipcMain.handle('scan:headers', wrap((url, opts) => scanners.scanHeaders(url, opts || {})));
ipcMain.handle('scan:tls', wrap((url, opts) => scanners.scanTls(url, opts || {})));
ipcMain.handle('scan:xss', wrap((url, opts) => scanners.scanXss(url, opts || {})));
ipcMain.handle('scan:exposed', wrap((url, opts) => scanners.scanExposedFiles(url, opts || {})));
ipcMain.handle('scan:cookies', wrap((url, opts) => scanners.scanCookies(url, opts || {})));
ipcMain.handle('scan:sqli', wrap((url, opts) => scanners.scanSqlInjection(url, opts || {})));
ipcMain.handle('scan:ports', wrap((url, opts) => scanners.scanPorts(url, opts || {})));
ipcMain.handle('scan:admin', wrap((url, opts) => scanners.scanAdmin(url, opts || {})));
ipcMain.handle('scan:fingerprint', wrap((url, opts) => scanners.scanFingerprint(url, opts || {})));

app.whenReady().then(() => {
  installSessionHttpClient();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
