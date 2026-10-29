'use strict';

const I18n = window.I18n;
function t(key, vars) {
  return I18n.t(key, vars);
}
function sevLabel(sev) {
  const map = {
    critical: t('sevCritical'),
    high: t('sevHigh'),
    medium: t('sevMedium'),
    low: t('sevLow'),
    info: t('sevInfo'),
  };
  return map[sev] || sev;
}
function applyStaticI18n() {
  document.documentElement.lang = I18n.getLang();
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const key = el.getAttribute('data-i18n');
    if (!key) return;
    if (el.tagName === 'TITLE') {
      document.title = t(key);
      return;
    }
    el.textContent = t(key);
  });
  document.querySelectorAll('[data-i18n-title]').forEach((el) => {
    const key = el.getAttribute('data-i18n-title');
    if (key) el.title = t(key);
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (key) el.placeholder = t(key);
  });
  const sel = document.getElementById('langSelect');
  if (sel) sel.value = I18n.getLang();
}
function setLanguage(lang) {
  const next = I18n.setLang(lang);
  try {
    localStorage.setItem('brauser.lang', next);
  } catch (err) {
    /* ignore */
  }
  applyStaticI18n();
  tabs.forEach((tab) => {
    tab.scanCache = null;
  });
  const tab = activeTab();
  if (tab) {
    restoreScanUiFromTab(tab);
    viewportStatus.textContent =
      tab.url && tab.url !== 'about:blank' ? t('tabLabel', { host: hostOf(tab.url) }) : t('newTab');
    if (!tab.scanBusy) payloadStatus.textContent = t('readyToScan');
  } else {
    resetScanUi(false);
  }
  updateCrawlUi();
  renderTabs();
}

const address = document.getElementById('address');
const activeMode = document.getElementById('activeMode');
const webviewHost = document.getElementById('webviewHost');
const tabsStrip = document.getElementById('tabsStrip');

const verdictEl = document.getElementById('verdict');
const verdictBadge = document.getElementById('verdictBadge');
const verdictLabel = document.getElementById('verdictLabel');
const verdictAdvice = document.getElementById('verdictAdvice');
const verdictUrl = document.getElementById('verdictUrl');
const verdictScoreNum = document.getElementById('verdictScoreNum');
const trustHint = document.getElementById('trustHint');
const metricRep = document.getElementById('metricRep');
const metricTls = document.getElementById('metricTls');
const metricVulns = document.getElementById('metricVulns');

const summaryEl = document.getElementById('summary');
const resultsEl = document.getElementById('results');
const loadingBar = document.getElementById('loadingBar');
const httpsBadge = document.getElementById('httpsBadge');
const httpsLabel = document.getElementById('httpsLabel');
const viewportStatus = document.getElementById('viewportStatus');
const wafBadge = document.getElementById('wafBadge');
const tlsFooter = document.getElementById('tlsFooter');
const payloadStatus = document.getElementById('payloadStatus');
const modulesProgress = document.getElementById('modulesProgress');
const auditLog = document.getElementById('auditLog');
const liveTag = document.getElementById('liveTag');
const crawlCount = document.getElementById('crawlCount');
const crawlList = document.getElementById('crawlList');

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const MODULE_KEYS = ['fingerprint', 'tls', 'headers', 'cookies', 'xss', 'sqli', 'ports', 'admin', 'exposed'];

// ---------------------------------------------------------------------------
// Вкладки
// ---------------------------------------------------------------------------

let tabs = [];
let activeTabId = null;
let nextTabId = 1;

function activeTab() {
  return tabs.find((t) => t.id === activeTabId) || null;
}

function activeView() {
  const t = activeTab();
  return t ? t.webview : null;
}

function originKey(url) {
  try {
    return new URL(url).origin.toLowerCase();
  } catch (err) {
    return String(url || '').toLowerCase();
  }
}

function cacheKey(url) {
  return originKey(url);
}

function tabById(id) {
  return tabs.find((t) => t.id === id) || null;
}

function isTabActive(tabOrId) {
  const id = typeof tabOrId === 'number' ? tabOrId : tabOrId && tabOrId.id;
  return id != null && id === activeTabId;
}

function getScanCache(tab) {
  const t = tab || activeTab();
  return t ? t.scanCache : null;
}

function clearScanCache(tab) {
  const t = tab || activeTab();
  if (t) t.scanCache = null;
}

function resetScanUi(clearCache, tab) {
  const t = tab || activeTab();
  if (clearCache !== false) clearScanCache(t);
  // Не трогаем чужую вкладку на экране.
  if (t && !isTabActive(t)) return;
  for (const key of MODULE_KEYS) setModuleState(key, 'idle', t('notChecked'));
  modulesProgress.textContent = '0 / ' + MODULE_KEYS.length;
  summaryEl.innerHTML = '';
  resultsEl.innerHTML =
    '<div class="placeholder">' + escapeHtml(t('resultsPlaceholder')) + '</div>';
  verdictEl.className = 'verdict verdict-idle';
  verdictBadge.textContent = '—';
  verdictScoreNum.textContent = '—';
  trustHint.textContent = t('waiting');
  verdictLabel.textContent = t('openSiteAndScan');
  verdictAdvice.textContent = t('autoScanOff');
  metricRep.textContent = '—';
  metricRep.className = 'metric-v';
  metricTls.textContent = '—';
  metricTls.className = 'metric-v cyan';
  metricVulns.textContent = '—';
  metricVulns.className = 'metric-v';
  wafBadge.textContent = 'WAF: —';
  wafBadge.className = 'waf-badge idle';
  tlsFooter.textContent = 'TLS —';
  document.querySelectorAll('.module-card').forEach((c) => c.classList.remove('active'));
}

function paintScanResult(tab, url, verdict, sections) {
  if (!isTabActive(tab)) return;
  setVerdict(verdict, url);
  verdictLabel.textContent = labelForVerdict(verdict);
  renderSummary(verdict.counts || {});
  applySectionsToModules(sections);
  updateTlsChrome(sections, url);
  const all = [];
  for (const key of Object.keys(sections || {})) all.push(...(sections[key].findings || []));
  renderFindings(all);
  updateCrawlUi();
}

function restoreScanUiFromTab(tab) {
  updateCrawlUi();
  if (tab.scanBusy) {
    setVerdictScanning(tab.url || tab.address || '');
    showScanning(t('tabScanRunning'));
    setLive(true);
    return;
  }
  setLive(false);
  const cache = tab.scanCache;
  if (!cache || !cache.sections) {
    resetScanUi(false, tab);
    updateCrawlUi();
    return;
  }
  if (cache.verdict) {
    paintScanResult(tab, cache.url, cache.verdict, cache.sections);
  } else {
    resetScanUi(false, tab);
    applySectionsToModules(cache.sections);
    const all = [];
    for (const key of Object.keys(cache.sections)) all.push(...(cache.sections[key].findings || []));
    renderFindings(all);
    verdictLabel.textContent = t('partialResults');
    updateCrawlUi();
  }
}

function pageKey(url) {
  try {
    const u = new URL(url);
    return (u.origin + u.pathname.replace(/\/$/, '') + u.search).toLowerCase();
  } catch (err) {
    return String(url || '').toLowerCase();
  }
}

function rememberPage(url, tabRef) {
  const tab = tabRef || activeTab();
  if (!tab || !url || url === 'about:blank') return;
  try {
    const u = new URL(url);
    if (!/^https?:$/i.test(u.protocol)) return;
    if (!tab.crawlOrigin) tab.crawlOrigin = u.origin;
    if (u.origin !== tab.crawlOrigin) return;
    if (!tab.visitedPages) tab.visitedPages = [];
    const key = pageKey(url);
    if (tab.visitedPages.some((p) => pageKey(p) === key)) return;
    tab.visitedPages.push(u.toString());
    if (tab.visitedPages.length > 40) tab.visitedPages.shift();
    if (isTabActive(tab)) updateCrawlUi();
  } catch (err) {
    /* ignore */
  }
}

function getCrawlPages(tabRef) {
  const tab = tabRef || activeTab();
  const cur = tab && isTabActive(tab) ? currentUrl() : tab && tab.url;
  const list = [];
  const seen = new Set();
  const add = (u) => {
    if (!u || u === 'about:blank') return;
    try {
      if (tab && tab.crawlOrigin && new URL(u).origin !== tab.crawlOrigin) return;
    } catch (err) {
      return;
    }
    const k = pageKey(u);
    if (seen.has(k)) return;
    seen.add(k);
    list.push(u);
  };
  add(cur);
  if (tab && tab.visitedPages) tab.visitedPages.forEach(add);
  list.sort((a, b) => Number(b.includes('?')) - Number(a.includes('?')));
  return list;
}

function updateCrawlUi() {
  const pages = getCrawlPages().filter((u) => u && u !== 'about:blank');
  crawlCount.textContent = String(pages.length);
  crawlList.innerHTML = '';
  pages.slice(0, 12).forEach((u) => {
    const row = document.createElement('div');
    row.className = 'crawl-item';
    row.title = u;
    try {
      const p = new URL(u);
      row.textContent = p.pathname + p.search || '/';
    } catch (err) {
      row.textContent = u;
    }
    crawlList.appendChild(row);
  });
  if (pages.length > 12) {
    const more = document.createElement('div');
    more.className = 'crawl-item';
    more.textContent = t('morePages', { n: pages.length - 12 });
    crawlList.appendChild(more);
  }
}

async function harvestLinksFromPage() {
  const v = activeView();
  const tab = activeTab();
  if (!v || !tab) return;
  const origin = tab.crawlOrigin || (currentUrl() ? new URL(currentUrl()).origin : null);
  if (!origin) {
    logLine('warn', t('openSiteFirst'));
    return;
  }
  try {
    const links = await v.executeJavaScript(
      `(function(){
        var origin = ${JSON.stringify(origin)};
        var out = [];
        var seen = {};
        var nodes = document.querySelectorAll('a[href]');
        for (var i = 0; i < nodes.length; i++) {
          try {
            var u = new URL(nodes[i].href, location.href);
            if (u.origin !== origin) continue;
            if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
            if (u.hash && u.pathname === location.pathname && !u.search) continue;
            var key = u.origin + u.pathname.replace(/\\/$/, '') + u.search;
            key = key.toLowerCase();
            if (seen[key]) continue;
            seen[key] = 1;
            out.push(u.origin + u.pathname + u.search);
            if (out.length >= 30) break;
          } catch (e) {}
        }
        return out;
      })()`
    );
    let added = 0;
    (links || []).forEach((u) => {
      const before = (tab.visitedPages || []).length;
      rememberPage(u, tab);
      if ((tab.visitedPages || []).length > before) added += 1;
    });
    rememberPage(currentUrl(), tab);
    updateCrawlUi();
    logLine('http', t('linksCollected', { added, total: getCrawlPages(tab).length }));
  } catch (err) {
    logLine('warn', t('linksFailed', { error: err && err.message ? err.message : err }));
  }
}

function getCachedSection(url, kind, tab) {
  const scanCache = getScanCache(tab);
  if (!scanCache || scanCache.urlKey !== cacheKey(url)) return null;
  return scanCache.sections[kind] || null;
}

function saveFullCache(tab, url, verdict, sections) {
  if (!tab) return;
  tab.scanCache = {
    urlKey: cacheKey(url),
    url,
    verdict,
    sections: Object.assign({}, sections),
  };
}

function saveSectionCache(tab, url, kind, data) {
  if (!tab) return;
  let scanCache = tab.scanCache;
  if (!scanCache || scanCache.urlKey !== cacheKey(url)) {
    scanCache = { urlKey: cacheKey(url), url, verdict: null, sections: {} };
  }
  scanCache.sections[kind] = data;
  tab.scanCache = scanCache;
}

function renderTabs() {
  tabsStrip.innerHTML = '';
  for (const tab of tabs) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'tab-pill' + (tab.id === activeTabId ? ' active' : '');
    btn.title = tab.url || t('newTab');
    btn.innerHTML =
      `<span class="tab-dot${tab.url && tab.url !== 'about:blank' ? ' on' : ''}"></span>` +
      `<span class="tab-title">${escapeHtml(tab.title || t('newTab'))}</span>` +
      `<span class="tab-close" title="${escapeHtml(t('closeTab'))}" data-close="${tab.id}">×</span>`;
    btn.addEventListener('click', (e) => {
      if (e.target && e.target.dataset && e.target.dataset.close) {
        e.stopPropagation();
        closeTab(Number(e.target.dataset.close));
        return;
      }
      activateTab(tab.id);
    });
    tabsStrip.appendChild(btn);
  }
}

function bindWebview(tab) {
  const view = tab.webview;
  view.addEventListener('did-start-loading', () => {
    if (tab.id !== activeTabId) return;
    loadingBar.classList.remove('hidden');
    payloadStatus.textContent = t('loadingPage');
    payloadStatus.className = '';
  });
  view.addEventListener('did-stop-loading', () => {
    const u = view.getURL();
    if (u && u !== 'about:blank') {
      tab.url = u;
      tab.title = hostOf(u);
      tab.address = u;
      rememberPage(u, tab);
      // Сбрасываем отчёт только если сменился сайт (origin), не при прогулке по страницам.
      if (tab.scanCache && tab.scanCache.urlKey !== originKey(u)) {
        tab.scanCache = null;
        if (isTabActive(tab)) resetScanUi(false, tab);
      }
    }
    if (!isTabActive(tab)) {
      renderTabs();
      return;
    }
    loadingBar.classList.add('hidden');
    if (u && u !== 'about:blank') {
      address.value = u;
      updateChromeForUrl(u);
      viewportStatus.textContent = t('domReady', { host: hostOf(u) });
      payloadStatus.textContent = t('readyToScan');
      payloadStatus.className = 'ok';
      updateCrawlUi();
    }
    renderTabs();
  });
  view.addEventListener('did-navigate', (e) => {
    if (!e.url || e.url === 'about:blank') return;
    tab.url = e.url;
    tab.title = hostOf(e.url);
    tab.address = e.url;
    try {
      const origin = new URL(e.url).origin;
      if (tab.crawlOrigin && tab.crawlOrigin !== origin) {
        tab.visitedPages = [];
        tab.crawlOrigin = origin;
        tab.scanCache = null;
        if (isTabActive(tab)) resetScanUi(false, tab);
      } else if (!tab.crawlOrigin) {
        tab.crawlOrigin = origin;
      }
    } catch (err) {
      /* ignore */
    }
    rememberPage(e.url, tab);
    if (isTabActive(tab)) {
      address.value = e.url;
      updateChromeForUrl(e.url);
      updateCrawlUi();
    }
    renderTabs();
  });
  view.addEventListener('did-navigate-in-page', (e) => {
    if (e.url) rememberPage(e.url, tab);
  });
  view.addEventListener('page-title-updated', (e) => {
    if (e.title) {
      tab.title = e.title.length > 28 ? e.title.slice(0, 26) + '…' : e.title;
      renderTabs();
    }
  });
}

function createTab(initialUrl) {
  const id = nextTabId++;
  const webview = document.createElement('webview');
  webview.setAttribute('partition', 'persist:lab');
  webview.setAttribute('allowpopups', '');
  webview.setAttribute('webpreferences', 'spellcheck=no, backgroundThrottling=false');
  webview.src = initialUrl || 'about:blank';
  webviewHost.insertBefore(webview, loadingBar);

  const tab = {
    id,
    title: initialUrl && initialUrl !== 'about:blank' ? hostOf(initialUrl) : t('newTab'),
    url: initialUrl || 'about:blank',
    address: initialUrl && initialUrl !== 'about:blank' ? initialUrl : '',
    scanCache: null,
    scanBusy: false,
    visitedPages: [],
    crawlOrigin: null,
    webview,
  };
  bindWebview(tab);
  tabs.push(tab);
  activateTab(id);
  return tab;
}

function activateTab(id) {
  const tab = tabs.find((t) => t.id === id);
  if (!tab) return;
  activeTabId = id;
  for (const t of tabs) {
    t.webview.classList.toggle('active', t.id === id);
  }
  address.value = tab.address || '';
  updateChromeForUrl(tab.url);
  restoreScanUiFromTab(tab);
  viewportStatus.textContent =
    tab.url && tab.url !== 'about:blank' ? t('tabLabel', { host: hostOf(tab.url) }) : t('newTab');
  renderTabs();
}

function closeTab(id) {
  if (tabs.length <= 1) {
    const only = tabs[0];
    only.webview.src = 'about:blank';
    only.url = 'about:blank';
    only.title = t('newTab');
    only.address = '';
    only.scanCache = null;
    only.scanBusy = false;
    only.visitedPages = [];
    only.crawlOrigin = null;
    address.value = '';
    updateChromeForUrl('about:blank');
    resetScanUi(false);
    updateCrawlUi();
    renderTabs();
    return;
  }
  const idx = tabs.findIndex((t) => t.id === id);
  if (idx < 0) return;
  const [removed] = tabs.splice(idx, 1);
  removed.webview.remove();
  if (activeTabId === id) {
    const next = tabs[Math.max(0, idx - 1)];
    activateTab(next.id);
  } else {
    renderTabs();
  }
}

// ---------------------------------------------------------------------------
// Навигация
// ---------------------------------------------------------------------------

function normalizeUrl(input) {
  let url = (input || '').trim();
  if (!url) return '';
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  return url;
}

function hostOf(url) {
  try {
    return new URL(url).hostname || url;
  } catch (err) {
    return url;
  }
}

function updateChromeForUrl(url) {
  if (!url || url === 'about:blank') {
    httpsBadge.className = 'https-badge';
    httpsLabel.textContent = '—';
    verdictUrl.hidden = true;
    return;
  }
  const secure = /^https:/i.test(url);
  httpsBadge.className = 'https-badge ' + (secure ? 'secure' : 'insecure');
  httpsLabel.textContent = secure ? 'HTTPS' : 'HTTP';
  verdictUrl.hidden = false;
  verdictUrl.textContent = url;
  verdictUrl.href = url;
}

function navigate() {
  const url = normalizeUrl(address.value);
  if (!url) return;
  let tab = activeTab();
  if (!tab) tab = createTab(url);
  address.value = url;
  tab.address = url;
  tab.url = url;
  tab.title = hostOf(url);
  updateChromeForUrl(url);
  tab.webview.src = url;
  viewportStatus.textContent = t('loadingHost', { host: hostOf(url) });
  logLine('http', t('navigated', { url }));
  try {
    const origin = new URL(url).origin;
    if (tab.crawlOrigin && tab.crawlOrigin !== origin) {
      tab.visitedPages = [];
      tab.scanCache = null;
      resetScanUi(false, tab);
    }
    tab.crawlOrigin = origin;
  } catch (err) {
    /* ignore */
  }
  rememberPage(url, tab);
  updateCrawlUi();
  renderTabs();
}

document.getElementById('btnGo').addEventListener('click', navigate);
address.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') navigate();
});
document.getElementById('btnBack').addEventListener('click', () => {
  const v = activeView();
  if (v && v.canGoBack()) v.goBack();
});
document.getElementById('btnForward').addEventListener('click', () => {
  const v = activeView();
  if (v && v.canGoForward()) v.goForward();
});
document.getElementById('btnReload').addEventListener('click', () => {
  const v = activeView();
  if (v) v.reload();
});
document.getElementById('btnCopy').addEventListener('click', async () => {
  const u = currentUrl() || address.value;
  if (!u) return;
  try {
    await navigator.clipboard.writeText(u);
    logLine('sec', t('addressCopied'));
  } catch (err) {
    /* ignore */
  }
});
document.getElementById('btnNewTab').addEventListener('click', () => {
  createTab('about:blank');
  address.focus();
  logLine('http', t('newTabLog'));
});

document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.key === 't') {
    e.preventDefault();
    createTab('about:blank');
    address.focus();
  }
  if (e.ctrlKey && e.key === 'w') {
    e.preventDefault();
    if (activeTabId) closeTab(activeTabId);
  }
  if (e.ctrlKey && e.key === 'l') {
    e.preventDefault();
    address.focus();
    address.select();
  }
});

function currentUrl() {
  const v = activeView();
  if (v) {
    try {
      const u = v.getURL();
      if (u && u !== 'about:blank') return u;
    } catch (err) {
      /* ignore */
    }
  }
  return normalizeUrl(address.value);
}

async function getPageHtml() {
  const v = activeView();
  if (!v) return null;
  try {
    const html = await v.executeJavaScript(
      `(function(){
        var b = document.documentElement ? document.documentElement.outerHTML : '';
        if (!b || b.length < 200) return b || '';
        return b.length > 350000 ? b.slice(0, 350000) : b;
      })()`
    );
    return html || null;
  } catch (err) {
    return null;
  }
}

async function scanOptions(extra) {
  const pageHtml = await getPageHtml();
  const pages = getCrawlPages().filter((u) => u && u !== 'about:blank');
  return Object.assign({ pageHtml: pageHtml || undefined, pages, lang: I18n.getLang() }, extra || {});
}

// ---------------------------------------------------------------------------
// Журнал / модули
// ---------------------------------------------------------------------------

function nowTime() {
  const d = new Date();
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, '0')).join(':');
}

function logLine(tag, msg) {
  const row = document.createElement('div');
  row.className = 'log-line';
  row.innerHTML =
    `<span class="log-time">${nowTime()}</span>` +
    `<span class="log-tag ${escapeHtml(tag)}">[${tag.toUpperCase()}]</span>` +
    `<span class="log-msg">${escapeHtml(msg)}</span>`;
  auditLog.appendChild(row);
  while (auditLog.children.length > 40) auditLog.removeChild(auditLog.firstChild);
  auditLog.scrollTop = auditLog.scrollHeight;
}

function setLive(on) {
  liveTag.textContent = on ? '● LIVE' : '● IDLE';
  liveTag.className = 'live-tag' + (on ? ' on' : '');
}

function moduleCard(kind) {
  return document.querySelector('.module-card[data-scan="' + kind + '"]');
}

function setModuleState(kind, state, meta) {
  const card = moduleCard(kind);
  if (!card) return;
  const dot = card.querySelector('[data-dot]');
  const metaEl = card.querySelector('[data-meta]');
  if (dot) dot.className = 'mod-dot ' + (state || 'idle');
  if (metaEl && meta != null) metaEl.textContent = meta;
}

function summarizeModule(kind, section) {
  if (!section || !section.findings) return { state: 'idle', meta: t('notChecked') };
  const findings = section.findings;
  const worst = SEV_ORDER.find((s) => findings.some((f) => f.severity === s)) || 'info';
  const meta = section.meta || {};
  let text = findings[0] ? findings[0].title : t('done');
  if (kind === 'fingerprint') text = meta.cms ? meta.cms : meta.server ? String(meta.server) : text;
  if (kind === 'tls') text = meta.protocol || text;
  if (kind === 'ports' && meta.open != null) text = t('openPortsN', { n: meta.open });
  if (kind === 'admin' && meta.found != null) text = meta.found ? t('foundN', { n: meta.found }) : t('hiddenNotFound');
  if (kind === 'exposed' && meta.checked) text = findings.some((f) => f.severity !== 'info') ? text : t('clean');
  if (kind === 'xss' || kind === 'sqli') {
    const bad = findings.filter((f) => f.severity !== 'info');
    text = bad.length ? bad[0].title : t('clean');
  }
  if (text.length > 42) text = text.slice(0, 40) + '…';
  const state =
    worst === 'info'
      ? 'ok'
      : worst === 'low' || worst === 'medium'
      ? 'warn'
      : worst === 'critical' || worst === 'high'
      ? 'danger'
      : 'info';
  return { state: findings.every((f) => f.severity === 'info') ? 'ok' : state, meta: text };
}

function applySectionsToModules(sections) {
  let done = 0;
  for (const key of MODULE_KEYS) {
    if (!sections || !sections[key]) continue;
    done += 1;
    const s = summarizeModule(key, sections[key]);
    setModuleState(key, s.state, s.meta);
  }
  modulesProgress.textContent = done + ' / ' + MODULE_KEYS.length;
}

function markModulesRunning(active) {
  for (const key of MODULE_KEYS) {
    const passive = ['fingerprint', 'tls', 'headers', 'cookies'].includes(key);
    if (!active && !passive) continue;
    setModuleState(key, 'run', t('scanning'));
  }
  modulesProgress.textContent = '… / ' + MODULE_KEYS.length;
}

function setVerdict(v, url) {
  verdictEl.className = 'verdict verdict-' + v.level;
  verdictBadge.textContent = v.label;
  verdictScoreNum.textContent = String(v.score);
  verdictAdvice.textContent = v.advice;
  if (url) {
    verdictUrl.hidden = false;
    verdictUrl.textContent = url;
    verdictUrl.href = url;
  }
  const hints = {
    safe: t('excellent'),
    caution: t('hasIssues'),
    warning: t('elevatedRisk'),
    danger: t('doNotTrustHint'),
    idle: t('waiting'),
  };
  trustHint.textContent = hints[v.level] || t('done');
  const crit = (v.counts && v.counts.critical) || 0;
  const high = (v.counts && v.counts.high) || 0;
  metricVulns.textContent = crit + high > 0 ? t('seriousN', { n: crit + high }) : t('zeroCritical');
  metricVulns.className = 'metric-v' + (crit ? ' danger' : high ? ' warn' : '');
  metricRep.textContent =
    v.score >= 85
      ? t('reputationClean', { score: v.score })
      : v.score >= 60
      ? t('reputationMedium')
      : t('reputationLow');
  metricRep.className = 'metric-v' + (v.score >= 85 ? '' : v.score >= 60 ? ' warn' : ' danger');
}

function setVerdictScanning(urlHint) {
  verdictEl.className = 'verdict verdict-idle';
  verdictBadge.textContent = '…';
  verdictScoreNum.textContent = '—';
  trustHint.textContent = t('analyzing');
  verdictLabel.textContent = t('analyzingSecurity');
  verdictAdvice.textContent = urlHint || currentUrl() || '';
}

function renderSummary(counts) {
  summaryEl.innerHTML = '';
  for (const sev of SEV_ORDER) {
    const n = counts[sev] || 0;
    if (!n) continue;
    const chip = document.createElement('span');
    chip.className = 'chip ' + sev;
    chip.textContent = sevLabel(sev) + ': ' + n;
    summaryEl.appendChild(chip);
  }
}

function findingNode(f) {
  const el = document.createElement('div');
  el.className = 'finding ' + f.severity;
  const details = [];
  if (f.location) {
    details.push(
      `<div class="finding-row"><span class="finding-k">${escapeHtml(t('pathToClose'))}</span>` +
        `<code class="finding-path" title="${escapeHtml(t('clickCopy').trim())}">${escapeHtml(f.location)}</code></div>`
    );
  }
  if (f.param) {
    details.push(
      `<div class="finding-row"><span class="finding-k">${escapeHtml(t('param'))}</span>` +
        `<span class="finding-v"><code>${escapeHtml(f.param)}</code></span></div>`
    );
  }
  if (f.where) {
    details.push(
      `<div class="finding-row"><span class="finding-k">${escapeHtml(t('whereToLook'))}</span>` +
        `<span class="finding-v">${escapeHtml(f.where)}</span></div>`
    );
  }
  if (f.evidence) {
    details.push(
      `<div class="finding-row"><span class="finding-k">${escapeHtml(t('evidence'))}</span>` +
        `<span class="finding-v">${escapeHtml(f.evidence)}</span></div>`
    );
  }
  if (f.risk) {
    details.push(
      `<div class="finding-row risk"><span class="finding-k">${escapeHtml(t('whyDangerous'))}</span>` +
        `<span class="finding-v">${escapeHtml(f.risk)}</span></div>`
    );
  }
  if (f.fixSteps && f.fixSteps.length) {
    details.push(
      `<div class="finding-steps"><span class="finding-k">${escapeHtml(t('fixSteps'))}</span><ol>` +
        f.fixSteps.map((s) => `<li>${escapeHtml(s)}</li>`).join('') +
        `</ol></div>`
    );
  }
  const rec = f.recommendation ? `<div class="finding-rec">${escapeHtml(f.recommendation)}</div>` : '';
  const box = details.length ? `<div class="finding-guide">${details.join('')}</div>` : '';
  el.innerHTML = `
    <div class="finding-head">
      <span class="finding-title">${escapeHtml(f.title)}</span>
      <span class="sev-tag ${f.severity}">${sevLabel(f.severity)}</span>
    </div>
    <div class="finding-desc">${escapeHtml(f.description)}</div>
    ${box}
    ${rec}
  `;
  const pathEl = el.querySelector('.finding-path');
  if (pathEl) {
    pathEl.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(f.location);
        logLine('sec', t('pathCopied', { path: f.location }));
      } catch (err) {
        /* ignore */
      }
    });
  }
  return el;
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderFindings(findings) {
  resultsEl.innerHTML = '';
  const sorted = [...findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );
  if (!sorted.length) {
    resultsEl.innerHTML = '<div class="placeholder">' + escapeHtml(t('noFindings')) + '</div>';
    return;
  }
  let lastSev = null;
  for (const f of sorted) {
    if (f.severity !== lastSev) {
      const group = document.createElement('div');
      group.className = 'group-title';
      group.textContent = t('severityGroup', { sev: sevLabel(f.severity) });
      resultsEl.appendChild(group);
      lastSev = f.severity;
    }
    resultsEl.appendChild(findingNode(f));
  }
}

function showScanning(msg) {
  resultsEl.innerHTML = '<div class="scanning">' + escapeHtml(msg) + '</div>';
}

function updateTlsChrome(sections, urlHint) {
  const tls = sections && sections.tls;
  const url = urlHint || currentUrl() || '';
  if (tls && tls.meta && tls.meta.protocol) {
    metricTls.textContent = tls.meta.protocol + (tls.meta.authorized === false ? ' !' : '');
    metricTls.className = 'metric-v cyan' + (tls.meta.authorized === false ? ' danger' : '');
    tlsFooter.textContent = tls.meta.protocol + (tls.meta.subject ? ' / ' + tls.meta.subject : '');
  } else if (/^https:/i.test(url)) {
    metricTls.textContent = 'HTTPS';
    tlsFooter.textContent = 'HTTPS';
  } else if (url) {
    metricTls.textContent = 'HTTP';
    metricTls.className = 'metric-v danger';
    tlsFooter.textContent = t('httpNoTls');
  }

  const hdr = sections && sections.headers;
  const server = hdr && hdr.meta && hdr.meta.server;
  if (server && /cloudflare|ddos|waf|sucuri|incapsula/i.test(String(server))) {
    wafBadge.textContent = 'WAF: Active';
    wafBadge.className = 'waf-badge active';
  } else if (server) {
    wafBadge.textContent = 'Server: ' + String(server).slice(0, 18);
    wafBadge.className = 'waf-badge';
  }
}

async function runFullScan() {
  const tab = activeTab();
  if (!tab) return;
  const tabId = tab.id;
  const url = currentUrl();
  if (!url) return;

  tab.scanBusy = true;
  setVerdictScanning(url);
  setLive(true);
  markModulesRunning(activeMode.checked);
  const pages = getCrawlPages(tab).filter((u) => u && u !== 'about:blank');
  showScanning(
    t('fullScanProgress', {
      host: hostOf(url),
      active: activeMode.checked
        ? t('fullScanActivePart', { n: Math.min(pages.length || 1, 12) })
        : '',
    }) + '…'
  );
  logLine('sec', t('fullScanStart', { host: hostOf(url) }));

  const opts = await scanOptions({ active: activeMode.checked });
  // Страницы только этой вкладки.
  opts.pages = getCrawlPages(tab);
  const res = await window.lab.scanAll(url, opts);

  const owner = tabById(tabId);
  if (owner) owner.scanBusy = false;

  if (!res.ok) {
    logLine('warn', '[' + hostOf(url) + '] ' + res.error);
    if (isTabActive(tabId)) {
      setLive(false);
      verdictLabel.textContent = t('analysisError');
      verdictAdvice.textContent = res.error;
      resultsEl.innerHTML =
        '<div class="placeholder">' + escapeHtml(t('scanFailed', { error: res.error })) + '</div>';
    }
    return;
  }

  const { verdict, sections } = res.data;
  if (owner) saveFullCache(owner, url, verdict, sections);

  if (!isTabActive(tabId)) {
    logLine('sec', t('fullScanDoneBg', { host: hostOf(url), label: verdict.label, score: verdict.score }));
    return;
  }

  setLive(false);
  paintScanResult(owner, url, verdict, sections);
  logLine('sec', t('fullScanDone', { host: hostOf(url), label: verdict.label, score: verdict.score }));
}

function labelForVerdict(v) {
  if (v.level === 'danger') return t('verdictTitleDanger');
  if (v.level === 'warning') return t('verdictTitleWarning');
  if (v.level === 'caution') return t('verdictTitleCaution');
  return t('verdictTitleSafe');
}

function showModuleResults(kind, section, fromCache, host) {
  document.querySelectorAll('.module-card').forEach((c) => c.classList.remove('active'));
  const card = moduleCard(kind);
  if (card) card.classList.add('active');
  const findings = (section && section.findings) || [];
  const s = summarizeModule(kind, section);
  setModuleState(kind, s.state, s.meta);
  renderSummary(countBy(findings));
  renderFindings(findings);
  if (kind === 'tls' || kind === 'headers' || kind === 'fingerprint') {
    updateTlsChrome({ [kind]: section });
  }
  logLine('sec', (host ? '[' + host + '] ' : '') + (fromCache ? t('fromCache', { meta: s.meta }) : t('moduleDone', { meta: s.meta })));
}

async function runSingle(kind) {
  const tab = activeTab();
  if (!tab) return;
  const tabId = tab.id;
  const url = currentUrl();
  if (!url) return;
  const host = hostOf(url);
  const names = {
    headers: t('scanNameHeaders'),
    tls: t('scanNameTls'),
    xss: t('scanNameXss'),
    exposed: t('scanNameExposed'),
    cookies: t('scanNameCookies'),
    sqli: t('scanNameSqli'),
    ports: t('scanNamePorts'),
    admin: t('scanNameAdmin'),
    fingerprint: t('scanNameFingerprint'),
  };

  const cached = getCachedSection(url, kind, tab);
  if (cached) {
    showModuleResults(kind, cached, true, host);
    return;
  }

  document.querySelectorAll('.module-card').forEach((c) => c.classList.remove('active'));
  const card = moduleCard(kind);
  if (card) card.classList.add('active');
  setModuleState(kind, 'run', t('scanning'));
  showScanning(t('moduleCheck', { host, name: names[kind] }));
  setLive(true);
  logLine('sec', t('moduleStart', { host, name: names[kind] }));

  const opts = await scanOptions();
  opts.pages = getCrawlPages(tab);
  let res;
  if (kind === 'fingerprint') res = await window.lab.scanFingerprint(url, opts);
  else if (kind === 'admin') res = await window.lab.scanAdmin(url, opts);
  else if (kind === 'xss') res = await window.lab.scanXss(url, opts);
  else if (kind === 'sqli') res = await window.lab.scanSqli(url, opts);
  else {
    const fnMap = {
      headers: window.lab.scanHeaders,
      tls: window.lab.scanTls,
      exposed: window.lab.scanExposed,
      cookies: window.lab.scanCookies,
      ports: window.lab.scanPorts,
    };
    res = await fnMap[kind](url, opts);
  }

  const owner = tabById(tabId);
  if (!res.ok) {
    logLine('warn', '[' + host + '] ' + res.error);
    if (isTabActive(tabId)) {
      setLive(false);
      setModuleState(kind, 'danger', t('error'));
      resultsEl.innerHTML = '<div class="placeholder">' + escapeHtml(t('errorPrefix', { error: res.error })) + '</div>';
    }
    return;
  }
  if (owner) saveSectionCache(owner, url, kind, res.data);
  if (!isTabActive(tabId)) {
    logLine('sec', t('moduleBg', { host }));
    return;
  }
  setLive(false);
  showModuleResults(kind, res.data, false, host);
}

function countBy(findings) {
  const c = {};
  for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
  return c;
}

document.getElementById('scanAll').addEventListener('click', runFullScan);
document.querySelectorAll('[data-scan]').forEach((btn) => {
  btn.addEventListener('click', () => runSingle(btn.dataset.scan));
});
document.getElementById('btnHarvestLinks').addEventListener('click', () => harvestLinksFromPage());
document.getElementById('btnClearCrawl').addEventListener('click', () => {
  const tab = activeTab();
  if (tab) {
    tab.visitedPages = [];
    if (currentUrl()) rememberPage(currentUrl());
  }
  updateCrawlUi();
  logLine('http', t('pagesCleared'));
});

verdictUrl.addEventListener('click', (e) => {
  e.preventDefault();
  if (verdictUrl.textContent) {
    address.value = verdictUrl.textContent;
    navigate();
  }
});

// Language + стартовая вкладка
(function initLang() {
  let saved = 'ru';
  try {
    saved = localStorage.getItem('brauser.lang') || 'ru';
  } catch (err) {
    saved = 'ru';
  }
  I18n.setLang(saved);
  applyStaticI18n();
  const sel = document.getElementById('langSelect');
  if (sel) {
    sel.value = I18n.getLang();
    sel.addEventListener('change', () => setLanguage(sel.value));
  }
})();
createTab('about:blank');

