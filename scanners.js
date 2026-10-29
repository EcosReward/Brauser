'use strict';

// Движок анализа безопасности.
// Все проверки выполняются в основном процессе Electron (Node.js),
// поэтому мы можем делать сырые HTTP(S)/TLS запросы без ограничений CORS.

const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');
const { URL } = require('url');
const i18n = require('./i18n');
function tr(ru, en) { return i18n.tr(ru, en); }

const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const DEFAULT_TIMEOUT = 6000;

async function mapPool(items, concurrency, worker) {
  const list = [...items];
  const out = [];
  const runners = Array.from({ length: Math.min(concurrency, list.length || 1) }, async () => {
    while (list.length) {
      const item = list.shift();
      out.push(await worker(item));
    }
  });
  await Promise.all(runners);
  return out;
}

// Опциональный HTTP-клиент из Electron (session webview) —
// нужен, чтобы проходить JS-челленджи вроде ddosfilter после открытия сайта в браузере.
let httpClient = null;
function setHttpClient(fn) {
  httpClient = typeof fn === 'function' ? fn : null;
}

const SEVERITY = {
  critical: { rank: 4, get label() { return getSeverityLabel('critical'); } },
  high: { rank: 3, get label() { return getSeverityLabel('high'); } },
  medium: { rank: 2, get label() { return getSeverityLabel('medium'); } },
  low: { rank: 1, get label() { return getSeverityLabel('low'); } },
  info: { rank: 0, get label() { return getSeverityLabel('info'); } },
};

function getSeverityLabel(sev) {
  const labels = {
    critical: tr('Критическая', 'Critical'),
    high: tr('Высокая', 'High'),
    medium: tr('Средняя', 'Medium'),
    low: tr('Низкая', 'Low'),
    info: tr('Информация', 'Info'),
  };
  return labels[sev] || sev;
}

function finding(severity, title, description, recommendation, extra) {
  const e = extra || {};
  return {
    severity,
    title,
    description,
    recommendation: recommendation || '',
    // Подсказки для новичка: куда смотреть и что закрыть.
    location: e.location || '', // точный URL или путь, напр. https://site.com/.env
    where: e.where || '', // простыми словами: «Откройте этот адрес в браузере…»
    evidence: e.evidence || '', // что именно увидел сканер
    risk: e.risk || '', // чем опасно
    fixSteps: Array.isArray(e.fixSteps) ? e.fixSteps : [],
    param: e.param || '',
    module: e.module || '',
  };
}

// ---------------------------------------------------------------------------
// Низкоуровневый запрос с поддержкой редиректов.
// ---------------------------------------------------------------------------

function isChallengePage(body, headers) {
  const b = body || '';
  const server = String((headers && (headers.server || headers.Server)) || '');
  return (
    /ddosfilter|ddos-guard/i.test(server) ||
    /_dfjs\/b\.js|ddosfilter/i.test(b) ||
    /cf-browser-verification|challenge-platform|__cf_chl|Just a moment\.\.\.|Attention Required/i.test(b) ||
    /cdn-cgi\/challenge|Checking your browser|Enable JavaScript and cookies/i.test(b)
  );
}

function bodyLooksSame(a, b) {
  if (!a || !b) return false;
  if (Math.abs(a.length - b.length) > 48) return false;
  const n = Math.min(180, a.length, b.length);
  return a.slice(0, n) === b.slice(0, n);
}

function rawRequest(targetUrl, options = {}) {
  if (httpClient) {
    return httpClient(targetUrl, options);
  }
  return nodeRawRequest(targetUrl, options);
}

function nodeRawRequest(targetUrl, options = {}) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch (err) {
      reject(new Error(tr('Некорректный URL: ', 'Invalid URL: ') + targetUrl));
      return;
    }

    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const started = Date.now();

    const reqOptions = {
      method: options.method || 'GET',
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8',
        ...(options.headers || {}),
      },
      // Для анализа тела страницы нам не важна валидность сертификата —
      // валидность TLS проверяется отдельным сканером.
      rejectUnauthorized: false,
      timeout: options.timeout || DEFAULT_TIMEOUT,
    };

    const req = lib.request(reqOptions, (res) => {
      // Обработка редиректов.
      if (
        [301, 302, 303, 307, 308].includes(res.statusCode) &&
        res.headers.location &&
        (options.maxRedirects === undefined || options.maxRedirects > 0)
      ) {
        const next = new URL(res.headers.location, parsed).toString();
        res.resume();
        resolve(
          rawRequest(next, {
            ...options,
            maxRedirects: (options.maxRedirects ?? 5) - 1,
            _redirectChain: [...(options._redirectChain || [parsed.toString()]), next],
          })
        );
        return;
      }

      const chunks = [];
      let size = 0;
      const limit = options.maxBytes || 512 * 1024; // по умолчанию 512 КБ
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size <= limit) chunks.push(chunk);
        else req.destroy();
      });
      res.on('end', () => {
        resolve({
          url: targetUrl,
          finalUrl: parsed.toString(),
          status: res.statusCode,
          headers: res.headers,
          rawHeaders: res.rawHeaders,
          body: Buffer.concat(chunks).toString('utf8'),
          bytes: size,
          elapsed: Date.now() - started,
          redirectChain: options._redirectChain || null,
        });
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error(tr('Превышено время ожидания', 'Request timed out')));
    });
    req.on('error', (err) => reject(err));
    if (options.body) req.write(options.body);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// 1. Заголовки безопасности
// ---------------------------------------------------------------------------

async function scanHeaders(targetUrl, options = {}) {
  if (options && options.lang) i18n.setLang(options.lang);
  const findings = [];
  const res = await rawRequest(targetUrl, { method: 'GET' });
  const h = res.headers;
  const isHttps = res.finalUrl.startsWith('https:');

  const has = (name) => h[name.toLowerCase()] !== undefined;

  if (!has('content-security-policy')) {
    findings.push(
      finding(
        'medium',
        tr('Отсутствует Content-Security-Policy', 'Content-Security-Policy is missing'),
        tr('CSP защищает от XSS и внедрения стороннего контента. Заголовок не найден.', 'CSP protects against XSS and third-party content injection. The header was not found.'),
        tr('Добавьте заголовок Content-Security-Policy с ограничением источников скриптов.', 'Add a Content-Security-Policy header restricting script sources.')
      )
    );
  }

  if (isHttps && !has('strict-transport-security')) {
    findings.push(
      finding(
        'medium',
        tr('Отсутствует HSTS', 'HSTS is missing'),
        tr('Strict-Transport-Security заставляет браузер всегда использовать HTTPS. Заголовок не найден.', 'Strict-Transport-Security forces the browser to always use HTTPS. The header was not found.'),
        tr('Добавьте: Strict-Transport-Security: max-age=31536000; includeSubDomains.', 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains.')
      )
    );
  }

  const frameGuard =
    has('x-frame-options') ||
    (h['content-security-policy'] || '').includes('frame-ancestors');
  if (!frameGuard) {
    findings.push(
      finding(
        'medium',
        tr('Нет защиты от clickjacking', 'No clickjacking protection'),
        tr('Нет ни X-Frame-Options, ни CSP frame-ancestors — страницу можно встроить в iframe злоумышленника.', 'Neither X-Frame-Options nor CSP frame-ancestors is set, so an attacker can embed the page in an iframe.'),
        tr('Добавьте X-Frame-Options: DENY или CSP frame-ancestors.', 'Add X-Frame-Options: DENY or CSP frame-ancestors.')
      )
    );
  }

  if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') {
    findings.push(
      finding(
        'low',
        tr('Отсутствует X-Content-Type-Options', 'X-Content-Type-Options is missing'),
        tr('Браузер может угадывать MIME-тип, что повышает риск атак.', 'The browser may sniff the MIME type, increasing the risk of attacks.'),
        tr('Добавьте X-Content-Type-Options: nosniff.', 'Add X-Content-Type-Options: nosniff.')
      )
    );
  }

  if (!has('referrer-policy')) {
    findings.push(
      finding(
        'low',
        tr('Отсутствует Referrer-Policy', 'Referrer-Policy is missing'),
        tr('Возможна утечка URL во внешние ресурсы через заголовок Referer.', 'URLs may leak to external resources through the Referer header.'),
        tr('Добавьте Referrer-Policy: no-referrer-when-downgrade или строже.', 'Add Referrer-Policy: no-referrer-when-downgrade or a stricter policy.')
      )
    );
  }

  if (!has('permissions-policy')) {
    findings.push(
      finding(
        'info',
        tr('Отсутствует Permissions-Policy', 'Permissions-Policy is missing'),
        tr('Нет ограничений на использование камеры, микрофона, геолокации и др.', 'There are no restrictions on the use of the camera, microphone, geolocation, and other features.'),
        tr('Рассмотрите добавление Permissions-Policy.', 'Consider adding a Permissions-Policy header.')
      )
    );
  }

  const discloser = [];
  if (has('server') && /\d/.test(h['server'])) discloser.push('Server: ' + h['server']);
  if (has('x-powered-by')) discloser.push('X-Powered-By: ' + h['x-powered-by']);
  if (has('x-aspnet-version')) discloser.push('X-AspNet-Version: ' + h['x-aspnet-version']);
  if (discloser.length) {
    findings.push(
      finding(
        'low',
        tr('Раскрытие версий ПО', 'Software version disclosure'),
        tr('Сервер сообщает версии ПО: ', 'The server discloses software versions: ') + discloser.join('; ') + tr('. Это помогает подбирать эксплойты.', '. This helps attackers select exploits.'),
        tr('Скройте или обобщите заголовки Server / X-Powered-By.', 'Hide or generalize the Server / X-Powered-By headers.')
      )
    );
  }

  const cors = h['access-control-allow-origin'];
  if (cors === '*' && (h['access-control-allow-credentials'] || '').toLowerCase() === 'true') {
    findings.push(
      finding(
        'high',
        tr('Опасная конфигурация CORS', 'Dangerous CORS configuration'),
        tr('Access-Control-Allow-Origin: * вместе с Allow-Credentials: true позволяет красть данные пользователя с любого сайта.', 'Access-Control-Allow-Origin: * together with Allow-Credentials: true can allow user data to be stolen from any site.'),
        tr('Не используйте wildcard ACAO вместе с credentials. Укажите конкретные домены.', 'Do not use wildcard ACAO with credentials. Specify exact domains.')
      )
    );
  }

  if (!findings.length) {
    findings.push(
      finding('info', tr('Заголовки безопасности в порядке', 'Security headers are configured correctly'), tr('Основные защитные заголовки присутствуют.', 'The main security headers are present.'), '')
    );
  }

  return {
    findings,
    meta: {
      status: res.status,
      finalUrl: res.finalUrl,
      server: h['server'] || '—',
      elapsed: res.elapsed,
    },
  };
}

// ---------------------------------------------------------------------------
// 2. TLS / Сертификат
// ---------------------------------------------------------------------------

function scanTls(targetUrl, options = {}) {
  if (options && options.lang) i18n.setLang(options.lang);
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch (err) {
      resolve({ findings: [finding('info', tr('Некорректный URL', 'Invalid URL'), String(err), '')], meta: {} });
      return;
    }

    if (parsed.protocol !== 'https:') {
      resolve({
        findings: [
          finding(
            'critical',
            tr('Сайт работает по HTTP без шифрования', 'The site uses unencrypted HTTP'),
            tr('Трафик передаётся в открытом виде. Пароли, cookie и данные могут быть перехвачены.', 'Traffic is sent in plaintext. Passwords, cookies, and data can be intercepted.'),
            tr('Никогда не вводите пароли на таком сайте. Требуется HTTPS.', 'Never enter passwords on this site. HTTPS is required.')
          ),
        ],
        meta: { protocol: 'http' },
      });
      return;
    }

    const socket = tls.connect(
      {
        host: parsed.hostname,
        port: parsed.port || 443,
        servername: parsed.hostname,
        rejectUnauthorized: false,
        timeout: DEFAULT_TIMEOUT,
      },
      () => {
        const findings = [];
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        const authorized = socket.authorized;
        const authError = socket.authorizationError;

        if (!authorized) {
          findings.push(
            finding(
              'critical',
              tr('Недействительный TLS-сертификат', 'Invalid TLS certificate'),
              tr('Сертификат не прошёл проверку: ', 'Certificate validation failed: ') + (authError || tr('неизвестная ошибка', 'unknown error')) +
                tr('. Возможна атака «человек посередине» или самоподписанный сертификат.', '. This may indicate a man-in-the-middle attack or a self-signed certificate.'),
              tr('Не доверяйте сайту с невалидным сертификатом.', 'Do not trust a site with an invalid certificate.')
            )
          );
        }

        if (cert && cert.valid_to) {
          const expiry = new Date(cert.valid_to);
          const daysLeft = Math.round((expiry - Date.now()) / 86400000);
          if (daysLeft < 0) {
            findings.push(
              finding(
                'critical',
                tr('Срок сертификата истёк', 'Certificate has expired'),
                tr('Сертификат истёк ', 'The certificate expired ') + Math.abs(daysLeft) + tr(' дн. назад (', ' days ago (') + cert.valid_to + ').',
                tr('Сайт не поддерживает безопасное соединение корректно.', 'The site does not properly support a secure connection.')
              )
            );
          } else if (daysLeft < 15) {
            findings.push(
              finding(
                'medium',
                tr('Сертификат скоро истечёт', 'Certificate expires soon'),
                tr('Осталось ', '') + daysLeft + tr(' дн. (', ' days remaining (') + cert.valid_to + ').',
                tr('Владельцу стоит обновить сертификат.', 'The owner should renew the certificate.')
              )
            );
          }
        }

        if (protocol && (protocol === 'TLSv1' || protocol === 'TLSv1.1')) {
          findings.push(
            finding(
              'high',
              tr('Устаревший протокол TLS', 'Outdated TLS protocol'),
              tr('Используется ', 'The site uses ') + protocol + tr(', который считается небезопасным.', ', which is considered insecure.'),
              tr('Отключите TLS 1.0/1.1, используйте TLS 1.2+.', 'Disable TLS 1.0/1.1 and use TLS 1.2 or newer.')
            )
          );
        }

        if (!findings.length) {
          findings.push(
            finding('info', tr('TLS-сертификат в порядке', 'TLS certificate is valid'), tr('Соединение защищено валидным сертификатом (', 'The connection is protected by a valid certificate (') + protocol + ').', '')
          );
        }

        resolve({
          findings,
          meta: {
            protocol,
            authorized,
            issuer: cert && cert.issuer ? cert.issuer.O || cert.issuer.CN : '—',
            subject: cert && cert.subject ? cert.subject.CN : '—',
            validTo: cert ? cert.valid_to : '—',
          },
        });
        socket.end();
      }
    );

    socket.on('error', (err) => {
      resolve({
        findings: [
          finding(
            'high',
            tr('Ошибка TLS-соединения', 'TLS connection error'),
            tr('Не удалось установить защищённое соединение: ', 'Could not establish a secure connection: ') + err.message,
            tr('Проверьте доступность и конфигурацию TLS сайта.', 'Check the site availability and TLS configuration.')
          ),
        ],
        meta: {},
      });
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        findings: [finding('medium', tr('TLS: превышено время ожидания', 'TLS: request timed out'), tr('Сервер не ответил вовремя.', 'The server did not respond in time.'), '')],
        meta: {},
      });
    });
  });
}

// ---------------------------------------------------------------------------
// 3. Отражённый XSS (лёгкая активная проверка, может по нескольким страницам)
// ---------------------------------------------------------------------------

function collectPages(targetUrl, options) {
  const list = [];
  const seen = new Set();
  const add = (u) => {
    if (!u || typeof u !== 'string') return;
    try {
      const p = new URL(u);
      if (!/^https?:$/i.test(p.protocol)) return;
      const key = (p.origin + p.pathname.replace(/\/$/, '') + p.search).toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      list.push(p.toString());
    } catch (err) {
      /* skip */
    }
  };
  add(targetUrl);
  (options && options.pages ? options.pages : []).forEach(add);
  // Сначала страницы с ?параметрами — там чаще XSS/SQLi.
  list.sort((a, b) => Number(b.includes('?')) - Number(a.includes('?')));
  return list;
}

async function scanXssOne(targetUrl) {
  const findings = [];
  const token = 'brs' + Math.random().toString(36).slice(2, 8);
  const payload = '"\'><svg/onload=' + token + '>';

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch (err) {
    return { findings: [], meta: { tested: 0 } };
  }

  const params = [...parsed.searchParams.keys()];
  const testUrls = [];

  if (params.length) {
    for (const key of params.slice(0, 4)) {
      const u = new URL(parsed.toString());
      u.searchParams.set(key, payload);
      testUrls.push({ param: key, url: u.toString(), page: parsed.toString() });
    }
  } else {
    const u = new URL(parsed.toString());
    u.searchParams.set('q', payload);
    testUrls.push({ param: tr('q (добавлен)', 'q (added)'), url: u.toString(), page: parsed.toString() });
  }

  let reflectedAny = false;
  await mapPool(testUrls, 4, async (t) => {
    try {
      const res = await rawRequest(t.url, { maxBytes: 160 * 1024, timeout: 5000 });
      const body = res.body;
      if (body.includes(payload)) {
        reflectedAny = true;
        findings.push(
          finding(
            'high',
            tr('Возможный отражённый XSS в параметре «', 'Possible reflected XSS in parameter “') + t.param + tr('»', '”'),
            tr('Страница: ', 'Page: ') + t.page + tr('. Нагрузка вернулась без экранирования.', '. The payload was returned without escaping.'),
            tr('Экранируйте вывод пользовательских данных и добавьте Content-Security-Policy.', 'Escape user-controlled output and add a Content-Security-Policy.'),
            {
              module: 'xss',
              param: t.param,
              location: t.url,
              where:
                tr('Страница «', 'Page “') +
                t.page +
                tr('», параметр «', '”, parameter “') +
                t.param +
                tr('». Откройте: ', '”. Open: ') +
                t.url,
              evidence: tr('Неэкранированная тестовая нагрузка в HTML ответа', 'Unescaped test payload in the HTML response'),
              risk: tr('Кража cookie/сессии, подмена страницы.', 'Cookie/session theft and page manipulation.'),
              fixSteps: [
                tr('Откройте страницу: ', 'Open the page: ') + t.page,
                tr('Найдите вывод параметра «', 'Find where parameter “') + t.param + tr('» в коде.', '” is output in the code.'),
                tr('Экранируйте вывод (htmlspecialchars и аналоги).', 'Escape the output (htmlspecialchars or equivalent).'),
                tr('Добавьте CSP и повторите проверку XSS.', 'Add CSP and repeat the XSS check.'),
              ],
            }
          )
        );
      } else if (body.includes('&lt;svg') || body.includes(token)) {
        findings.push(
          finding(
            'info',
            tr('Параметр «', 'Parameter “') + t.param + tr('» отражается (экранирован) на ', '” is reflected (escaped) on ') + parsed.pathname,
            tr('Значение попадает на страницу, но экранируется.', 'The value reaches the page but is escaped.'),
            tr('Поддерживайте экранирование вывода.', 'Keep output escaping enabled.'),
            {
              module: 'xss',
              param: t.param,
              location: t.page,
              where: tr('Страница ', 'Page ') + t.page + tr(', параметр «', ', parameter “') + t.param + tr('»', '”'),
              evidence: tr('Отражение есть, экранирование работает', 'The value is reflected and escaping works'),
            }
          )
        );
      }
    } catch (err) {
      /* skip */
    }
  });

  return { findings, meta: { tested: testUrls.length, reflectedAny } };
}

async function scanXss(targetUrl, options = {}) {
  if (options && options.lang) i18n.setLang(options.lang);
  const pages = collectPages(targetUrl, options).slice(0, 12);
  const findings = [];
  let tested = 0;
  let hit = false;

  await mapPool(pages, 3, async (page) => {
    const r = await scanXssOne(page);
    tested += r.meta.tested || 0;
    if (r.meta.reflectedAny) hit = true;
    for (const f of r.findings) {
      if (f.severity !== 'info') findings.push(f);
      else if (pages.length === 1) findings.push(f);
    }
  });

  if (!hit && !findings.some((f) => f.severity !== 'info')) {
    findings.push(
      finding(
        'info',
        tr('Отражённый XSS не обнаружен', 'No reflected XSS detected'),
        tr('Проверено страниц: ', 'Pages checked: ') + pages.length + tr('. Неэкранированного отражения нет.', '. No unescaped reflection was found.'),
        '',
        {
          module: 'xss',
          where: tr('Просмотрены: ', 'Reviewed: ') + pages.slice(0, 5).join(' · ') + (pages.length > 5 ? ' …' : ''),
          evidence: tr('Тестов параметров: ', 'Parameter tests: ') + tested,
        }
      )
    );
  }

  return { findings, meta: { tested, pages: pages.length } };
}

// ---------------------------------------------------------------------------
// 4. Открытые файлы и каталоги
// ---------------------------------------------------------------------------

const SENSITIVE_PATHS = [
  {
    path: '/.git/config',
    sev: 'critical',
    desc: 'Открыт репозиторий Git — злоумышленник может скачать исходный код сайта.',
    risk: 'Утечка кода, паролей из конфигов, логики админки.',
    fixSteps: [
      'Запретите веб-доступ к папке .git на сервере (Nginx/Apache).',
      'Убедитесь, что https://ВАШ_САЙТ/.git/config больше не открывается (должна быть 403/404).',
      'Не храните .git в публичной папке сайта (public_html / www).',
    ],
  },
  {
    path: '/.git/HEAD',
    sev: 'critical',
    desc: 'Открыт репозиторий Git (.git/HEAD).',
    risk: 'Подтверждает наличие .git — дальше можно выгрузить весь код.',
    fixSteps: [
      'Закройте всю папку /.git/ от публичного доступа.',
      'Проверьте: адрес /.git/HEAD должен отдавать 403 или 404.',
    ],
  },
  {
    path: '/.env',
    sev: 'critical',
    desc: 'Файл .env часто содержит пароли БД, API-ключи и секреты.',
    risk: 'Прямой доступ к базе данных, почте, платёжным ключам.',
    fixSteps: [
      'Немедленно смените все пароли/ключи из этого файла (БД, API, SMTP).',
      'Удалите .env из публичной папки или запретите к нему доступ (deny all).',
      'Проверьте, что https://ВАШ_САЙТ/.env больше не открывается.',
    ],
  },
  {
    path: '/.env.local',
    sev: 'critical',
    desc: 'Локальный .env с секретами.',
    risk: 'Утечка секретов окружения.',
    fixSteps: ['Закройте или удалите файл из веб-корня.', 'Смените скомпрометированные секреты.'],
  },
  {
    path: '/config.php.bak',
    sev: 'critical',
    desc: 'Резервная копия конфигурации с возможными паролями.',
    risk: 'В .bak часто лежат пароли БД в открытом виде.',
    fixSteps: ['Удалите *.bak из публичной папки.', 'Смените пароли, если файл уже был доступен.'],
  },
  {
    path: '/wp-config.php.bak',
    sev: 'critical',
    desc: 'Резервная копия wp-config с доступом к БД WordPress.',
    risk: 'Полный доступ к базе WordPress.',
    fixSteps: ['Удалите wp-config.php.bak с сервера.', 'Смените пароль БД WordPress.'],
  },
  {
    path: '/backup.zip',
    sev: 'high',
    desc: 'Открытый бэкап сайта.',
    risk: 'В архиве могут быть исходники и конфиги.',
    fixSteps: ['Удалите backup.zip из веб-корня или перенесите вне public.', 'Храните бэкапы вне сайта.'],
  },
  {
    path: '/backup.sql',
    sev: 'critical',
    desc: 'Открытый дамп базы данных SQL.',
    risk: 'Полная копия БД: пользователи, пароли, личные данные.',
    fixSteps: [
      'СРОЧНО удалите backup.sql с сервера или закройте доступ.',
      'Смените пароли пользователей и админов.',
      'Никогда не кладите .sql в папку сайта.',
    ],
  },
  {
    path: '/database.sql',
    sev: 'critical',
    desc: 'Открытый дамп базы данных SQL.',
    risk: 'Утечка всей базы данных.',
    fixSteps: ['Удалите database.sql из публичного доступа.', 'Смените пароли после утечки.'],
  },
  {
    path: '/db.sql',
    sev: 'critical',
    desc: 'Открытый дамп базы данных SQL.',
    risk: 'Утечка всей базы данных.',
    fixSteps: ['Удалите db.sql.', 'Проверьте, нет ли других *.sql в корне сайта.'],
  },
  {
    path: '/dump.sql',
    sev: 'critical',
    desc: 'Открытый дамп базы данных SQL.',
    risk: 'Утечка всей базы данных.',
    fixSteps: ['Удалите dump.sql из веб-корня.', 'Храните дампы только в закрытом бэкап-хранилище.'],
  },
  {
    path: '/.svn/entries',
    sev: 'high',
    desc: 'Открыт репозиторий SVN.',
    risk: 'Можно выгрузить исходники.',
    fixSteps: ['Закройте папку /.svn/ от веба.'],
  },
  {
    path: '/.DS_Store',
    sev: 'low',
    desc: 'Файл .DS_Store раскрывает структуру каталогов.',
    risk: 'Подсказки о скрытых папках.',
    fixSteps: ['Удалите .DS_Store с сервера.'],
  },
  {
    path: '/.htaccess',
    sev: 'medium',
    desc: 'Доступен файл конфигурации Apache.',
    risk: 'Видны правила защиты и пути.',
    fixSteps: ['Запретите чтение .htaccess из браузера (обычно по умолчанию, проверьте конфиг).'],
  },
  {
    path: '/phpinfo.php',
    sev: 'high',
    desc: 'phpinfo() раскрывает полную конфигурацию сервера.',
    risk: 'Версии ПО, пути, модули — помощь атакующему.',
    fixSteps: ['Удалите phpinfo.php с продакшена.', 'Не оставляйте тестовые скрипты на сайте.'],
  },
  {
    path: '/server-status',
    sev: 'medium',
    desc: 'Apache server-status раскрывает трафик и запросы.',
    risk: 'Видны URL посетителей и нагрузка.',
    fixSteps: ['Отключите mod_status для внешнего доступа или ограничьте по IP.'],
  },
  {
    path: '/.well-known/security.txt',
    sev: 'info',
    desc: 'Есть security.txt (хороший признак).',
    risk: '',
    fixSteps: [],
  },
  {
    path: '/robots.txt',
    sev: 'info',
    desc: 'robots.txt может указывать скрытые пути (Disallow).',
    risk: '',
    fixSteps: [],
  },
];

const SENSITIVE_TEXT_EN = {
  '/.git/config': ['An exposed Git repository lets attackers download the site source code.', 'Source code, configuration passwords, and admin logic may leak.', ['Deny web access to the .git directory in Nginx/Apache.', 'Verify that https://YOUR_SITE/.git/config returns 403/404.', 'Do not keep .git in the public site directory (public_html / www).']],
  '/.git/HEAD': ['An exposed Git repository (.git/HEAD).', 'Confirms that .git exists and the full source may be downloaded.', ['Block public access to the entire /.git/ directory.', 'Verify that /.git/HEAD returns 403 or 404.']],
  '/.env': ['The .env file often contains database passwords, API keys, and secrets.', 'Direct access to databases, email, and payment keys.', ['Immediately rotate all passwords/keys in this file (DB, API, SMTP).', 'Remove .env from the public directory or deny access to it.', 'Verify that https://YOUR_SITE/.env is no longer accessible.']],
  '/.env.local': ['A local .env file containing secrets.', 'Environment secrets may leak.', ['Block or remove the file from the web root.', 'Rotate compromised secrets.']],
  '/config.php.bak': ['A configuration backup that may contain passwords.', '.bak files often contain plaintext database passwords.', ['Remove *.bak files from the public directory.', 'Rotate passwords if the file was accessible.']],
  '/wp-config.php.bak': ['A wp-config backup containing WordPress database access.', 'Full access to the WordPress database.', ['Remove wp-config.php.bak from the server.', 'Rotate the WordPress database password.']],
  '/backup.zip': ['An exposed site backup.', 'The archive may contain source code and configuration files.', ['Remove backup.zip from the web root or move it outside public storage.', 'Keep backups outside the site.']],
  '/backup.sql': ['An exposed SQL database dump.', 'A full database copy containing users, passwords, and personal data.', ['URGENT: remove backup.sql from the server or block access.', 'Rotate user and administrator passwords.', 'Never place .sql files in the site directory.']],
  '/database.sql': ['An exposed SQL database dump.', 'The entire database may leak.', ['Remove database.sql from public access.', 'Rotate passwords after the leak.']],
  '/db.sql': ['An exposed SQL database dump.', 'The entire database may leak.', ['Remove db.sql.', 'Check for other *.sql files in the site root.']],
  '/dump.sql': ['An exposed SQL database dump.', 'The entire database may leak.', ['Remove dump.sql from the web root.', 'Keep dumps only in protected backup storage.']],
  '/.svn/entries': ['An exposed SVN repository.', 'Source code can be downloaded.', ['Block web access to the /.svn/ directory.']],
  '/.DS_Store': ['The .DS_Store file reveals the directory structure.', 'It provides clues about hidden directories.', ['Remove .DS_Store from the server.']],
  '/.htaccess': ['An Apache configuration file is accessible.', 'Protection rules and paths are exposed.', ['Block browser access to .htaccess (normally blocked by default; verify the configuration).']],
  '/phpinfo.php': ['phpinfo() reveals the full server configuration.', 'Software versions, paths, and modules help attackers.', ['Remove phpinfo.php from production.', 'Do not leave test scripts on the site.']],
  '/server-status': ['Apache server-status reveals traffic and requests.', 'Visitor URLs and server load are visible.', ['Disable external mod_status access or restrict it by IP.']],
  '/.well-known/security.txt': ['security.txt is present (a good sign).', '', []],
  '/robots.txt': ['robots.txt may reveal hidden paths (Disallow).', '', []],
};

async function pathExists(baseUrl, path, options = {}) {
  const u = new URL(path, baseUrl).toString();
  try {
    const res = await rawRequest(u, {
      method: 'GET',
      maxBytes: options.maxBytes || 120 * 1024,
      maxRedirects: options.maxRedirects === undefined ? 0 : options.maxRedirects,
    });
    return {
      status: res.status,
      bytes: res.bytes,
      body: res.body,
      headers: res.headers,
      url: u,
      challenge: isChallengePage(res.body, res.headers),
    };
  } catch (err) {
    return { status: 0, error: err.message, url: u, challenge: false };
  }
}

async function scanExposedFiles(targetUrl, options = {}) {
  if (options && options.lang) i18n.setLang(options.lang);
  const findings = [];
  const base = new URL(targetUrl);
  const origin = base.origin + '/';

  // Определяем «мягкий 404»: некоторые сайты возвращают 200 на любой путь.
  const randomPath = '/brs-does-not-exist-' + Math.random().toString(36).slice(2, 10);
  const baseline = await pathExists(origin, randomPath);
  const softNotFound = baseline.status === 200;
  const baselineLen = baseline.body ? baseline.body.length : -1;

  // Ограничиваем параллелизм.
  const queue = [...SENSITIVE_PATHS];
  await mapPool(queue, 10, async (item) => {
    const res = await pathExists(origin, item.path, { maxBytes: 48 * 1024 });
    const found =
      res.status === 200 &&
      !res.challenge &&
      !(softNotFound && bodyLooksSame(res.body, baseline.body)) &&
      !(softNotFound && Math.abs((res.body ? res.body.length : 0) - baselineLen) < 32);

    if (found) {
      const fullUrl = res.url || new URL(item.path, origin).toString();
      const itemEn = SENSITIVE_TEXT_EN[item.path] || [item.desc, item.risk, item.fixSteps];
      findings.push(
        finding(
          item.sev,
          tr('Доступен файл: ', 'Exposed file: ') + item.path,
          tr(item.desc, itemEn[0]) + tr(' Сервер ответил HTTP 200 (', ' The server returned HTTP 200 (') + (res.bytes || 0) + tr(' байт).', ' bytes).'),
          item.sev === 'info'
            ? ''
            : tr('Закройте этот путь: удалите файл из публичной папки или запретите доступ в Nginx/Apache.', 'Close this path: remove the file from the public directory or deny access in Nginx/Apache.'),
          {
            module: 'exposed',
            location: fullUrl,
            where:
              tr('Откройте в браузере этот адрес: ', 'Open this address in a browser: ') +
              fullUrl +
              tr(' — если страница/файл скачивается или показывается текст, уязвимость подтверждена.', ' — if the page/file downloads or displays text, the vulnerability is confirmed.'),
            evidence: tr('HTTP 200, размер ответа ≈ ', 'HTTP 200, response size ≈ ') + (res.bytes || 0) + tr(' байт', ' bytes'),
            risk: tr(item.risk || '', itemEn[1] || ''),
            fixSteps: (i18n.getLang() === 'en' ? (itemEn[2] || []) : (item.fixSteps || []))
              .map((s) => s.replace(/ВАШ_САЙТ|YOUR_SITE/g, base.hostname)),
          }
        )
      );
    }
  });

  // Проверка листинга каталогов.
  try {
    const dirRes = await pathExists(origin, '/uploads/');
    const uploadsUrl = new URL('/uploads/', origin).toString();
    if (dirRes.status === 200 && /Index of \//i.test(dirRes.body || '')) {
      findings.push(
        finding(
          'medium',
          tr('Открыт листинг каталога /uploads/', 'Directory listing is enabled for /uploads/'),
          tr('Сервер показывает список файлов в каталоге — любой может увидеть имена загруженных файлов.', 'The server displays the directory contents, so anyone can see uploaded file names.'),
          tr('Отключите directory listing (Apache: Options -Indexes; Nginx: autoindex off).', 'Disable directory listing (Apache: Options -Indexes; Nginx: autoindex off).'),
          {
            module: 'exposed',
            location: uploadsUrl,
            where: tr('Откройте ', 'Open ') + uploadsUrl + tr(' — если видите «Index of /uploads», листинг включён.', ' — if you see “Index of /uploads”, listing is enabled.'),
            evidence: tr('В HTML найдена строка «Index of /»', 'The HTML contains “Index of /”'),
            risk: tr('Утечка имён файлов, возможность скачать чужие загрузки.', 'File-name disclosure and the ability to download other users’ uploads.'),
            fixSteps: [
              tr('В Apache добавьте Options -Indexes для этой папки.', 'In Apache, add Options -Indexes for this directory.'),
              tr('В Nginx: autoindex off;', 'In Nginx: autoindex off;'),
              tr('Проверьте, что ', 'Verify that ') + uploadsUrl + tr(' больше не показывает список файлов.', ' no longer displays a file list.'),
            ],
          }
        )
      );
    }
  } catch (err) {
    /* ignore */
  }

  if (!findings.length) {
    findings.push(
      finding('info', tr('Открытых чувствительных файлов не найдено', 'No exposed sensitive files found'), tr('Проверенные типичные пути недоступны.', 'The common paths checked are not accessible.'), '')
    );
  }

  return { findings, meta: { softNotFound, checked: SENSITIVE_PATHS.length } };
}

// ---------------------------------------------------------------------------
// 5. Cookie
// ---------------------------------------------------------------------------

async function scanCookies(targetUrl, options = {}) {
  if (options && options.lang) i18n.setLang(options.lang);
  const findings = [];
  const res = await rawRequest(targetUrl, { method: 'GET' });
  const isHttps = res.finalUrl.startsWith('https:');

  let setCookie = res.headers['set-cookie'];
  if (!setCookie) {
    findings.push(finding('info', tr('Cookie не устанавливаются', 'No cookies are set'), tr('Сервер не прислал заголовок Set-Cookie.', 'The server did not return a Set-Cookie header.'), ''));
    return { findings, meta: {} };
  }
  if (!Array.isArray(setCookie)) setCookie = [setCookie];

  for (const cookie of setCookie) {
    const name = cookie.split('=')[0].trim();
    const lower = cookie.toLowerCase();
    const issues = [];
    if (isHttps && !lower.includes('secure')) issues.push(tr('нет флага Secure', 'missing Secure flag'));
    if (!lower.includes('httponly')) issues.push(tr('нет флага HttpOnly (доступна из JS)', 'missing HttpOnly flag (accessible from JS)'));
    if (!lower.includes('samesite')) issues.push(tr('нет атрибута SameSite (риск CSRF)', 'missing SameSite attribute (CSRF risk)'));

    if (issues.length) {
      const hasHttpOnly = !lower.includes('httponly');
      findings.push(
        finding(
          hasHttpOnly ? 'medium' : 'low',
          tr('Небезопасная cookie: ', 'Insecure cookie: ') + name,
          tr('Проблемы: ', 'Issues: ') + issues.join(', ') + '.',
          tr('Установите флаги Secure, HttpOnly и SameSite для cookie.', 'Set the Secure, HttpOnly, and SameSite flags for the cookie.')
        )
      );
    }
  }

  if (!findings.length) {
    findings.push(finding('info', tr('Cookie защищены корректно', 'Cookies are properly protected'), tr('У всех cookie выставлены безопасные флаги.', 'All cookies have secure flags set.'), ''));
  }

  return { findings, meta: { count: setCookie.length } };
}

// ---------------------------------------------------------------------------
// 6. SQL-инъекции (error-based, лёгкая активная проверка)
// ---------------------------------------------------------------------------

const SQL_ERROR_SIGNS = [
  /SQL syntax.*MySQL/i,
  /Warning.*\bmysqli?\b/i,
  /MySQLSyntaxErrorException/i,
  /valid MySQL result/i,
  /com\.mysql\.jdbc/i,
  /check the manual that corresponds to your (MySQL|MariaDB)/i,
  /PostgreSQL.*ERROR/i,
  /pg_query\(\)/i,
  /PG::(Syntax|Undefined)/i,
  /Microsoft SQL Server/i,
  /ODBC SQL Server Driver/i,
  /SQLServer JDBC Driver/i,
  /Unclosed quotation mark after the character string/i,
  /ORA-\d{5}/i,
  /Oracle error/i,
  /quoted string not properly terminated/i,
  /SQLite\/JDBCDriver/i,
  /SQLiteException/i,
  /sqlite3\.OperationalError/i,
  /syntax error.*query expression/i,
];

async function scanSqlOne(targetUrl) {
  const findings = [];
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch (err) {
    return { findings: [], meta: { tested: 0 } };
  }

  const params = [...parsed.searchParams.keys()].slice(0, 4);
  const payloads = ["'", "1'\"", "' OR '1'='1"];
  const tests = [];

  if (params.length) {
    for (const key of params) {
      for (const pl of payloads) {
        const u = new URL(parsed.toString());
        u.searchParams.set(key, (parsed.searchParams.get(key) || '1') + pl);
        tests.push({ param: key, url: u.toString(), page: parsed.toString() });
      }
    }
  } else {
    for (const pl of payloads) {
      const u = new URL(parsed.toString());
      u.searchParams.set('id', '1' + pl);
      tests.push({ param: tr('id (добавлен)', 'id (added)'), url: u.toString(), page: parsed.toString() });
    }
  }

  let baselineErr = false;
  try {
    const b = await rawRequest(parsed.toString(), { maxBytes: 120 * 1024, timeout: 5000 });
    baselineErr = SQL_ERROR_SIGNS.some((r) => r.test(b.body));
  } catch (err) {
    /* ignore */
  }

  const flagged = new Set();
  await mapPool(tests, 6, async (t) => {
    if (flagged.has(t.param)) return;
    try {
      const res = await rawRequest(t.url, { maxBytes: 120 * 1024, timeout: 5000 });
      if (SQL_ERROR_SIGNS.some((r) => r.test(res.body)) && !baselineErr) {
        if (flagged.has(t.param)) return;
        flagged.add(t.param);
        const errLine = (res.body.match(/SQL syntax|mysql_|PostgreSQL|ORA-\d+|Unclosed quotation|sqlite3/i) || [
          tr('ошибка БД в HTML', 'database error in HTML'),
        ])[0];
        findings.push(
          finding(
            'critical',
            tr('Возможная SQL-инъекция в параметре «', 'Possible SQL injection in parameter “') + t.param + tr('»', '”'),
            tr('Страница: ', 'Page: ') + t.page + tr('. Сервер вернул ошибку БД после спецсимволов в параметре.', '. The server returned a database error after special characters were added to the parameter.'),
            tr('Используйте prepared statements и не показывайте ошибки SQL пользователю.', 'Use prepared statements and do not expose SQL errors to users.'),
            {
              module: 'sqli',
              param: t.param,
              location: t.url,
              where: tr('Страница «', 'Page “') + t.page + tr('», параметр «', '”, parameter “') + t.param + tr('». Тест: ', '”. Test: ') + t.url,
              evidence: tr('Ошибка БД: «', 'Database error: “') + String(errLine).slice(0, 80) + tr('»', '”'),
              risk: tr('Чтение/изменение базы данных.', 'Reading or modifying the database.'),
              fixSteps: [
                tr('Откройте страницу: ', 'Open the page: ') + t.page,
                tr('Найдите обработчик параметра «', 'Find the handler for parameter “') + t.param + tr('».', '”.'),
                tr('Замените склейку SQL на prepared statements.', 'Replace SQL string concatenation with prepared statements.'),
                tr('Отключите вывод ошибок БД на продакшене.', 'Disable database error output in production.'),
              ],
            }
          )
        );
      }
    } catch (err) {
      /* skip */
    }
  });

  return { findings, meta: { tested: tests.length } };
}

async function scanSqlInjection(targetUrl, options = {}) {
  if (options && options.lang) i18n.setLang(options.lang);
  const pages = collectPages(targetUrl, options).slice(0, 12);
  const findings = [];
  let tested = 0;

  await mapPool(pages, 3, async (page) => {
    const r = await scanSqlOne(page);
    tested += r.meta.tested || 0;
    findings.push(...r.findings);
  });

  if (!findings.length) {
    findings.push(
      finding(
        'info',
        tr('Признаков SQL-инъекции не обнаружено', 'No signs of SQL injection detected'),
        tr('Проверено страниц: ', 'Pages checked: ') + pages.length + tr('. Ошибок БД после спецсимволов нет.', '. No database errors appeared after special characters.'),
        '',
        {
          module: 'sqli',
          where: tr('Просмотрены: ', 'Reviewed: ') + pages.slice(0, 5).join(' · ') + (pages.length > 5 ? ' …' : ''),
          evidence: tr('Тестов: ', 'Tests: ') + tested,
        }
      )
    );
  }

  return { findings, meta: { tested, pages: pages.length } };
}

// ---------------------------------------------------------------------------
// 7. Открытые порты (TCP connect)
// ---------------------------------------------------------------------------

const COMMON_PORTS = [
  { port: 21, name: 'FTP', sev: 'medium', note: 'FTP часто передаёт пароли в открытом виде.' },
  { port: 22, name: 'SSH', sev: 'low', note: 'SSH — отключите вход по паролю, оставьте ключи.' },
  { port: 23, name: 'Telnet', sev: 'high', note: 'Telnet передаёт всё открытым текстом.' },
  { port: 25, name: 'SMTP', sev: 'low', note: 'Почтовый сервер.' },
  { port: 80, name: 'HTTP', sev: 'info', note: 'Веб-порт (ожидаемо).' },
  { port: 110, name: 'POP3', sev: 'low', note: 'Почтовый порт.' },
  { port: 143, name: 'IMAP', sev: 'low', note: 'Почтовый порт.' },
  { port: 443, name: 'HTTPS', sev: 'info', note: 'Веб-порт (ожидаемо).' },
  { port: 445, name: 'SMB', sev: 'high', note: 'SMB не должен быть доступен из интернета.' },
  { port: 1433, name: 'MSSQL', sev: 'critical', note: 'База данных MSSQL доступна извне.' },
  { port: 3306, name: 'MySQL', sev: 'critical', note: 'База данных MySQL доступна извне — закройте фаерволом.' },
  { port: 3389, name: 'RDP', sev: 'high', note: 'RDP — частая цель брутфорса.' },
  { port: 5432, name: 'PostgreSQL', sev: 'critical', note: 'База данных PostgreSQL доступна извне.' },
  { port: 5900, name: 'VNC', sev: 'high', note: 'Удалённый рабочий стол VNC доступен извне.' },
  { port: 6379, name: 'Redis', sev: 'critical', note: 'Redis часто работает без пароля — критично.' },
  { port: 8080, name: 'HTTP-alt', sev: 'low', note: 'Альтернативный веб-порт.' },
  { port: 8443, name: 'HTTPS-alt', sev: 'low', note: 'Альтернативный веб-порт.' },
  { port: 9200, name: 'Elasticsearch', sev: 'critical', note: 'Elasticsearch без авторизации — утечка данных.' },
  { port: 27017, name: 'MongoDB', sev: 'critical', note: 'MongoDB доступна извне.' },
];

const PORT_NOTES_EN = {
  21: 'FTP often sends passwords in plaintext.',
  22: 'SSH — disable password login and use keys.',
  23: 'Telnet sends everything in plaintext.',
  25: 'Mail server.',
  80: 'Web port (expected).',
  110: 'Mail port.',
  143: 'Mail port.',
  443: 'Web port (expected).',
  445: 'SMB should not be exposed to the internet.',
  1433: 'The MSSQL database is accessible externally.',
  3306: 'The MySQL database is accessible externally — block it with a firewall.',
  3389: 'RDP is a common brute-force target.',
  5432: 'The PostgreSQL database is accessible externally.',
  5900: 'The VNC remote desktop is accessible externally.',
  6379: 'Redis often runs without a password — critical.',
  8080: 'Alternative web port.',
  8443: 'Alternative web port.',
  9200: 'Unauthenticated Elasticsearch can leak data.',
  27017: 'MongoDB is accessible externally.',
};

function checkPort(host, port, timeout = 800) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(open);
    };
    sock.setTimeout(timeout);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    try {
      sock.connect(port, host);
    } catch (err) {
      finish(false);
    }
  });
}

async function scanPorts(targetUrl, options = {}) {
  if (options && options.lang) i18n.setLang(options.lang);
  const findings = [];
  let host;
  try {
    host = new URL(targetUrl).hostname;
  } catch (err) {
    return { findings: [finding('info', tr('Некорректный URL', 'Invalid URL'), String(err), '')], meta: {} };
  }

  const open = [];
  await mapPool(COMMON_PORTS, 12, async (p) => {
    if (await checkPort(host, p.port)) open.push(p);
  });

  for (const p of open) {
    const loc = host + ':' + p.port;
    const portNote = tr(p.note, PORT_NOTES_EN[p.port]);
    if (p.sev === 'info') {
      findings.push(
        finding('info', tr('Открыт порт ', 'Open port ') + p.port + ' (' + p.name + ')', portNote, '', {
          module: 'ports',
          location: loc,
          where: tr('Хост ', 'Host ') + host + tr(', порт ', ', port ') + p.port + ' (' + p.name + ')' + tr(' — это нормально для сайта.', ' — this is normal for a website.'),
        })
      );
    } else {
      findings.push(
        finding(
          p.sev,
          tr('Открыт порт ', 'Open port ') + p.port + ' (' + p.name + ')',
          portNote + tr(' Порт отвечает на подключения из интернета.', ' The port accepts connections from the internet.'),
          tr('Закройте порт фаерволом, если он не нужен публично, или ограничьте доступ по IP.', 'Block the port with a firewall if it does not need to be public, or restrict access by IP.'),
          {
            module: 'ports',
            location: loc,
            where:
              tr('Смотрите на сервере/VPS: хост «', 'Check the server/VPS: host “') +
              host +
              tr('», TCP-порт ', '”, TCP port ') +
              p.port +
              ' (' +
              p.name +
              tr('). Это не путь в браузере, а сетевой порт машины.', '). This is a machine network port, not a browser path.'),
            evidence: tr('TCP-подключение к ', 'TCP connection to ') + loc + tr(' успешно установлено', ' succeeded'),
            risk: portNote,
            fixSteps: [
              tr('В фаерволе (ufw / security group / панель хостинга) закройте входящий порт ', 'In the firewall (ufw / security group / hosting panel), block inbound port ') + p.port + tr(' для 0.0.0.0/0.', ' for 0.0.0.0/0.'),
              tr('Оставьте доступ только с вашего IP или через VPN, если порт нужен вам.', 'Allow access only from your IP or through a VPN if you need the port.'),
              tr('Для БД (3306, 5432, 27017, 6379) снаружи порт почти никогда не должен быть открыт.', 'Database ports (3306, 5432, 27017, 6379) should almost never be exposed externally.'),
            ],
          }
        )
      );
    }
  }

  if (!findings.length) {
    findings.push(
      finding('info', tr('Лишних открытых портов не найдено', 'No unnecessary open ports found'), tr('Проверенные служебные порты закрыты.', 'The checked service ports are closed.'), '')
    );
  }

  return { findings, meta: { host, checked: COMMON_PORTS.length, open: open.length } };
}

// ---------------------------------------------------------------------------
// 8. Видимость админок и панелей входа (CMS-aware + проверка по содержимому)
// ---------------------------------------------------------------------------

const GENERIC_LOGIN_SIG = /<(?:form|input)[^>]*(?:password|login|passwd|user[_-]?name|log)/i;

const CMS_ADMIN_CATALOG = {
  XenForo: [
    {
      path: '/admin.php',
      label: 'XenForo Admin CP',
      signatures: [/admin\.php/i, /xfAdmin|data-template="login"|XenForo|name="login"/i, GENERIC_LOGIN_SIG],
    },
    {
      path: '/admin.php?login/',
      label: 'XenForo Admin login',
      signatures: [/admin\.php/i, /xfAdmin|XenForo|name="login"|name="password"/i, GENERIC_LOGIN_SIG],
    },
    {
      path: '/admin.php?logout/',
      label: 'XenForo Admin',
      signatures: [/admin\.php/i, /xfAdmin|XenForo|name="login"/i, GENERIC_LOGIN_SIG],
    },
  ],
  WordPress: [
    {
      path: '/wp-login.php',
      label: 'WordPress login',
      signatures: [/wp-login\.php|wordpress|loginform|id="user_login"|name="log"/i, GENERIC_LOGIN_SIG],
    },
    {
      path: '/wp-admin/',
      label: 'WordPress Admin',
      signatures: [/wp-admin|wp-login|wordpress|dashboard/i, GENERIC_LOGIN_SIG],
    },
    {
      path: '/wp-admin/admin.php',
      label: 'WordPress Admin',
      signatures: [/wp-admin|wordpress/i],
    },
  ],
  Joomla: [
    {
      path: '/administrator/',
      label: 'Joomla Administrator',
      signatures: [/joomla|com_login|administrator/i, GENERIC_LOGIN_SIG],
    },
    {
      path: '/administrator/index.php',
      label: 'Joomla Administrator',
      signatures: [/joomla|com_login|administrator/i, GENERIC_LOGIN_SIG],
    },
  ],
  Drupal: [
    {
      path: '/user/login',
      label: 'Drupal login',
      signatures: [/drupal|user-login|name="name"|name="pass"/i, GENERIC_LOGIN_SIG],
    },
    {
      path: '/admin',
      label: 'Drupal admin',
      signatures: [/drupal|administration/i],
    },
  ],
  '1C-Bitrix': [
    {
      path: '/bitrix/admin/',
      label: 'Bitrix Admin',
      signatures: [/bitrix|BX\.|login/i, GENERIC_LOGIN_SIG],
    },
    {
      path: '/bitrix/admin/index.php',
      label: 'Bitrix Admin',
      signatures: [/bitrix|login/i, GENERIC_LOGIN_SIG],
    },
  ],
  phpBB: [
    {
      path: '/adm/',
      label: 'phpBB Admin',
      signatures: [/phpbb|acp|administrator/i, GENERIC_LOGIN_SIG],
    },
    {
      path: '/ucp.php?mode=login',
      label: 'phpBB login',
      signatures: [/phpbb|username|password/i, GENERIC_LOGIN_SIG],
    },
  ],
  vBulletin: [
    {
      path: '/admincp/',
      label: 'vBulletin AdminCP',
      signatures: [/vbulletin|admincp|login/i, GENERIC_LOGIN_SIG],
    },
    {
      path: '/modcp/',
      label: 'vBulletin ModCP',
      signatures: [/vbulletin|modcp|login/i, GENERIC_LOGIN_SIG],
    },
  ],
  MyBB: [
    {
      path: '/admin/',
      label: 'MyBB Admin',
      signatures: [/mybb|admincp|username/i, GENERIC_LOGIN_SIG],
    },
  ],
  IPS: [
    {
      path: '/admin/',
      label: 'Invision Community Admin',
      signatures: [/invision|ips\.|admin/i, GENERIC_LOGIN_SIG],
    },
  ],
  OpenCart: [
    {
      path: '/admin/',
      label: 'OpenCart Admin',
      signatures: [/opencart|route=common\/login|username/i, GENERIC_LOGIN_SIG],
    },
  ],
  Magento: [
    {
      path: '/admin/',
      label: 'Magento Admin',
      signatures: [/magento|admin/i, GENERIC_LOGIN_SIG],
    },
    {
      path: '/index.php/admin/',
      label: 'Magento Admin',
      signatures: [/magento|admin/i, GENERIC_LOGIN_SIG],
    },
  ],
  MODX: [
    {
      path: '/manager/',
      label: 'MODX Manager',
      signatures: [/modx|manager|login/i, GENERIC_LOGIN_SIG],
    },
  ],
  TYPO3: [
    {
      path: '/typo3/',
      label: 'TYPO3 Backend',
      signatures: [/typo3|backend|login/i, GENERIC_LOGIN_SIG],
    },
  ],
  Ghost: [
    {
      path: '/ghost/',
      label: 'Ghost Admin',
      signatures: [/ghost|ember|login/i, GENERIC_LOGIN_SIG],
    },
  ],
  PrestaShop: [
    {
      path: '/admin/',
      label: 'PrestaShop Admin',
      signatures: [/prestashop|admin/i, GENERIC_LOGIN_SIG],
    },
  ],
};

const SHARED_ADMIN_TOOLS = [
  {
    path: '/phpmyadmin/',
    label: 'phpMyAdmin',
    signatures: [/phpmyadmin|pma_|mysql/i, GENERIC_LOGIN_SIG],
  },
  {
    path: '/pma/',
    label: 'phpMyAdmin',
    signatures: [/phpmyadmin|pma_|mysql/i, GENERIC_LOGIN_SIG],
  },
  {
    path: '/adminer.php',
    label: 'Adminer',
    signatures: [/adminer|login/i, GENERIC_LOGIN_SIG],
  },
  {
    path: '/dbadmin/',
    label: 'DB Admin',
    signatures: [/phpmyadmin|adminer|mysql/i, GENERIC_LOGIN_SIG],
  },
  {
    path: '/cpanel',
    label: 'cPanel',
    signatures: [/cpanel|cPanel/i],
  },
  {
    path: '/manager/html',
    label: 'Tomcat Manager',
    signatures: [/tomcat|manager/i],
  },
];

// Если CMS ещё не определён — проверяем известные «фирменные» пути всех движков.
const FALLBACK_ADMIN_PATHS = [
  ...CMS_ADMIN_CATALOG.XenForo,
  ...CMS_ADMIN_CATALOG.WordPress,
  ...CMS_ADMIN_CATALOG.Joomla,
  ...CMS_ADMIN_CATALOG.Drupal,
  ...CMS_ADMIN_CATALOG['1C-Bitrix'],
  ...CMS_ADMIN_CATALOG.vBulletin,
  ...CMS_ADMIN_CATALOG.phpBB,
  { path: '/admin/', label: 'Generic /admin/', signatures: [GENERIC_LOGIN_SIG] },
  { path: '/admin/login', label: 'Generic admin login', signatures: [GENERIC_LOGIN_SIG] },
  { path: '/login', label: 'Generic /login', signatures: [GENERIC_LOGIN_SIG] },
  { path: '/panel/', label: 'Generic /panel/', signatures: [GENERIC_LOGIN_SIG] },
  { path: '/adminpanel/', label: 'Generic /adminpanel/', signatures: [GENERIC_LOGIN_SIG] },
];

function getAdminTargets(cms) {
  const list = [];
  const seen = new Set();
  const push = (items) => {
    for (const item of items) {
      if (seen.has(item.path)) continue;
      seen.add(item.path);
      list.push(item);
    }
  };
  if (cms && CMS_ADMIN_CATALOG[cms]) push(CMS_ADMIN_CATALOG[cms]);
  else push(FALLBACK_ADMIN_PATHS);
  push(SHARED_ADMIN_TOOLS);
  return list;
}

function matchesAdminSignatures(body, signatures) {
  if (!body) return false;
  if (isChallengePage(body)) return false;
  // Нужен хотя бы один «сильный» признак формы/движка.
  return (signatures || []).some((re) => re.test(body));
}

async function scanAdmin(targetUrl, options = {}) {
  if (options && options.lang) i18n.setLang(options.lang);
  const findings = [];
  const origin = new URL(targetUrl).origin + '/';

  // Сначала узнаём CMS — чтобы проверять правильные пути (XenForo → /admin.php и т.д.).
  let cms = options.cms || null;
  if (!cms) {
    try {
      const fp = await scanFingerprint(targetUrl, options);
      cms = (fp.meta && fp.meta.cms) || null;
      if (fp.meta && fp.meta.challenge) {
        findings.push(
          finding(
            'medium',
            tr('Антибот мешает проверке админок', 'Anti-bot protection blocks the admin check'),
            tr('Сайт отдаёт JS-челлендж (ddosfilter/Cloudflare и т.п.). Сначала откройте сайт во встроенном браузере, дождитесь загрузки, затем повторите проверку.', 'The site returns a JavaScript challenge (ddosfilter/Cloudflare, etc.). Open it in the built-in browser, wait for it to load, then retry the check.'),
            tr('Повторите скан после полной загрузки страницы в Brauser.', 'Retry the scan after the page fully loads in Brauser.')
          )
        );
        return { findings, meta: { checked: 0, found: 0, cms, challenge: true } };
      }
    } catch (err) {
      /* продолжаем с fallback-путями */
    }
  }

  const targets = getAdminTargets(cms);
  const rnd = '/brs-nope-' + Math.random().toString(36).slice(2, 10);
  const baseline = await pathExists(origin, rnd, { maxBytes: 120 * 1024 });
  if (baseline.challenge) {
    findings.push(
      finding(
        'medium',
        tr('Антибот мешает проверке админок', 'Anti-bot protection blocks the admin check'),
        tr('Ответ на запросы — страница-челлендж, а не реальный контент. Откройте сайт в браузере Brauser и повторите проверку после загрузки.', 'Requests return a challenge page instead of real content. Open the site in Brauser and retry after it loads.'),
        tr('Повторите скан после прохождения антибота во встроенном браузере.', 'Retry the scan after passing the anti-bot check in the built-in browser.')
      )
    );
    return { findings, meta: { checked: 0, found: 0, cms, challenge: true } };
  }

  const found = [];
  await mapPool(targets, 8, async (item) => {
    const r = await pathExists(origin, item.path, { maxBytes: 96 * 1024, maxRedirects: 2 });
    if (r.challenge) return;
    if (![200, 401, 403].includes(r.status)) return;
    if (r.status === 200 && bodyLooksSame(r.body, baseline.body)) return;

    const authWall = r.status === 401 || r.status === 403;
    const signed = matchesAdminSignatures(r.body, item.signatures);
    const cmsSpecific = !!(cms && CMS_ADMIN_CATALOG[cms] && CMS_ADMIN_CATALOG[cms].some((x) => x.path === item.path));

    if (authWall || signed || (cmsSpecific && r.status === 200 && GENERIC_LOGIN_SIG.test(r.body || ''))) {
      found.push({
        path: item.path,
        label: item.label,
        status: r.status,
        authWall,
        signed,
        cmsSpecific,
      });
    }
  });

  for (const f of found) {
    const sev = f.authWall ? 'low' : 'medium';
    const fullUrl = new URL(f.path, origin).toString();
    findings.push(
      finding(
        sev,
        (f.cmsSpecific && cms ? cms + ': ' : '') + tr('Доступна панель «', 'Exposed panel “') + f.label + tr('»: ', '”: ') + f.path,
        'HTTP ' +
          f.status +
          (f.authWall ? tr(' (закрыта авторизацией, но путь известен)', ' (protected by authentication, but the path is known)') : '') +
          (f.signed ? tr('. На странице обнаружена форма входа/признаки админки.', '. A login form or admin-panel indicators were found.') : '.') +
          tr(' Публично видимая админка — цель для подбора пароля.', ' A publicly visible admin panel is a password-guessing target.'),
        tr('Ограничьте доступ по IP / VPN, включите 2FA и защиту от перебора. Для XenForo смените путь admin.php.', 'Restrict access by IP/VPN, enable 2FA and brute-force protection. For XenForo, change the admin.php path.'),
        {
          module: 'admin',
          location: fullUrl,
          where:
            tr('Откройте в браузере: ', 'Open in a browser: ') +
            fullUrl +
            tr(' — если видите форму входа в админку, путь найден. Именно его нужно закрыть или усилить.', ' — if an admin login form appears, the path is confirmed. Restrict or harden this path.'),
          evidence: 'HTTP ' + f.status + (f.signed ? tr(', признаки формы входа', ', login-form indicators') : ''),
          risk: tr('Брутфорс пароля администратора, захват сайта.', 'Administrator password brute force and site takeover.'),
          fixSteps: [
            tr('Сохраните этот адрес: ', 'Save this address: ') + fullUrl,
            tr('Ограничьте доступ к нему по IP (Nginx allow/deny или Cloudflare Access).', 'Restrict access by IP (Nginx allow/deny or Cloudflare Access).'),
            tr('Включите 2FA для админов и сложный пароль.', 'Enable 2FA and a strong password for administrators.'),
            cms === 'XenForo'
              ? tr('В XenForo можно переименовать/сменить admin.php на нестандартный путь.', 'In XenForo, rename/change admin.php to a nonstandard path.')
              : tr('Смените стандартный URL админки, если CMS это позволяет.', 'Change the default admin URL if the CMS supports it.'),
          ],
        }
      )
    );
  }

  if (!findings.length) {
    findings.push(
      finding(
        'info',
        tr('Открытых админ-панелей не найдено', 'No exposed admin panels found'),
        cms
          ? tr('Проверены стандартные пути для ', 'Checked standard paths for ') + cms + tr(' и общие панели (phpMyAdmin и др.).', ' and common panels (phpMyAdmin, etc.).')
          : tr('Проверены стандартные пути популярных CMS. Движок не определён — результат менее точен.', 'Checked standard paths for popular CMSs. The engine was not identified, so the result is less precise.'),
        ''
      )
    );
  }

  return { findings, meta: { checked: targets.length, found: found.length, cms } };
}

// ---------------------------------------------------------------------------
// 9. Определение движка сайта (CMS / стек технологий)
// ---------------------------------------------------------------------------

function detectCmsFromBody(body, headers, setCookie) {
  const h = headers || {};
  const gen = (body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i) || [])[1] || '';
  let cms = null;

  // XenForo — расширенные признаки (в т.ч. кастомные темы вроде lolz.team)
  if (
    /data-xf-init|data-xf-|xf-body|xf-page|XF\.config|XF\.Cookie|xenforo/i.test(body) ||
    /\/styles\/.*\/xenforo|js\/xf\//i.test(body) ||
    /\bxf_session\b|\bxf_user\b|\bxf_csrf\b/i.test(setCookie) ||
    /<html[^>]+id=["']XF["']/i.test(body)
  ) {
    cms = 'XenForo';
  } else if (/wp-content|wp-includes|\/wp-json|wp-emoji|wp-block/i.test(body) || /\bwordpress_/i.test(setCookie)) {
    cms = 'WordPress';
  } else if (/Joomla/i.test(gen) || /\/media\/jui\/|option=com_|\/components\/com_/i.test(body)) {
    cms = 'Joomla';
  } else if (
    /Drupal/i.test(gen) ||
    /Drupal/i.test(h['x-generator'] || '') ||
    /sites\/default\/files|Drupal\.settings|drupal\.js/i.test(body)
  ) {
    cms = 'Drupal';
  } else if (/vbulletin/i.test(body) || /vbulletin/i.test(gen)) {
    cms = 'vBulletin';
  } else if (/phpbb/i.test(body) || /phpbb/i.test(setCookie)) {
    cms = 'phpBB';
  } else if (/cdn\.shopify\.com/i.test(body) || /Shopify/i.test(gen)) {
    cms = 'Shopify';
  } else if (/bitrix\/js|BX\.message|\/bitrix\//i.test(body) || /bitrix/i.test(setCookie)) {
    cms = '1C-Bitrix';
  } else if (/MODX/i.test(gen) || /\/assets\/components\/|modx/i.test(body)) {
    cms = 'MODX';
  } else if (/typo3/i.test(body) || /TYPO3/i.test(gen)) {
    cms = 'TYPO3';
  } else if (/ghost/i.test(gen) || /ghost-sdk|casper/i.test(body)) {
    cms = 'Ghost';
  } else if (/wix\.com|wixstatic/i.test(body)) {
    cms = 'Wix';
  } else if (/opencart|route=common\/home/i.test(body)) {
    cms = 'OpenCart';
  } else if (/magento|mage\/cookies|Magento_/i.test(body)) {
    cms = 'Magento';
  } else if (/prestashop|presta-/i.test(body)) {
    cms = 'PrestaShop';
  } else if (/mybb/i.test(body) || /mybb/i.test(setCookie)) {
    cms = 'MyBB';
  } else if (/invision|ipsTemplate|ips\./i.test(body)) {
    cms = 'IPS';
  } else if (/discourse/i.test(body) || /discourse/i.test(gen)) {
    cms = 'Discourse';
  }

  const version = (gen.match(/[\d]+(?:\.[\d]+)+/) || [])[0] || null;
  return { cms, version, gen };
}

async function scanFingerprint(targetUrl, options = {}) {
  if (options && options.lang) i18n.setLang(options.lang);
  const findings = [];
  const tech = [];
  const add = (name) => {
    if (name && !tech.includes(name)) tech.push(name);
  };

  let body = options.pageHtml || '';
  let h = {};
  let finalUrl = targetUrl;
  let challenge = false;

  if (!body) {
    const res = await rawRequest(targetUrl, { maxBytes: 280 * 1024, timeout: 5000 });
    h = res.headers || {};
    body = res.body || '';
    finalUrl = res.finalUrl || targetUrl;
    challenge = isChallengePage(body, h);
  } else {
    challenge = isChallengePage(body, {});
  }

  if (challenge) {
    findings.push(
      finding(
        'medium',
        tr('Сайт закрыт антиботом (челлендж)', 'The site is protected by an anti-bot challenge'),
        tr('Сервер отдал страницу защиты (ddosfilter / Cloudflare и т.п.) вместо HTML сайта. Без прохождения челленджа нельзя надёжно определить CMS и админки.', 'The server returned a protection page (ddosfilter / Cloudflare, etc.) instead of the site HTML. The CMS and admin panels cannot be identified reliably until the challenge is passed.'),
        tr('Откройте сайт во встроенном браузере Brauser, дождитесь полной загрузки, затем снова нажмите «Движок сайта» или «Полная проверка».', 'Open the site in the built-in Brauser browser, wait for it to load fully, then click “Site engine” or “Full security check” again.')
      )
    );
    if (h['server']) add('Server: ' + h['server']);
    return {
      findings,
      meta: { tech, cms: null, version: null, server: h['server'] || '—', challenge: true },
    };
  }

  const setCookie = []
    .concat(h['set-cookie'] || [])
    .join('; ')
    .toLowerCase();

  // Серверная часть / язык
  if (h['server']) add('Server: ' + h['server']);
  if (h['x-powered-by']) add('X-Powered-By: ' + h['x-powered-by']);
  if (/phpsessid/i.test(setCookie) || /\.php(\?|$)/i.test(finalUrl) || /<\?php/i.test(body)) add('PHP');
  if (/asp\.net_sessionid/i.test(setCookie) || h['x-aspnet-version']) add('ASP.NET');
  if (/laravel_session/i.test(setCookie)) add('Laravel (PHP)');
  if (/express/i.test(h['x-powered-by'] || '')) add('Node.js / Express');
  if (/jsessionid/i.test(setCookie)) add(tr('Java (сервлеты)', 'Java (servlets)'));

  const { cms, version, gen } = detectCmsFromBody(body, h, setCookie);
  if (cms) add('CMS: ' + cms + (version ? ' ' + version : ''));

  findings.push(
    finding(
      'info',
      cms ? tr('Движок сайта: ', 'Site engine: ') + cms + (version ? ' ' + version : '') : tr('Явный CMS не определён', 'No obvious CMS detected'),
      tech.length ? tr('Обнаружено: ', 'Detected: ') + tech.join(' | ') : tr('Характерных признаков движка не найдено.', 'No characteristic engine indicators were found.'),
      cms
        ? tr('Следите за обновлениями ', 'Keep ') + cms + tr(' и плагинов — устаревшие версии имеют известные уязвимости (CVE).', ' and its plugins updated; outdated versions have known vulnerabilities (CVEs).')
        : tr('Если страница ещё грузится или стоит антибот — откройте сайт в браузере и повторите проверку.', 'If the page is still loading or protected by anti-bot checks, open it in the browser and retry.')
    )
  );

  if (version && gen) {
    findings.push(
      finding(
        'low',
        tr('Версия движка раскрыта в метатеге generator', 'Engine version disclosed in the generator meta tag'),
        tr('«', '“') + gen + tr('». Это помогает злоумышленнику подобрать эксплойт под конкретную версию.', '”. This helps attackers select an exploit for the specific version.'),
        tr('Уберите метатег <meta name="generator"> из разметки.', 'Remove the <meta name="generator"> tag from the markup.')
      )
    );
  }

  return { findings, meta: { tech, cms, version, server: h['server'] || '—', challenge: false } };
}

// ---------------------------------------------------------------------------
// Агрегатор: полная проверка + расчёт вердикта
// ---------------------------------------------------------------------------

function computeVerdict(allFindings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of allFindings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  let score = 100;
  score -= counts.critical * 40;
  score -= counts.high * 20;
  score -= counts.medium * 8;
  score -= counts.low * 3;
  if (score < 0) score = 0;

  let level, label, advice;
  if (counts.critical > 0) {
    level = 'danger';
    label = i18n.t('verdictBadgeDanger');
    advice = i18n.t('verdictAdviceDanger');
  } else if (counts.high > 0) {
    level = 'warning';
    label = i18n.t('verdictBadgeWarning');
    advice = i18n.t('verdictAdviceWarning');
  } else if (counts.medium > 0) {
    level = 'caution';
    label = i18n.t('verdictBadgeCaution');
    advice = i18n.t('verdictAdviceCaution');
  } else {
    level = 'safe';
    label = i18n.t('verdictBadgeSafe');
    advice = i18n.t('verdictAdviceSafe');
  }

  return { level, label, advice, score, counts };
}

async function scanAll(targetUrl, options = {}) {
  i18n.setLang(options.lang);
  const sections = {};
  // Все модули стартуют параллельно. Админка ждёт только fingerprint (для CMS-путей).
  const fpPromise = scanFingerprint(targetUrl, options).catch((err) => ({
    findings: [finding('info', tr('Проверка не выполнена (fingerprint)', 'Check failed (fingerprint)'), String(err), '')],
    meta: {},
  }));

  const tasks = [
    ['fingerprint', fpPromise],
    ['tls', scanTls(targetUrl, options)],
    ['headers', scanHeaders(targetUrl, options)],
    ['cookies', scanCookies(targetUrl, options)],
  ];
  if (options.active !== false) {
    tasks.push(['xss', scanXss(targetUrl, options)]);
    tasks.push(['sqli', scanSqlInjection(targetUrl, options)]);
    tasks.push(['exposed', scanExposedFiles(targetUrl, options)]);
    tasks.push(['ports', scanPorts(targetUrl, options)]);
    tasks.push([
      'admin',
      fpPromise.then((fp) =>
        scanAdmin(targetUrl, { ...options, cms: fp.meta && fp.meta.cms })
      ),
    ]);
  }

  const results = await Promise.allSettled(tasks.map((t) => t[1]));
  results.forEach((r, i) => {
    const key = tasks[i][0];
    if (r.status === 'fulfilled') {
      sections[key] = r.value;
    } else {
      sections[key] = {
        findings: [finding('info', tr('Проверка не выполнена (', 'Check failed (') + key + ')', String(r.reason), '')],
        meta: {},
      };
    }
  });

  // Для вердикта собираем все реальные находки.
  const flat = [];
  Object.values(sections).forEach((s) => flat.push(...s.findings));
  const verdict = computeVerdict(flat);

  return { url: targetUrl, verdict, sections };
}

module.exports = {
  setHttpClient,
  isChallengePage,
  scanHeaders,
  scanTls,
  scanXss,
  scanExposedFiles,
  scanCookies,
  scanSqlInjection,
  scanPorts,
  scanAdmin,
  scanFingerprint,
  scanAll,
  computeVerdict,
  SEVERITY,
};
