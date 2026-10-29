'use strict';

// Движок анализа безопасности.
// Все проверки выполняются в основном процессе Electron (Node.js),
// поэтому мы можем делать сырые HTTP(S)/TLS запросы без ограничений CORS.

const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');
const { URL } = require('url');

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
  critical: { rank: 4, label: 'Критическая' },
  high: { rank: 3, label: 'Высокая' },
  medium: { rank: 2, label: 'Средняя' },
  low: { rank: 1, label: 'Низкая' },
  info: { rank: 0, label: 'Информация' },
};

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
      reject(new Error('Некорректный URL: ' + targetUrl));
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
      req.destroy(new Error('Превышено время ожидания'));
    });
    req.on('error', (err) => reject(err));
    if (options.body) req.write(options.body);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// 1. Заголовки безопасности
// ---------------------------------------------------------------------------

async function scanHeaders(targetUrl) {
  const findings = [];
  const res = await rawRequest(targetUrl, { method: 'GET' });
  const h = res.headers;
  const isHttps = res.finalUrl.startsWith('https:');

  const has = (name) => h[name.toLowerCase()] !== undefined;

  if (!has('content-security-policy')) {
    findings.push(
      finding(
        'medium',
        'Отсутствует Content-Security-Policy',
        'CSP защищает от XSS и внедрения стороннего контента. Заголовок не найден.',
        'Добавьте заголовок Content-Security-Policy с ограничением источников скриптов.'
      )
    );
  }

  if (isHttps && !has('strict-transport-security')) {
    findings.push(
      finding(
        'medium',
        'Отсутствует HSTS',
        'Strict-Transport-Security заставляет браузер всегда использовать HTTPS. Заголовок не найден.',
        'Добавьте: Strict-Transport-Security: max-age=31536000; includeSubDomains.'
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
        'Нет защиты от clickjacking',
        'Нет ни X-Frame-Options, ни CSP frame-ancestors — страницу можно встроить в iframe злоумышленника.',
        'Добавьте X-Frame-Options: DENY или CSP frame-ancestors.'
      )
    );
  }

  if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') {
    findings.push(
      finding(
        'low',
        'Отсутствует X-Content-Type-Options',
        'Браузер может угадывать MIME-тип, что повышает риск атак.',
        'Добавьте X-Content-Type-Options: nosniff.'
      )
    );
  }

  if (!has('referrer-policy')) {
    findings.push(
      finding(
        'low',
        'Отсутствует Referrer-Policy',
        'Возможна утечка URL во внешние ресурсы через заголовок Referer.',
        'Добавьте Referrer-Policy: no-referrer-when-downgrade или строже.'
      )
    );
  }

  if (!has('permissions-policy')) {
    findings.push(
      finding(
        'info',
        'Отсутствует Permissions-Policy',
        'Нет ограничений на использование камеры, микрофона, геолокации и др.',
        'Рассмотрите добавление Permissions-Policy.'
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
        'Раскрытие версий ПО',
        'Сервер сообщает версии ПО: ' + discloser.join('; ') + '. Это помогает подбирать эксплойты.',
        'Скройте или обобщите заголовки Server / X-Powered-By.'
      )
    );
  }

  const cors = h['access-control-allow-origin'];
  if (cors === '*' && (h['access-control-allow-credentials'] || '').toLowerCase() === 'true') {
    findings.push(
      finding(
        'high',
        'Опасная конфигурация CORS',
        'Access-Control-Allow-Origin: * вместе с Allow-Credentials: true позволяет красть данные пользователя с любого сайта.',
        'Не используйте wildcard ACAO вместе с credentials. Укажите конкретные домены.'
      )
    );
  }

  if (!findings.length) {
    findings.push(
      finding('info', 'Заголовки безопасности в порядке', 'Основные защитные заголовки присутствуют.', '')
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

function scanTls(targetUrl) {
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch (err) {
      resolve({ findings: [finding('info', 'Некорректный URL', String(err), '')], meta: {} });
      return;
    }

    if (parsed.protocol !== 'https:') {
      resolve({
        findings: [
          finding(
            'critical',
            'Сайт работает по HTTP без шифрования',
            'Трафик передаётся в открытом виде. Пароли, cookie и данные могут быть перехвачены.',
            'Никогда не вводите пароли на таком сайте. Требуется HTTPS.'
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
              'Недействительный TLS-сертификат',
              'Сертификат не прошёл проверку: ' + (authError || 'неизвестная ошибка') +
                '. Возможна атака «человек посередине» или самоподписанный сертификат.',
              'Не доверяйте сайту с невалидным сертификатом.'
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
                'Срок сертификата истёк',
                'Сертификат истёк ' + Math.abs(daysLeft) + ' дн. назад (' + cert.valid_to + ').',
                'Сайт не поддерживает безопасное соединение корректно.'
              )
            );
          } else if (daysLeft < 15) {
            findings.push(
              finding(
                'medium',
                'Сертификат скоро истечёт',
                'Осталось ' + daysLeft + ' дн. (' + cert.valid_to + ').',
                'Владельцу стоит обновить сертификат.'
              )
            );
          }
        }

        if (protocol && (protocol === 'TLSv1' || protocol === 'TLSv1.1')) {
          findings.push(
            finding(
              'high',
              'Устаревший протокол TLS',
              'Используется ' + protocol + ', который считается небезопасным.',
              'Отключите TLS 1.0/1.1, используйте TLS 1.2+.'
            )
          );
        }

        if (!findings.length) {
          findings.push(
            finding('info', 'TLS-сертификат в порядке', 'Соединение защищено валидным сертификатом (' + protocol + ').', '')
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
            'Ошибка TLS-соединения',
            'Не удалось установить защищённое соединение: ' + err.message,
            'Проверьте доступность и конфигурацию TLS сайта.'
          ),
        ],
        meta: {},
      });
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        findings: [finding('medium', 'TLS: превышено время ожидания', 'Сервер не ответил вовремя.', '')],
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
    testUrls.push({ param: 'q (добавлен)', url: u.toString(), page: parsed.toString() });
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
            'Возможный отражённый XSS в параметре «' + t.param + '»',
            'Страница: ' + t.page + '. Нагрузка вернулась без экранирования.',
            'Экранируйте вывод пользовательских данных и добавьте Content-Security-Policy.',
            {
              module: 'xss',
              param: t.param,
              location: t.url,
              where:
                'Страница «' +
                t.page +
                '», параметр «' +
                t.param +
                '». Откройте: ' +
                t.url,
              evidence: 'Неэкранированная тестовая нагрузка в HTML ответа',
              risk: 'Кража cookie/сессии, подмена страницы.',
              fixSteps: [
                'Откройте страницу: ' + t.page,
                'Найдите вывод параметра «' + t.param + '» в коде.',
                'Экранируйте вывод (htmlspecialchars и аналоги).',
                'Добавьте CSP и повторите проверку XSS.',
              ],
            }
          )
        );
      } else if (body.includes('&lt;svg') || body.includes(token)) {
        findings.push(
          finding(
            'info',
            'Параметр «' + t.param + '» отражается (экранирован) на ' + parsed.pathname,
            'Значение попадает на страницу, но экранируется.',
            'Поддерживайте экранирование вывода.',
            {
              module: 'xss',
              param: t.param,
              location: t.page,
              where: 'Страница ' + t.page + ', параметр «' + t.param + '»',
              evidence: 'Отражение есть, экранирование работает',
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
        'Отражённый XSS не обнаружен',
        'Проверено страниц: ' + pages.length + '. Неэкранированного отражения нет.',
        '',
        {
          module: 'xss',
          where: 'Просмотрены: ' + pages.slice(0, 5).join(' · ') + (pages.length > 5 ? ' …' : ''),
          evidence: 'Тестов параметров: ' + tested,
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

async function scanExposedFiles(targetUrl) {
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
      findings.push(
        finding(
          item.sev,
          'Доступен файл: ' + item.path,
          item.desc + ' Сервер ответил HTTP 200 (' + (res.bytes || 0) + ' байт).',
          item.sev === 'info'
            ? ''
            : 'Закройте этот путь: удалите файл из публичной папки или запретите доступ в Nginx/Apache.',
          {
            module: 'exposed',
            location: fullUrl,
            where:
              'Откройте в браузере этот адрес: ' +
              fullUrl +
              ' — если страница/файл скачивается или показывается текст, уязвимость подтверждена.',
            evidence: 'HTTP 200, размер ответа ≈ ' + (res.bytes || 0) + ' байт',
            risk: item.risk || '',
            fixSteps: (item.fixSteps || []).map((s) => s.replace(/ВАШ_САЙТ/g, base.hostname)),
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
          'Открыт листинг каталога /uploads/',
          'Сервер показывает список файлов в каталоге — любой может увидеть имена загруженных файлов.',
          'Отключите directory listing (Apache: Options -Indexes; Nginx: autoindex off).',
          {
            module: 'exposed',
            location: uploadsUrl,
            where: 'Откройте ' + uploadsUrl + ' — если видите «Index of /uploads», листинг включён.',
            evidence: 'В HTML найдена строка «Index of /»',
            risk: 'Утечка имён файлов, возможность скачать чужие загрузки.',
            fixSteps: [
              'В Apache добавьте Options -Indexes для этой папки.',
              'В Nginx: autoindex off;',
              'Проверьте, что ' + uploadsUrl + ' больше не показывает список файлов.',
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
      finding('info', 'Открытых чувствительных файлов не найдено', 'Проверенные типичные пути недоступны.', '')
    );
  }

  return { findings, meta: { softNotFound, checked: SENSITIVE_PATHS.length } };
}

// ---------------------------------------------------------------------------
// 5. Cookie
// ---------------------------------------------------------------------------

async function scanCookies(targetUrl) {
  const findings = [];
  const res = await rawRequest(targetUrl, { method: 'GET' });
  const isHttps = res.finalUrl.startsWith('https:');

  let setCookie = res.headers['set-cookie'];
  if (!setCookie) {
    findings.push(finding('info', 'Cookie не устанавливаются', 'Сервер не прислал заголовок Set-Cookie.', ''));
    return { findings, meta: {} };
  }
  if (!Array.isArray(setCookie)) setCookie = [setCookie];

  for (const cookie of setCookie) {
    const name = cookie.split('=')[0].trim();
    const lower = cookie.toLowerCase();
    const issues = [];
    if (isHttps && !lower.includes('secure')) issues.push('нет флага Secure');
    if (!lower.includes('httponly')) issues.push('нет флага HttpOnly (доступна из JS)');
    if (!lower.includes('samesite')) issues.push('нет атрибута SameSite (риск CSRF)');

    if (issues.length) {
      const hasHttpOnly = !lower.includes('httponly');
      findings.push(
        finding(
          hasHttpOnly ? 'medium' : 'low',
          'Небезопасная cookie: ' + name,
          'Проблемы: ' + issues.join(', ') + '.',
          'Установите флаги Secure, HttpOnly и SameSite для cookie.'
        )
      );
    }
  }

  if (!findings.length) {
    findings.push(finding('info', 'Cookie защищены корректно', 'У всех cookie выставлены безопасные флаги.', ''));
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
      tests.push({ param: 'id (добавлен)', url: u.toString(), page: parsed.toString() });
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
          'ошибка БД в HTML',
        ])[0];
        findings.push(
          finding(
            'critical',
            'Возможная SQL-инъекция в параметре «' + t.param + '»',
            'Страница: ' + t.page + '. Сервер вернул ошибку БД после спецсимволов в параметре.',
            'Используйте prepared statements и не показывайте ошибки SQL пользователю.',
            {
              module: 'sqli',
              param: t.param,
              location: t.url,
              where: 'Страница «' + t.page + '», параметр «' + t.param + '». Тест: ' + t.url,
              evidence: 'Ошибка БД: «' + String(errLine).slice(0, 80) + '»',
              risk: 'Чтение/изменение базы данных.',
              fixSteps: [
                'Откройте страницу: ' + t.page,
                'Найдите обработчик параметра «' + t.param + '».',
                'Замените склейку SQL на prepared statements.',
                'Отключите вывод ошибок БД на продакшене.',
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
        'Признаков SQL-инъекции не обнаружено',
        'Проверено страниц: ' + pages.length + '. Ошибок БД после спецсимволов нет.',
        '',
        {
          module: 'sqli',
          where: 'Просмотрены: ' + pages.slice(0, 5).join(' · ') + (pages.length > 5 ? ' …' : ''),
          evidence: 'Тестов: ' + tested,
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

async function scanPorts(targetUrl) {
  const findings = [];
  let host;
  try {
    host = new URL(targetUrl).hostname;
  } catch (err) {
    return { findings: [finding('info', 'Некорректный URL', String(err), '')], meta: {} };
  }

  const open = [];
  await mapPool(COMMON_PORTS, 12, async (p) => {
    if (await checkPort(host, p.port)) open.push(p);
  });

  for (const p of open) {
    const loc = host + ':' + p.port;
    if (p.sev === 'info') {
      findings.push(
        finding('info', 'Открыт порт ' + p.port + ' (' + p.name + ')', p.note, '', {
          module: 'ports',
          location: loc,
          where: 'Хост ' + host + ', порт ' + p.port + ' (' + p.name + ') — это нормально для сайта.',
        })
      );
    } else {
      findings.push(
        finding(
          p.sev,
          'Открыт порт ' + p.port + ' (' + p.name + ')',
          p.note + ' Порт отвечает на подключения из интернета.',
          'Закройте порт фаерволом, если он не нужен публично, или ограничьте доступ по IP.',
          {
            module: 'ports',
            location: loc,
            where:
              'Смотрите на сервере/VPS: хост «' +
              host +
              '», TCP-порт ' +
              p.port +
              ' (' +
              p.name +
              '). Это не путь в браузере, а сетевой порт машины.',
            evidence: 'TCP-подключение к ' + loc + ' успешно установлено',
            risk: p.note,
            fixSteps: [
              'В фаерволе (ufw / security group / панель хостинга) закройте входящий порт ' + p.port + ' для 0.0.0.0/0.',
              'Оставьте доступ только с вашего IP или через VPN, если порт нужен вам.',
              'Для БД (3306, 5432, 27017, 6379) снаружи порт почти никогда не должен быть открыт.',
            ],
          }
        )
      );
    }
  }

  if (!findings.length) {
    findings.push(
      finding('info', 'Лишних открытых портов не найдено', 'Проверенные служебные порты закрыты.', '')
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
            'Антибот мешает проверке админок',
            'Сайт отдаёт JS-челлендж (ddosfilter/Cloudflare и т.п.). Сначала откройте сайт во встроенном браузере, дождитесь загрузки, затем повторите проверку.',
            'Повторите скан после полной загрузки страницы в Brauser.'
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
        'Антибот мешает проверке админок',
        'Ответ на запросы — страница-челлендж, а не реальный контент. Откройте сайт в браузере Brauser и повторите проверку после загрузки.',
        'Повторите скан после прохождения антибота во встроенном браузере.'
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
        (f.cmsSpecific && cms ? cms + ': ' : '') + 'Доступна панель «' + f.label + '»: ' + f.path,
        'HTTP ' +
          f.status +
          (f.authWall ? ' (закрыта авторизацией, но путь известен)' : '') +
          (f.signed ? '. На странице обнаружена форма входа/признаки админки.' : '.') +
          ' Публично видимая админка — цель для подбора пароля.',
        'Ограничьте доступ по IP / VPN, включите 2FA и защиту от перебора. Для XenForo смените путь admin.php.',
        {
          module: 'admin',
          location: fullUrl,
          where:
            'Откройте в браузере: ' +
            fullUrl +
            ' — если видите форму входа в админку, путь найден. Именно его нужно закрыть или усилить.',
          evidence: 'HTTP ' + f.status + (f.signed ? ', признаки формы входа' : ''),
          risk: 'Брутфорс пароля администратора, захват сайта.',
          fixSteps: [
            'Сохраните этот адрес: ' + fullUrl,
            'Ограничьте доступ к нему по IP (Nginx allow/deny или Cloudflare Access).',
            'Включите 2FA для админов и сложный пароль.',
            cms === 'XenForo'
              ? 'В XenForo можно переименовать/сменить admin.php на нестандартный путь.'
              : 'Смените стандартный URL админки, если CMS это позволяет.',
          ],
        }
      )
    );
  }

  if (!findings.length) {
    findings.push(
      finding(
        'info',
        'Открытых админ-панелей не найдено',
        cms
          ? 'Проверены стандартные пути для ' + cms + ' и общие панели (phpMyAdmin и др.).'
          : 'Проверены стандартные пути популярных CMS. Движок не определён — результат менее точен.',
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
        'Сайт закрыт антиботом (челлендж)',
        'Сервер отдал страницу защиты (ddosfilter / Cloudflare и т.п.) вместо HTML сайта. Без прохождения челленджа нельзя надёжно определить CMS и админки.',
        'Откройте сайт во встроенном браузере Brauser, дождитесь полной загрузки, затем снова нажмите «Движок сайта» или «Полная проверка».'
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
  if (/jsessionid/i.test(setCookie)) add('Java (сервлеты)');

  const { cms, version, gen } = detectCmsFromBody(body, h, setCookie);
  if (cms) add('CMS: ' + cms + (version ? ' ' + version : ''));

  findings.push(
    finding(
      'info',
      cms ? 'Движок сайта: ' + cms + (version ? ' ' + version : '') : 'Явный CMS не определён',
      tech.length ? 'Обнаружено: ' + tech.join(' | ') : 'Характерных признаков движка не найдено.',
      cms
        ? 'Следите за обновлениями ' + cms + ' и плагинов — устаревшие версии имеют известные уязвимости (CVE).'
        : 'Если страница ещё грузится или стоит антибот — откройте сайт в браузере и повторите проверку.'
    )
  );

  if (version && gen) {
    findings.push(
      finding(
        'low',
        'Версия движка раскрыта в метатеге generator',
        '«' + gen + '». Это помогает злоумышленнику подобрать эксплойт под конкретную версию.',
        'Уберите метатег <meta name="generator"> из разметки.'
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
    label = 'НЕ ДОВЕРЯТЬ';
    advice = 'Обнаружены критические уязвимости. Не регистрируйтесь и не вводите личные данные.';
  } else if (counts.high > 0) {
    level = 'warning';
    label = 'ОПАСНО';
    advice = 'Есть серьёзные проблемы. Регистрация рискованна — будьте осторожны.';
  } else if (counts.medium > 0) {
    level = 'caution';
    label = 'С ОСТОРОЖНОСТЬЮ';
    advice = 'Критичных уязвимостей нет, но есть недочёты. Регистрация возможна с осторожностью.';
  } else {
    level = 'safe';
    label = 'БЕЗОПАСНО';
    advice = 'Критичных проблем не обнаружено. Сайту можно доверять.';
  }

  return { level, label, advice, score, counts };
}

async function scanAll(targetUrl, options = {}) {
  const sections = {};
  // Все модули стартуют параллельно. Админка ждёт только fingerprint (для CMS-путей).
  const fpPromise = scanFingerprint(targetUrl, options).catch((err) => ({
    findings: [finding('info', 'Проверка не выполнена (fingerprint)', String(err), '')],
    meta: {},
  }));

  const tasks = [
    ['fingerprint', fpPromise],
    ['tls', scanTls(targetUrl)],
    ['headers', scanHeaders(targetUrl)],
    ['cookies', scanCookies(targetUrl)],
  ];
  if (options.active !== false) {
    tasks.push(['xss', scanXss(targetUrl, options)]);
    tasks.push(['sqli', scanSqlInjection(targetUrl, options)]);
    tasks.push(['exposed', scanExposedFiles(targetUrl)]);
    tasks.push(['ports', scanPorts(targetUrl)]);
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
        findings: [finding('info', 'Проверка не выполнена (' + key + ')', String(r.reason), '')],
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
