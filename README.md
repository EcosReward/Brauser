<p align="center">
  <img src="docs/assets/brauser-icon.svg" width="96" alt="Brauser icon" />
</p>

<h1 align="center">Brauser — Security Laboratory Browser</h1>

<p align="center">
  <b>EN:</b> Check the site — then trust it.<br/>
  <b>RU:</b> Проверяй сайт — потом доверяй.
</p>

<p align="center">
  <img src="docs/assets/brauser-banner-en.svg" width="100%" alt="Brauser banner EN" />
</p>

## English

**Brauser** is a desktop browser + security lab. Open a website, run an audit, and get a clear verdict before you register or enter personal data.

### Features
- Chromium tabs and dark laboratory UI
- Trust score `0–100` and verdict: Safe / Caution / Do not trust
- Modules: CMS, TLS, headers, cookies, XSS, SQL injection, ports, admin panels, exposed files
- Beginner-friendly findings with exact paths and fix steps
- Collect visited pages/links, then scan XSS/SQL across them
- Per-tab reports (no mix-up between sites)

### Run
```bash
npm install
npm start
```

More promo copy: [`docs/PROMO_EN.md`](docs/PROMO_EN.md)

---

## Русский

**Brauser** — десктопный браузер-лаборатория. Откройте сайт, запустите аудит и получите понятный вердикт до регистрации и ввода данных.

<p align="center">
  <img src="docs/assets/brauser-banner-ru.svg" width="100%" alt="Brauser banner RU" />
</p>

### Возможности
- Вкладки Chromium и тёмный интерфейс лаборатории
- Индекс доверия `0–100` и вердикт: Безопасно / С осторожностью / Не доверять
- Модули: CMS, TLS, заголовки, cookie, XSS, SQL-инъекции, порты, админки, открытые файлы
- Понятные находки: точный путь, риск и шаги исправления
- Сбор посещённых страниц/ссылок и проверка XSS/SQL по ним
- Отдельный отчёт на каждую вкладку

### Запуск
```bash
npm install
npm start
```

Подробный рекламный текст: [`docs/PROMO_RU.md`](docs/PROMO_RU.md)

---

## Important / Важно

Active checks send real test requests. Use only on sites you own or have permission to test.

Активные проверки отправляют тестовые запросы. Используйте только на своих сайтах или с разрешением.

## License

MIT
