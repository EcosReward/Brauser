# Brauser — Security Laboratory Browser

## Short description (store / GitHub)

**Brauser** is a desktop security-lab browser that helps you audit websites before you register or enter personal data. Open a page, run a scan, and get a clear verdict: safe, caution, or do not trust.

## Tagline

- **Primary:** Check the site — then trust it.
- **Alternatives:**
  - A browser that thinks about security for you.
  - Security lab inside normal browsing.
  - Spot the vulnerability — keep your data.

## Full description

Brauser combines everyday web browsing with a built-in security audit lab. Browse your site, collect links, run a full check or individual modules, and immediately see what is unsafe.

Every finding is explained in plain language: **where to look**, **which path to close**, **why it is dangerous**, and **step-by-step fixes**. Severity levels help you decide whether registration is safe.

Ideal for site owners, admins, freelancers, and anyone who wants a fast risk check before sharing passwords or personal information.

## Key features

- Built-in Chromium browser with tabs
- Security verdict and trust score (0–100)
- Modules: CMS/fingerprint, TLS, headers, cookies, XSS, SQL injection, open ports, admin panels, exposed files
- Beginner-friendly reports with exact URLs/paths
- Visited-page and link collection for XSS/SQL checks
- Per-tab report isolation
- Dark laboratory UI

## Who it is for

- Site owners before launch/release
- Anyone verifying a landing page before collecting user signups
- Security beginners who need plain explanations

## How to use (30 seconds)

1. Open a site in a Brauser tab  
2. Browse sections (or click “Collect links”)  
3. Press **Full security check**  
4. Read the verdict and findings on the right  

## Run

```bash
npm install
npm start
```

## Important

Active checks (XSS, SQL, ports, admin panels, files) send test requests. Use only on sites you own or have explicit permission to test.

## Hashtags

`#Brauser` `#cybersecurity` `#websiteaudit` `#XSS` `#SQLi` `#devtools` `#electron`
