# Security Policy & Hardening Guide

This document outlines the security architecture and defensive controls for the PSE&G Auth Companion service (`ha-pseg-auth-addon`).

## Threat Model & Boundary

The companion service provides automated authentication against the PSE&G and MyMeter portals via headless Chromium. It listens on port 8000 for requests initiated by the Home Assistant integration.

### Core Defensive Controls

1. **Principle of Least Privilege (Container Isolation)**:
   - The add-on runs as an isolated service container.
   - External filesystem mounts (`homeassistant_config`, `share`) are removed from the add-on manifest.
   - The service only stores transient browser session state within `/data/browser_data`.

2. **reCAPTCHA Audio URL Verification (SSRF Prevention)**:
   - Audio challenge URLs extracted from the reCAPTCHA iframe are strictly validated before download.
   - Schemes must be `https://`.
   - Hostnames must match trusted Google domains (`www.google.com`, `google.com`, `www.recaptcha.net`, `recaptcha.net`).
   - Local file schemes (`file://`), unencrypted HTTP (`http://`), and arbitrary IP addresses are rejected.

3. **Safe Temporary File Handling**:
   - Audio challenge files are created using atomic, randomly named temporary files via Python's `tempfile` module.
   - Temporary files are explicitly purged within `finally` blocks upon completion or failure.

4. **Credential & Sensitive Data Redaction**:
   - One-Time Passcode (OTP) values are never written to standard logs or console output.
   - Log output records operational state and flow checkpoints without logging verification tokens or raw credentials.

5. **Request Body Bounds & DoS Prevention**:
   - POST request bodies are capped at 64 KB, mitigating memory exhaustion risks.
   - Non-integer or malformed `Content-Length` headers are rejected with `400 Bad Request`.


## Sentinel Security Learnings

### 2026-10-30 - Audio reCAPTCHA SSRF and Protocol Hijacking
- **Vulnerability:** `urllib.request.urlretrieve` accepts any URL scheme, including `file://`, `ftp://`, or internal private network IPs. When parsing the iframe DOM for the audio challenge source, unvalidated URLs could lead to local file reads or internal SSRF.
- **Learning:** Browser automation scrapers often treat DOM attributes as semi-trusted internal data, but any dynamic attribute passed to network fetchers must be scheme- and host-validated.
- **Prevention:** Explicitly validate protocol schemes (`https://` only) and whitelist authorized CDN/API hostnames (`ALLOWED_RECAPTCHA_HOSTS`) before passing URLs to downloaders.
