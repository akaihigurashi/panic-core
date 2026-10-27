<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.png">
    <img alt="panic-core" src="docs/logo-light.png" width="285">
  </picture>
</h1>

The shared engine behind the [shouldipanic.ch](https://shouldipanic.ch) scanners
([php2scan](https://github.com/akaihigurashi/php2scan),
[brotli2scan](https://github.com/akaihigurashi/brotli2scan), ...).

Every scanner is published as **one Python file with no dependencies**. This
repository holds what they have in common, and `bundle.py` combines it with a
scanner's own `check.py` into that single file.

| Path | What |
|---|---|
| `core/engine.py` | Fetching (connection pinned to the checked IP, redirects only on the same server, foreign URLs ignored), fingerprint matching, TCP port scan, vhost discovery (TLS certificates, SNI, redirects, PTR, passive DNS, certificate transparency), command-line interface |
| `core/web.py` | Public web page server: consent, audit log, VPN/Tor/datacenter blocking, rate limit, cache, never-check lists, SSRF protection |
| `vendor/webappanalyzer/` | Fingerprint database ([webappanalyzer](https://github.com/enthec/webappanalyzer), GPL-3.0) |
| `templates/scanner/` | Dockerfile, Compose file, GitHub workflows and nginx example for a scanner repo |
| `bundle.py` | Builds `<scanner>.py` and `web.py` |

## Building a scanner

```bash
python3 bundle.py ../php2scan/check.py           # writes ../php2scan/php2scan.py and web.py
python3 bundle.py ../php2scan/check.py --check   # exit 1 if they are out of date (used in CI)
python3 bundle.py --update-db                    # refresh the vendored fingerprint database
```

The embedded fingerprint database only contains the technologies a scanner
needs: its `TARGETS` and everything that runs on them (webappanalyzer's
`implies`).

## A new scanner

```bash
mkdir ../newscan && cp ../brotli2scan/check.py ../newscan/   # start from an existing check
python3 bundle.py ../newscan/check.py --scaffold --port 8090 --title "Check websites for ..."
```

`--scaffold` adds the Dockerfile, Compose file, workflows and nginx example.
Then write `static/index.html`, `app.js` and `style.css` for the page.

A `check.py` defines:

| Name | Purpose |
|---|---|
| module docstring | Usage text at the top of the bundled file |
| `NAME`, `VERSION`, `DESCRIPTION` | Identity, banner, user agent, cache directory |
| `TARGETS` | Technologies whose database rules are embedded (with everything implying them) |
| `FINGERPRINTS` | Hand-written rules `(technology, "header"/"cookie"/"body", regex)`; a capture group is the version |
| `IMPLIES` | Extra "X always runs on Y" rules |
| `BANNER`, `BANNER_COLOR`, `BANNER_TAGS`, `BUILTIN_LABEL`, `APPS_LABEL`, `COLUMNS` | Command-line look and CSV columns |
| `verdict(info)` | Returns `(verdict, version, technologies)` for the result row |
| `count_key(verdict)` | Groups verdicts in the summary line |
| `post_fingerprint(info)` | Optional: extra detection after the rules ran |
| `probe(info)` | Optional: active check, runs only when the `probe` option is set |
| `add_arguments(ap)`, `options_from_args(a)` | Optional: extra command-line options |
| `CONSENT_VERSION`, `WHERE`, `web_options`, `web_result`, `web_timeout_result`, `audit_fields` | The web page: options it accepts, result JSON, audit log fields |

`info` is a dict with the final URL, status, headers, cookies, page body (foreign
URLs removed), found technologies with versions and evidence, implied
technologies, the pinned server IP, timeout and a debug logger.

In the bundled file the check runs in the same namespace as the engine, so it
can use `http_request`, `resolve`, `explain` and the rest directly.

## License

GPL-3.0, see [LICENSE](LICENSE).
