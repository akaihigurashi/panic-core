# ===========================================================================
# panic-core engine: fetching, fingerprinting, port scan, vhost discovery, CLI.
# Generic part shared by every scanner; the scanner-specific part (its
# fingerprints, verdicts and optional probe) is the check module.
# https://github.com/akaihigurashi/panic-core
# ===========================================================================
import argparse
import concurrent.futures as cf
import csv
import fnmatch
import functools
import glob
import hashlib
import http.client
import ipaddress
import itertools
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

MAX_BODY = 1_500_000
UA = "Mozilla/5.0 (compatible; panic-core; security check)"   # set from the check's NAME in init()

# --- fingerprint database: open Wappalyzer fork "webappanalyzer" (GPL-3.0) ---
# A subset is embedded by the bundler (EMBEDDED_RULES); -U downloads a fresher copy.
RULES_URL = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/{}.json"
RULES_FILES = ["_"] + [chr(c) for c in range(ord("a"), ord("z") + 1)]
RULES_DIR = ""      # ~/.cache/<scanner>/technologies, set in init()
DB_RULES = []       # (tech, kind, key, regex, version_template)
DB_IMPLIES = {}     # tech -> [implied techs] (from the database)
COMPILED = []       # built-in rules of the check, compiled


def init():
    """Called once after the check module is loaded."""
    global UA, RULES_DIR, COMPILED
    UA = f"Mozilla/5.0 (compatible; {NAME}/{VERSION}; security check)"
    RULES_DIR = os.path.join(os.path.expanduser("~"), ".cache", NAME, "technologies")
    COMPILED = [(t, w, re.compile(p, re.I | re.M)) for t, w, p in FINGERPRINTS]


APPS_LABEL = "APPS"          # header of the 3rd output column (a check may override it)


def builtin_count():
    return len({t for t, _, _ in FINGERPRINTS if t not in TARGETS})


def update_rules(dest=None):
    dest = dest or RULES_DIR
    os.makedirs(dest, exist_ok=True)
    ok = 0
    for name in RULES_FILES:
        url = RULES_URL.format(name)
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                data = r.read()
            json.loads(data)                       # validate before saving
            with open(os.path.join(dest, f"{name}.json"), "wb") as f:
                f.write(data)
            ok += 1
        except Exception as e:  # noqa: BLE001
            print(f"  failed {url}: {e}", file=sys.stderr)
    print(f"Downloaded {ok}/{len(RULES_FILES)} rule files to {dest}", file=sys.stderr)
    return ok == len(RULES_FILES)


def load_rules(path=None):
    """Load every technology that is one of the check's TARGETS or runs on one of them
    (directly or via 'implies'). Uses a downloaded database (-U / --rules) if present,
    else the embedded one. Returns (number of technologies, source description)."""
    path = path or RULES_DIR
    files = [path] if os.path.isfile(path) else sorted(glob.glob(os.path.join(path, "*.json")))
    techs = {}
    for f in files:
        with open(f, encoding="utf-8") as fh:
            techs.update(json.load(fh))
    if techs:
        newest = max(os.path.getmtime(f) for f in files)
        source = f"downloaded database ({time.strftime('%Y-%m-%d', time.localtime(newest))})"
    else:
        techs = json.loads(EMBEDDED_RULES)
        source = f"embedded database ({EMBEDDED_RULES_DATE})"
    return _load_techs(techs), source


def tech_implies(techs, t):
    v = techs.get(t, {}).get("implies", [])
    return [x.split("\\;")[0] for x in ([v] if isinstance(v, str) else v)]


def closure(techs, targets):
    """The targets plus every technology that implies one of them (transitively,
    e.g. Plugin -> WordPress -> PHP)."""
    found = set(targets)
    changed = True
    while changed:
        changed = False
        for t in techs:
            if t not in found and any(i in found for i in tech_implies(techs, t)):
                found.add(t)
                changed = True
    return found


def _load_techs(techs):
    DB_RULES.clear()
    DB_IMPLIES.clear()
    wanted = closure(techs, TARGETS)
    for t in wanted:
        DB_IMPLIES[t] = tech_implies(techs, t)

    def as_list(v):
        return [v] if isinstance(v, str) else (v or [])

    def add(tech, kind, key, pattern):
        pat, _, rest = pattern.partition("\\;")
        ver = ""
        for part in rest.split("\\;"):
            if part.startswith("version:"):
                ver = part[8:]
        try:
            rx = re.compile(pat, re.I) if pat else None
        except re.error:
            return                       # JS-only regex syntax: skip
        DB_RULES.append((tech, kind, key, rx, ver))

    for t in wanted:
        d = techs.get(t, {})
        for k, v in (d.get("headers") or {}).items():
            add(t, "header", k.lower(), v)
        for k, v in (d.get("cookies") or {}).items():
            add(t, "cookie", k, v)
        for k, v in (d.get("meta") or {}).items():
            for p in as_list(v):
                add(t, "meta", k.lower(), p)
        for p in as_list(d.get("html")):
            add(t, "html", "", p)
        for p in as_list(d.get("scriptSrc")):
            add(t, "script", "", p)
        for p in as_list(d.get("url")):
            add(t, "url", "", p)
    return len(wanted - set(TARGETS))


def parse_response(final, hdr, cookie, body):
    """Structured view of a response for the database rules."""
    headers = {}
    for line in hdr.splitlines():
        k, _, v = line.partition(": ")
        headers.setdefault(k.lower(), []).append(v)
    cookies = {}
    for line in cookie.splitlines():
        name, _, val = line.split(";", 1)[0].partition("=")
        cookies[name.strip()] = val.strip()
    metas = {}
    for tag in re.findall(r"<meta\s[^>]*>", body, re.I):
        name = re.search(r"""(?:name|property|http-equiv)\s*=\s*["']([^"']+)""", tag, re.I)
        content = re.search(r"""content\s*=\s*["']([^"']*)""", tag, re.I)
        if name:
            metas.setdefault(name.group(1).lower(), []).append(content.group(1) if content else "")
    scripts = re.findall(r"""<script[^>]+src\s*=\s*["']([^"']+)""", body, re.I)
    return headers, cookies, metas, scripts


def match_db(final, hdr, cookie, body):
    """Yield (tech, where, matched_text, version) for database rules."""
    if not DB_RULES:
        return
    headers, cookies, metas, scripts = parse_response(final, hdr, cookie, body)
    for tech, kind, key, rx, ver in DB_RULES:
        if kind == "header":
            values = headers.get(key, [])
        elif kind == "cookie":
            values = [v for n, v in cookies.items() if fnmatch.fnmatch(n, key)]
        elif kind == "meta":
            values = metas.get(key, [])
        elif kind == "html":
            values = [body]
        elif kind == "script":
            values = scripts
        else:
            values = [final]
        for v in values:
            m = rx.search(v) if rx else True
            if not m:
                continue
            version = ""
            if rx and ver and "\\1" in ver and m.lastindex:
                version = m.group(1) or ""
            text = (m.group(0) if rx else f"{key} present")[:90]
            yield tech, f"db-{kind}", text, version
            break


def make_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False          # fingerprinting only: don't skip
    ctx.verify_mode = ssl.CERT_NONE     # customers with broken certificates
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")   # also talk to old servers
    except ssl.SSLError:
        pass
    return ctx


TLS_CTX = make_ctx()


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a fixed IP while sending another name via SNI (vhost scanning)."""

    def __init__(self, ip, port, sni, timeout):
        super().__init__(ip, port, timeout=timeout, context=TLS_CTX)
        self._sni = sni

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = TLS_CTX.wrap_socket(sock, server_hostname=self._sni or None)


def http_request(url, timeout, pin=None, method="GET", body=None, headers=None):
    """One request without redirects. pin: {hostname: ip} -> connect to that IP but
    send the hostname as Host header and SNI. Returns (connection, response)."""
    u = urlparse(url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    ip = (pin or {}).get(host.lower(), host)
    sni = host if not is_ip(host) else None
    if u.scheme == "https":
        conn = PinnedHTTPSConnection(ip, port, sni, timeout)
    else:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    host_hdr = host if ":" not in host else f"[{host}]"
    if u.port and u.port not in (80, 443):
        host_hdr += f":{u.port}"
    hdrs = {"Host": host_hdr, "User-Agent": UA, "Accept": "text/html,*/*", "Connection": "close"}
    hdrs.update(headers or {})
    conn.request(method, path, body=body, headers=hdrs)
    resp = conn.getresponse()
    return conn, resp


def http_get(url, timeout, pin=None):
    return http_request(url, timeout, pin)


def is_ip(s):
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False


RESULT_META = {}   # target -> (body hash, <title>) to spot vhosts that just show the default site

# absolute or protocol-relative URL: https://host, http://host, //host  (also JSON-escaped)
URL_HOST_RX = re.compile(r"(?:https?:)?//([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?|\[[0-9a-f:.]+\])(?::\d+)?"
                         r"(?:[/?#][^\s\"'<>()\\,]*)?", re.I)   # host + the whole rest of the URL


def local_view(body, host, server_ips):
    """Return the page with every URL to ANOTHER server replaced by //external.invalid.
    A URL counts as local if its host is the page's own host (with/without www.),
    or a hostname that resolves to the scanned server's IP."""
    host = host.lower()
    me = {host, host[4:] if host.startswith("www.") else "www." + host}
    verdict = {}
    dropped = set()

    def is_local(h):
        h = h.lower().strip("[]")
        if h in me or h in server_ips:
            return True
        if h not in verdict:
            if is_ip(h) or "." not in h:
                verdict[h] = False
            else:
                verdict[h] = bool(server_ips and set(resolve(h)) & server_ips)
        return verdict[h]

    def repl(m):
        if is_local(m.group(1)):
            return m.group(0)
        dropped.add(m.group(1).lower())
        return "//external.invalid/"              # host AND path removed

    text = body.replace("\\/", "/")               # JSON-escaped URLs: https:\/\/host\/...
    return URL_HOST_RX.sub(repl, text), dropped



DEBUG = 0
PRINT_LOCK = threading.Lock()


def print_banner():
    """Banner goes to stderr so piped/redirected results stay clean."""
    color = sys.stderr.isatty()
    g, d, r = (f"\033[1;{BANNER_COLOR}m", f"\033[2;{BANNER_COLOR}m", "\033[0m") if color else ("", "", "")
    print(f"{g}{BANNER}{r}", file=sys.stderr)
    for line in BANNER_TAGS + [f"authorized targets only  ::  v{VERSION}"]:
        print(f"{d}  [ {line:<52} ]{r}", file=sys.stderr)
    print(file=sys.stderr, flush=True)


def explain(e):
    """Turn a network exception into a short reason plus a hint."""
    reason = getattr(e, "reason", e)
    text = " ".join(f"{type(e).__name__}: {reason}".split())   # no stray newlines
    s = str(reason).lower()
    if isinstance(reason, socket.timeout) or "timed out" in s:
        hint = "timeout: host silent or port filtered by a firewall (try a larger -t)"
    elif "refused" in s:
        hint = "connection refused: nothing listening on that port"
    elif "name or service not known" in s or "nodename nor servname" in s or "getaddrinfo" in s:
        hint = "DNS: hostname does not resolve"
    elif "no route" in s or "unreachable" in s:
        hint = "network unreachable: routing or firewall"
    elif isinstance(reason, ssl.SSLError) or "ssl" in s or "tls" in s:
        hint = "TLS handshake failed: old protocol/cipher, or port is not HTTPS"
    elif "reset" in s:
        hint = "connection reset: WAF/firewall or server closed it"
    elif "remote end closed" in s or "badstatusline" in s:
        hint = "server closed connection without a valid HTTP reply"
    else:
        hint = ""
    return text, hint


META_REFRESH_RX = re.compile(
    r"""<meta(?=[^>]*http-equiv\s*=\s*["']?refresh)[^>]*content\s*=\s*["']?\s*\d*\s*;?\s*url\s*=\s*['"]?([^"'>\s]+)""",
    re.I)
JS_REDIRECT_RX = re.compile(
    r"""(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']"""
    r"""|location\.(?:replace|assign)\(\s*["']([^"']+)["']\s*\)""", re.I)


def body_redirect(body):
    """Target of a client-side redirect in a small placeholder page, else None.
    Only small pages count, so a big site with some location= in its JS isn't 'redirected'."""
    if len(body) > 4096:
        return None
    m = META_REFRESH_RX.search(body)
    if m:
        return m.group(1)
    m = JS_REDIRECT_RX.search(body)
    if m:
        return m.group(1) or m.group(2)
    return None


def fetch(url, timeout, log, pin=None, pin_out=None):
    """GET url, follow up to 5 redirects manually so every Set-Cookie is kept.

    Redirects are only followed while they stay on the SAME SERVER (same IP):
    hosts in pin are reached on their pinned IP, other hostnames only if they
    resolve to the scanned IP. A redirect to another server is reported, not
    followed, so results always describe the scanned server.
    Returns (final_url, status, headers, cookies, body, server, locations, offsite_url)."""
    headers, cookies, locations = [], [], []
    pin = dict(pin or {})
    if pin_out is not None:                  # caller wants to know which IPs were used
        pin_out.clear()
        pin_out.update(pin)
        pin = pin_out
    first = (urlparse(url).hostname or "").lower()
    if pin:
        server_ips = set(pin.values())
    elif is_ip(first):
        server_ips = {first.strip("[]")}
    else:
        server_ips = set(resolve(first))
        if server_ips:                       # keep talking to the IP we resolved first
            pin[first] = sorted(server_ips)[0]
    for hop in range(6):
        h = (urlparse(url).hostname or "").lower()
        via = f"  via {pin[h]}" if pin and h in pin else ""
        log(f"  -> GET {url}{via}" + (f"  (redirect {hop})" if hop else ""))
        t0 = time.monotonic()
        conn, resp = http_get(url, timeout, pin)
        try:
            hdrs = resp.getheaders()
            log(f"     HTTP {resp.status} in {time.monotonic() - t0:.2f}s")
            for k, v in hdrs:
                log(f"     < {k}: {v}")
            headers += [f"{k.lower()}: {v}" for k, v in hdrs]
            cookies += [v for k, v in hdrs if k.lower() == "set-cookie"]
            loc = resp.getheader("Location")
            body = ""
            if resp.status in (301, 302, 303, 307, 308) and loc:
                nxt = urljoin(url, loc)
            else:
                body = resp.read(MAX_BODY).decode("utf-8", "replace")
                log(f"     body: {len(body)} chars")
                # client-side redirect in a small placeholder page (meta refresh or
                # window.location), e.g. Nextcloud's static index.html -> index.php
                target = body_redirect(body) if hop < 5 else None
                if not target:
                    return (url, resp.status, "\n".join(headers), "\n".join(cookies), body,
                            resp.getheader("Server", ""), locations, "")
                nxt = urljoin(url, target)
                log(f"     client-side redirect in page -> {nxt}")
            locations.append(nxt)
            if urlparse(nxt).scheme not in ("http", "https"):
                log(f"     redirect to non-HTTP target ignored: {nxt}")
                return (url, resp.status, "\n".join(headers), "\n".join(cookies), body,
                        resp.getheader("Server", ""), locations, "")
            nh = (urlparse(nxt).hostname or "").lower().strip("[]")
            if nh not in pin and nh not in server_ips:
                target_ips = set(resolve(nh)) if not is_ip(nh) else {nh}
                if server_ips and target_ips & server_ips:
                    pin[nh] = pin.get(first) or sorted(server_ips)[0]   # same server: follow
                else:
                    log(f"     redirect to another server ({nh} -> "
                        f"{','.join(sorted(target_ips)) or 'no dns'}): not followed")
                    return (url, resp.status, "\n".join(headers), "\n".join(cookies), body,
                            resp.getheader("Server", ""), locations, nxt)
            if nxt == url:                      # page refreshing itself: done
                return (url, resp.status, "\n".join(headers), "\n".join(cookies), body,
                        resp.getheader("Server", ""), locations, "")
            url = nxt
            continue
        finally:
            conn.close()
    log("     too many redirects, stopped")
    return url, 0, "\n".join(headers), "\n".join(cookies), "", "", locations, ""


SNI_ONLY = set()   # "ip:port" endpoints whose TLS only works with a hostname


def is_sni_reject(e):
    """Handshake aborted by the server (no alert, or 'unrecognized name'/'handshake failure'),
    which is how nginx/Apache react to a missing or unknown SNI hostname."""
    # urllib wraps errors in URLError(.reason = exception); ssl.SSLError's own .reason is a
    # string like "TLSV1_UNRECOGNIZED_NAME" - so look at the exception objects, not .reason
    errs = [e] + ([e.reason] if isinstance(getattr(e, "reason", None), BaseException) else [])
    for x in errs:
        s = f"{type(x).__name__} {x} {getattr(x, 'reason', '')}".upper()
        if isinstance(x, (ssl.SSLError, ConnectionResetError)) and any(
                k in s for k in ("EOF", "UNRECOGNIZED_NAME", "HANDSHAKE_FAILURE",
                                 "INTERNAL_ERROR", "CONNECTIONRESET")):
            return True
    return False


INFO = {}          # target -> full result details (only filled when KEEP_INFO is set, web server)
KEEP_INFO = False


def check(target, timeout, options=None):
    """Check one endpoint. Returns the result row
    [target, final_url, status, verdict, version, apps, server, evidence]."""
    lines = []
    log = lines.append if DEBUG else (lambda _m: None)
    try:
        return _check(target, timeout, log, options or {})
    finally:
        if DEBUG:
            with PRINT_LOCK:
                print(f"\n[DEBUG] {target}", file=sys.stderr)
                print("\n".join(lines), file=sys.stderr, flush=True)


def _check(target, timeout, log, options):
    target = target.strip()
    pin = None
    if "://" in target:
        urls = [target]
    else:
        vhost, addr = (target.split("@", 1) + [None])[:2] if "@" in target else (None, target)
        ip, port = split_hostport(addr)
        if vhost:                          # vhost@ip:port -> Host/SNI = vhost, connect to ip
            pin = {vhost.lower(): ip}
            name = vhost if port is None else f"{vhost}:{port}"
        else:
            name = addr
        if port == 80:
            urls = [f"http://{name}/"]
        elif port == 443:
            urls = [f"https://{name}/"]
        else:   # unknown port: try TLS first, then plain HTTP
            urls = [f"https://{name}/", f"http://{name}/"]
    errors, sni_rejected = [], False
    for url in urls:
        try:
            used_pin = {}
            final, status, hdr, cookie, body, server, locations, offsite = fetch(url, timeout, log, pin, used_pin)
            break
        except Exception as e:  # noqa: BLE001 - report any network error
            text, hint = explain(e)
            scheme = urlparse(url).scheme
            # TLS server that hangs up / refuses when we connect WITHOUT a hostname:
            # nginx "ssl_reject_handshake on" or no default certificate. It is an HTTPS
            # server - it just only answers for its configured vhosts.
            if scheme == "https" and is_sni_reject(e) and is_ip(urlparse(url).hostname or ""):
                sni_rejected = True
                hint = "TLS refused without a hostname (SNI): server only answers for its vhosts"
            log(f"     ERROR {text}")
            if hint:
                log(f"     hint: {hint}")
            if DEBUG >= 2:
                log("     " + traceback.format_exc().strip().replace("\n", "\n     "))
            errors.append(f"{scheme}: {hint or text}")
    else:
        if sni_rejected:
            SNI_ONLY.add(target)
            return [target, "", "", "SNI ONLY", "", "", "",
                    "HTTPS needs a hostname (SNI) - see vhost results"]
        return [target, "", "", "ERROR", "", "", "", " | ".join(errors)]

    title = re.search(r"<title[^>]*>([^<]{0,200})", body, re.I)
    RESULT_META[target] = {
        "hash": hashlib.sha1(re.sub(r"\s+", "", body).encode()).hexdigest(),
        "title": (title.group(1).strip() if title else ""),
        "status": status,
        "hosts": {(urlparse(u).hostname or "").lower() for u in locations + [final]},
    }

    # Only this server's own content counts: neutralize every URL that points to
    # another server (images, scripts, CSS, iframes, links from e.g. a WordPress
    # elsewhere), so path rules like /wp-content/ can't match foreign resources.
    fhost = (urlparse(final).hostname or "").lower().strip("[]")
    if pin:
        server_ips = set(pin.values())
    elif is_ip(fhost):
        server_ips = {fhost}
    else:
        server_ips = set(resolve(fhost))
    local, dropped = local_view(body, fhost, server_ips)
    if dropped:
        log(f"  ignored {len(dropped)} external host(s): {', '.join(sorted(dropped)[:8])}"
            + (" ..." if len(dropped) > 8 else ""))

    techs, evidence, versions = [], [], {}
    if offsite:
        evidence.append(f"redirects to other server: {offsite}")
    src = {"header": hdr, "cookie": cookie, "body": local}
    for tech, where, rx in COMPILED:
        m = rx.search(src[where])
        if not m:
            continue
        if m.lastindex and m.group(1):
            versions[tech] = m.group(1)
        if tech not in techs:
            techs.append(tech)
        evidence.append(f"{tech}:{where}")
        log(f"  match {tech:<20} in {where:<6}: {m.group(0)[:90]!r}")

    # fingerprint database
    known = {t.lower() for t in techs}
    for tech, where, text, ver in match_db(final, hdr, cookie, local):
        # same product, different spelling ("TYPO3" built-in vs "TYPO3 CMS" in the database)
        for t in techs:
            tl, dl = t.lower(), tech.lower()
            if t != tech and (dl.startswith(tl + " ") or tl.startswith(dl + " ")):
                tech = t
                break
        if ver:
            versions.setdefault(tech, ver)
        if tech.lower() not in known:
            techs.append(tech)
            known.add(tech.lower())
        evidence.append(f"{tech}:{where}")
        log(f"  match {tech:<20} in {where:<9}: {text!r}" + (f"  version {ver}" if ver else ""))

    info = {"target": target, "final": final, "status": status, "server": server,
            "headers": hdr, "cookies": cookie, "body": local, "pin": used_pin, "timeout": timeout,
            "server_ips": server_ips,
            "log": log, "options": options, "offsite": offsite,
            "techs": techs, "versions": versions, "evidence": evidence, "implied": {}, "notes": []}
    hook = globals().get("post_fingerprint")
    if hook:
        hook(info)
    # technologies implied by what was found ("Express always runs on Node.js")
    implied = info["implied"]
    todo = list(techs)
    while todo:
        t = todo.pop()
        for i in DB_IMPLIES.get(t, []) + IMPLIES.get(t, []):
            if i not in techs and i not in implied:
                implied[i] = t
                todo.append(i)
    if not [e for e in evidence if not e.startswith("redirects to")]:
        log("  no fingerprint matched")
    probe_fn = globals().get("probe")
    if probe_fn and options.get("probe"):
        try:
            probe_fn(info)
        except Exception as e:  # noqa: BLE001
            text, hint = explain(e)
            log(f"  probe failed: {text}")
            info["probe"] = {"result": "error", "detail": hint or text}

    verdict_, version, apps = verdict(info)
    if KEEP_INFO:
        INFO[target] = info
    return [target, final, status, verdict_, version, ", ".join(apps), server,
            ", ".join(dict.fromkeys(evidence))]


def expand(arg):
    """An IP, IP range (CIDR), hostname, URL, or a file containing any of these."""
    import ipaddress, os
    if os.path.isfile(arg):
        out = []
        with open(arg, encoding="utf-8") as f:
            for l in f:
                l = l.strip()
                if l and not l.startswith("#"):
                    out += expand(l)
        return out
    if "/" in arg and "://" not in arg:
        try:
            net = ipaddress.ip_network(arg, strict=False)
            hosts = list(net.hosts()) or [net.network_address]
            return [f"[{h}]" if h.version == 6 else str(h) for h in hosts]
        except ValueError:
            pass
    return [arg]


# Common web ports: standard, alternate HTTP/HTTPS, and hosting panels
# (cPanel 2082/2083, WHM 2086/2087, DirectAdmin 2222, Plesk 8443/8880,
#  CyberPanel 8090, LiteSpeed WebAdmin 7080)
DEFAULT_PORTS = "80,443,81,2082,2083,2086,2087,2222,3000,4443,7080,8000,8008,8080,8081,8090,8443,8880,8888,9443"


def parse_ports(spec):
    spec = spec.strip().lower()
    if spec in ("all", "-", "1-65535"):
        return list(range(1, 65536))
    if spec == "web":
        spec = DEFAULT_PORTS
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            ports += range(lo, hi + 1)
        else:
            ports.append(int(part))
    return list(dict.fromkeys(p for p in ports if 0 < p < 65536))


def split_hostport(t):
    """'1.2.3.4' -> ('1.2.3.4', None); 'host:8080' -> ('host', 8080); '[::1]:443' -> ('::1', 443)."""
    if t.startswith("["):
        host, _, rest = t[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
    if t.count(":") == 1:
        host, port = t.split(":")
        return host, int(port) if port.isdigit() else None
    return t, None


def port_open(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def max_sockets():
    """How many parallel connections the OS allows us (open-file limit)."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = 4096
        if soft < want and (hard == resource.RLIM_INFINITY or hard > soft):
            new = want if hard == resource.RLIM_INFINITY else min(want, hard)
            resource.setrlimit(resource.RLIMIT_NOFILE, (new, hard))
            soft = new
        return max(50, soft - 100)
    except Exception:  # noqa: BLE001 - Windows has no resource module
        return 500


def scan(items, workers, timeout):
    """TCP connect scan. items: iterable of (target, host, port). Streams work so
    even a full 65535-port scan of many hosts stays small in memory."""
    total = len(items)
    open_ports, done, last_pct = {}, 0, -1
    t0 = time.monotonic()

    def probe(item):
        t, h, p = item
        return t, p, port_open(h, p, timeout)

    it = iter(items)
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        pending = {ex.submit(probe, x) for x in itertools.islice(it, workers * 2)}
        while pending:
            finished, pending = cf.wait(pending, return_when=cf.FIRST_COMPLETED)
            for f in finished:
                t, p, ok = f.result()
                done += 1
                if ok:
                    open_ports.setdefault(t, []).append(p)
                    if DEBUG:
                        print(f"\r[SCAN] open {t}:{p}" + " " * 20, file=sys.stderr, flush=True)
                nxt = next(it, None)
                if nxt is not None:
                    pending.add(ex.submit(probe, nxt))
            pct = done * 100 // total
            if pct != last_pct and sys.stderr.isatty():
                last_pct = pct
                el = time.monotonic() - t0
                eta = el / done * (total - done) if done else 0
                n_open = sum(len(v) for v in open_ports.values())
                print(f"\r  scan {pct:3d}%  {done}/{total} probes  {n_open} open  ETA {eta:5.0f}s ",
                      end="", file=sys.stderr, flush=True)
    if sys.stderr.isatty():
        print(file=sys.stderr)
    return open_ports


# --- vhost discovery -------------------------------------------------------

HOSTNAME_RX = re.compile(r"^(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$", re.I)


def _der_len(b, i):
    n = b[i]
    i += 1
    if n < 0x80:
        return n, i
    k = n & 0x7F
    return int.from_bytes(b[i:i + k], "big"), i + k


def cert_names_from_der(der):
    """Hostnames from a DER certificate: subjectAltName dNSNames + CommonName."""
    names = set()
    k = der.find(b"\x06\x03\x55\x1d\x11")             # OID 2.5.29.17 subjectAltName
    if k >= 0:
        try:
            i = k + 5
            if der[i] == 0x01:                           # optional 'critical' BOOLEAN
                ln, i2 = _der_len(der, i + 1)
                i = i2 + ln
            if der[i] == 0x04:                           # OCTET STRING
                ln, i = _der_len(der, i + 1)
                seq = der[i:i + ln]
                if seq and seq[0] == 0x30:
                    sl, j = _der_len(seq, 1)
                    end = j + sl
                    while j < end:
                        tag = seq[j]
                        ln, j2 = _der_len(seq, j + 1)
                        if tag == 0x82:                  # dNSName
                            names.add(seq[j2:j2 + ln].decode("ascii", "ignore"))
                        j = j2 + ln
        except IndexError:
            pass
    for m in re.finditer(rb"\x06\x03\x55\x04\x03[\x0c\x13\x16](.)", der, re.S):   # CN
        ln = m.group(1)[0]
        names.add(der[m.end():m.end() + ln].decode("utf-8", "ignore"))
    return {n.strip().lower() for n in names if HOSTNAME_RX.match(n.strip())}


def cert_names(ip, port, sni, timeout):
    """Names in the certificate the server presents for sni. None = no TLS on this port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with TLS_CTX.wrap_socket(s, server_hostname=sni) as t:
                der = t.getpeercert(binary_form=True)
        return cert_names_from_der(der) if der else set()
    except (OSError, ValueError):
        return None


@functools.lru_cache(maxsize=20000)
def resolve(name):
    try:
        return frozenset(ai[4][0] for ai in socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP))
    except (OSError, UnicodeError):
        return frozenset()


def reverse_dns(ip):
    try:
        n, aliases, _ = socket.gethostbyaddr(ip)
        return {n, *aliases}
    except (OSError, UnicodeError):
        return set()


def base_domain(name):
    parts = name.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "net", "org", "ac", "gov", "edu"):
        return ".".join(parts[-3:])          # example.co.uk
    return ".".join(parts[-2:])


@functools.lru_cache(maxsize=5000)
def ct_names(domain, timeout):
    """Certificate Transparency: all names ever in a public certificate for *.domain (crt.sh)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read() or b"[]")
    return frozenset(n for e in data for n in e.get("name_value", "").split("\n"))


def _get(url, timeout, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def pdns_otx(ip, timeout):
    """AlienVault OTX passive DNS (free, no key)."""
    kind = "IPv6" if ":" in ip else "IPv4"
    data = json.loads(_get(f"https://otx.alienvault.com/api/v1/indicators/{kind}/{ip}/passive_dns", timeout))
    return {e.get("hostname", "") for e in data.get("passive_dns", [])}


def pdns_hackertarget(ip, timeout):
    """HackerTarget reverse IP (free, no key, few queries per day)."""
    txt = _get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout)
    low = txt.lower()
    if "error" in low or "api count" in low or "no dns a records" in low or "no records" in low:
        raise RuntimeError(txt.strip()[:80])
    return set(txt.split())


API_KEYS = {}   # filled from --vt-key / --shodan-key / --securitytrails-key


def pdns_virustotal(ip, timeout):
    """VirusTotal resolutions (free API key, 500 lookups/day)."""
    data = json.loads(_get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit=40",
                           timeout, {"x-apikey": API_KEYS["virustotal"]}))
    return {d.get("attributes", {}).get("host_name", "") for d in data.get("data", [])}


def pdns_shodan(ip, timeout):
    """Shodan host info: hostnames and domains (API key)."""
    data = json.loads(_get(f"https://api.shodan.io/shodan/host/{ip}?key={API_KEYS['shodan']}"
                           "&minify=true", timeout))
    return set(data.get("hostnames", [])) | set(data.get("domains", []))


def pdns_securitytrails(ip, timeout):
    """SecurityTrails reverse A lookup (API key)."""
    req = urllib.request.Request(
        "https://api.securitytrails.com/v1/domains/list",
        data=json.dumps({"filter": {"ipv4": ip}}).encode(),
        headers={"User-Agent": UA, "APIKEY": API_KEYS["securitytrails"],
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read())
    return {d.get("hostname", "") for d in data.get("records", [])}


# (name, function, needs an API key?) - free sources always run, keyed ones only with a key
PDNS_SOURCES = [
    ("otx", pdns_otx, False),
    ("hackertarget", pdns_hackertarget, False),
    ("virustotal", pdns_virustotal, True),
    ("shodan", pdns_shodan, True),
    ("securitytrails", pdns_securitytrails, True),
]


def passive_dns(ip, timeout=12):
    """Ask every available passive DNS source (in parallel) which names resolved to ip."""
    names, log = {}, []
    sources = [(s, fn) for s, fn, needs_key in PDNS_SOURCES if not needs_key or API_KEYS.get(s)]

    def ask(item):
        src, fn = item
        try:
            return src, {n for n in fn(ip.strip("[]"), timeout) if n}, ""
        except Exception as e:  # noqa: BLE001
            return src, None, str(e)[:80]

    with cf.ThreadPoolExecutor(max_workers=max(1, len(sources))) as ex:
        for src, got, err in ex.map(ask, sources):
            if got is None:
                log.append(f"passive DNS {src}: failed ({err})")
            else:
                names[src] = got
                log.append(f"passive DNS {src}: {len(got)} name(s)")
    return names, log


CANDIDATE_NAMES = set()   # --names: hostnames from your own data (vhost configs, customer list)
SEED_NAMES = {}           # ip -> hostnames given as targets (starting points for discovery)


def discover_vhosts(ip, web_ports, a):
    """Find hostnames served on ip. Returns ({name: {sources}}, {name: resolved IPs}, log lines)."""
    found, log = {}, []

    def add(n, src):
        n = n.strip().lower().rstrip(".")
        if n.startswith("*."):                   # wildcard cert: try the bare domain and www.
            add(n[2:], src)
            add("www." + n[2:], src)
            return
        if HOSTNAME_RX.match(n) and not is_ip(n):
            found.setdefault(n, set()).add(src)

    seen_sni = set()
    ip_n = str(ipaddress.ip_address(ip.strip("[]")))
    tls_timeout = max(2.0, a.scan_timeout * 3)
    timing = {}
    t_start = time.monotonic()

    def hosted_here(names_):
        """Names configured on this server (own certs/redirects) or resolving to it.
        Resolved in parallel; only these are worth TLS handshakes and CT lookups."""
        names_ = list(names_)
        with cf.ThreadPoolExecutor(max_workers=50) as ex:
            res = dict(zip(names_, ex.map(resolve, names_)))
        return [n for n in names_ if found[n] & {"cert", "redirect"} or ip_n in res[n]]

    def sni_round():
        """Ask the server for the certificate of every new name via SNI (in parallel,
        only on ports that speak TLS): other vhosts' certificates list further names."""
        t0 = time.monotonic()
        batch = [n for n in hosted_here(n for n in found if n not in seen_sni)][:300]
        seen_sni.update(batch)
        jobs = [(n, p) for n in batch for p in tls_ports]
        if jobs:
            with cf.ThreadPoolExecutor(max_workers=min(30, len(jobs))) as ex:
                for names_ in ex.map(lambda j: cert_names(ip, j[1], j[0], tls_timeout), jobs):
                    for m in names_ or ():
                        add(m, "cert")
        timing["sni"] = timing.get("sni", 0) + time.monotonic() - t0

    # 1) TLS certificate without SNI (default cert) - also tells us which ports speak TLS
    t0 = time.monotonic()
    tls_ports = []
    with cf.ThreadPoolExecutor(max_workers=max(1, len(web_ports))) as ex:
        for p, names_ in zip(web_ports, ex.map(lambda p: cert_names(ip, p, None, tls_timeout), web_ports)):
            if names_ is not None:
                tls_ports.append(p)
                for n in names_:
                    add(n, "cert")
            elif f"{ip}:{p}" in SNI_ONLY or (":" in ip and f"[{ip}]:{p}" in SNI_ONLY):
                tls_ports.append(p)          # TLS, but only with a known hostname
    timing["certs"] = time.monotonic() - t0
    if not found and tls_ports and not any(p for p in tls_ports if f"{ip}:{p}" not in SNI_ONLY):
        log.append("no default certificate (server requires SNI): names must come from "
                   "reverse DNS, passive DNS, CT or --names")
    # 2) where the default site redirects to
    for p in web_ports:
        for h in RESULT_META.get(f"{ip}:{p}", {}).get("hosts", ()):
            if h and not is_ip(h):
                add(h, "redirect")
    # 3) reverse DNS (PTR)
    for n in reverse_dns(ip):
        add(n, "ptr")
    # 4) passive DNS: names that resolved to this IP (the only external way to find
    #    names that appear nowhere on the server itself)
    if a.passive_dns:
        t0 = time.monotonic()
        by_src, plog = passive_dns(ip)
        log += plog
        for src, names_ in by_src.items():
            for n in names_:
                add(n, "pdns")
        timing["pdns"] = time.monotonic() - t0
    # 5) your own list (--names) and hostnames given as targets
    for n in CANDIDATE_NAMES:
        add(n, "list")
    for n in SEED_NAMES.get(ip, ()):
        add(n, "target")
    # 6) certificates of all names found so far
    sni_round()
    # 7) certificate transparency for every domain hosted here (parallel, cached per domain)
    if a.ct:
        t0 = time.monotonic()
        domains = sorted({base_domain(n) for n in hosted_here(found)})[:25]

        def ct(dom):
            try:
                return dom, ct_names(dom, 20), ""
            except Exception as e:  # noqa: BLE001
                return dom, None, str(e)[:80]

        if domains:
            with cf.ThreadPoolExecutor(max_workers=min(5, len(domains))) as ex:   # crt.sh rate-limits
                for dom, names_, err in ex.map(ct, domains):
                    if names_ is None:
                        log.append(f"crt.sh {dom}: failed ({err})")
                    for n in names_ or ():
                        add(n, "ct")
        timing["ct"] = time.monotonic() - t0
    # 8) certificates of the names CT added
    sni_round()
    total = time.monotonic() - t_start
    log.append(f"discovery took {total:.1f}s (" + ", ".join(f"{k} {v:.1f}s" for k, v in timing.items())
               + f"; TLS ports {tls_ports or 'none'})")

    # DNS check ("nslookup") for every name
    with cf.ThreadPoolExecutor(max_workers=20) as ex:
        dns = dict(zip(found, ex.map(resolve, list(found))))

    ip_norm = str(ipaddress.ip_address(ip.strip("[]")))
    keep = {}
    for n, srcs in found.items():
        here = ip_norm in dns[n]
        # names from this server's own certs/redirects are configured here even if DNS
        # points elsewhere (CDN, old cert); names from ct/pdns/ptr/list must resolve here
        if here or srcs & {"cert", "redirect"}:
            keep[n] = srcs
    names = sorted(keep, key=lambda n: (ip_norm not in dns[n], n))[:a.max_vhosts]
    return {n: keep[n] for n in names}, dns, log


def main():
    ap = argparse.ArgumentParser(
        description=f"{NAME} - {DESCRIPTION} Targets: IPs, IP ranges (CIDR), hostnames, URLs or files.",
        epilog=f"Example: {NAME}.py 203.0.113.10 203.0.113.11 198.51.100.0/28 example.ch",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="IP, CIDR range, hostname, URL or file")
    ap.add_argument("-U", "--update-rules", action="store_true",
                    help="download a fresher copy of the embedded fingerprint database (webappanalyzer) "
                         f"into ~/.cache/{NAME}; it then takes precedence over the embedded one")
    ap.add_argument("--rules", default=RULES_DIR,
                    help=f"fingerprint database directory or JSON file (default: ~/.cache/{NAME}/technologies)")
    ap.add_argument("--no-rules", action="store_true", help="use only the hand-written fingerprints")
    ap.add_argument("-p", "--ports", default="web",
                    help="ports to scan: 'web' (default: 20 common web/panel ports), 'all' (1-65535), "
                         "or a list like 80,443,8000-8100")
    ap.add_argument("-n", "--no-scan", action="store_true",
                    help="skip the port scan, only try 443/80")
    ap.add_argument("-o", "--out", help="optionally also write a CSV file")
    ap.add_argument("-w", "--workers", type=int, default=20, help="parallel HTTP checks (default 20)")
    ap.add_argument("-t", "--timeout", type=float, default=6, help="HTTP timeout in seconds (default 6)")
    ap.add_argument("--scan-workers", type=int, default=0,
                    help="parallel port probes (default: 200 for short lists, up to 2000 for all ports)")
    ap.add_argument("--scan-timeout", type=float, default=0.8,
                    help="TCP connect timeout per port in seconds (default 0.8)")
    ap.add_argument("-a", "--all", action="store_true",
                    help="also list unreachable targets (hidden by default for IP ranges)")
    ap.add_argument("-d", "--debug", action="count", default=0,
                    help="-d: show port scan, requests, response headers, matches and errors (stderr); "
                         "-dd: also full Python tracebacks")
    ap.add_argument("--no-vhosts", dest="vhosts", action="store_false",
                    help="don't discover/scan vhosts (default: on - TLS certificates, redirects, reverse DNS "
                         "and certificate transparency, with a DNS check for every name)")
    ap.add_argument("--no-ct", dest="ct", action="store_false",
                    help="skip the certificate transparency lookup (crt.sh) during vhost discovery")
    ap.add_argument("--no-passive-dns", dest="passive_dns", action="store_false",
                    help="skip passive DNS lookups (default: on - AlienVault OTX and HackerTarget, no "
                         "keys needed; sends the scanned IPs to these services)")
    ap.add_argument("--vt-key", metavar="KEY", help="VirusTotal API key: adds VirusTotal passive DNS")
    ap.add_argument("--shodan-key", metavar="KEY", help="Shodan API key: adds Shodan hostnames/domains")
    ap.add_argument("--securitytrails-key", metavar="KEY",
                    help="SecurityTrails API key: adds SecurityTrails reverse-IP lookup")
    ap.add_argument("--names", action="append", default=[], metavar="FILE",
                    help="file with hostnames from your own data (vhost configs, customer domain list); "
                         "names resolving to a scanned IP are checked as vhosts on it. Repeatable.")
    ap.add_argument("--max-vhosts", type=int, default=200, help="max vhosts per IP (default 200)")
    ap.add_argument("-q", "--no-banner", action="store_true", help="don't print the banner")
    ap.add_argument("-V", "--version", action="version", version=f"{NAME} {VERSION}")
    hook = globals().get("add_arguments")
    if hook:
        hook(ap)
    a = ap.parse_args()
    options = options_from_args(a) if "options_from_args" in globals() else {}
    if not a.no_banner:
        print_banner()
    if a.update_rules:
        print("Updating fingerprint database...", file=sys.stderr, flush=True)
        update_rules(a.rules if not a.rules.endswith(".json") else RULES_DIR)
    if not a.targets:
        if a.update_rules:
            return
        ap.error("no targets given")
    n_db, source = 0, ""
    if not a.no_rules:
        try:
            n_db, source = load_rules(a.rules)
        except Exception as e:  # noqa: BLE001
            print(f"Warning: could not load fingerprint database: {e}", file=sys.stderr)
    msg = f"Fingerprints: {builtin_count()} built-in {BUILTIN_LABEL}"
    if n_db:
        msg += f" + {n_db} from {source}"
    print(msg, file=sys.stderr, flush=True)
    global DEBUG
    DEBUG = a.debug
    if a.debug:
        a.all = True

    for src, key in (("virustotal", a.vt_key), ("shodan", a.shodan_key),
                     ("securitytrails", a.securitytrails_key)):
        if key:
            API_KEYS[src] = key.strip()
    if a.passive_dns:
        used = ["otx", "hackertarget"] + sorted(API_KEYS)
        print(f"Passive DNS: {', '.join(used)}", file=sys.stderr, flush=True)
    for fn in a.names:
        with open(fn, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0]
                for tok in re.split(r"[\s,;]+", line):
                    tok = tok.strip().lower().rstrip(".")
                    if tok and HOSTNAME_RX.match(tok):
                        CANDIDATE_NAMES.add(tok)
    if a.names:
        print(f"Loaded {len(CANDIDATE_NAMES)} candidate hostname(s) from {', '.join(a.names)}",
              file=sys.stderr, flush=True)

    targets = list(dict.fromkeys(t for arg in a.targets for t in expand(arg)))
    ports = parse_ports(a.ports)
    rows, counts = [], {}
    scanned = set()      # endpoints found by the scan (may be non-HTTP services)
    W = 44

    def add_row(row, hidden=False, key=None):
        rows.append(row)
        key = key or count_key(row[3])
        if row[3] == "ERROR" and row[0] in scanned:
            key = "NOT HTTP"            # open port, but no web server on it
            row[3] = "NOT HTTP"
        counts[key] = counts.get(key, 0) + 1
        if hidden and not a.all:
            return
        if row[3] in ("ERROR", "NOT HTTP") and not a.all and (len(targets) > 1 or row[0] in scanned):
            return
        print(f"{row[0]:<{W}} {row[3]:<16} {row[5][:24]:<24} {row[6][:28]:<28} {row[7]}", flush=True)

    # --- phase 1: quick TCP connect scan on web ports ---------------------
    checks = []          # "host:port" or URL items for the HTTP phase
    to_scan = []         # (target, host, port)
    no_port_rows = []    # targets where no web port was open
    for t in targets:
        addr = t.split("@", 1)[1] if ("@" in t and "://" not in t) else t   # vhost@ip
        host, port = split_hostport(addr)
        if a.no_scan or "://" in t or port is not None:
            checks.append(t)
        else:
            to_scan += [(t, host, p) for p in ports]

    if to_scan:
        n_hosts = len({x[0] for x in to_scan})
        limit = max_sockets()
        workers = a.scan_workers or (2000 if len(ports) > 1000 else 200)
        if workers > limit:
            print(f"Note: limiting scan workers to {limit} (open-file limit, see 'ulimit -n')",
                  file=sys.stderr)
            workers = limit
        print(f"Scanning {n_hosts} host(s) x {len(ports)} port(s) with {workers} parallel probes...",
              file=sys.stderr, flush=True)
        open_ports = scan(to_scan, workers, a.scan_timeout)
        n_open = 0
        for t in dict.fromkeys(x[0] for x in to_scan):
            found = sorted(open_ports.get(t, []))
            n_open += len(found)
            if DEBUG:
                print(f"[SCAN] {t}: open {found or 'none'}", file=sys.stderr, flush=True)
            if found:
                eps = [f"{t}:{p}" for p in found]
                checks += eps
                scanned.update(eps)
            else:
                no_port_rows.append([t, "", "", "ERROR", "", "", "",
                                     f"no open port (scanned {len(ports)} ports)"])
        print(f"Found {n_open} open port(s), checking each for HTTP...\n",
              file=sys.stderr, flush=True)

    cols = COLUMNS
    print(f"{'TARGET':<{W}} {'VERDICT':<16} {APPS_LABEL:<24} {'SERVER':<28} EVIDENCE")
    for row in no_port_rows:
        add_row(row)
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for row in ex.map(lambda t: check(t, a.timeout, options), checks):
            add_row(row)

    # --- phase 3: vhost discovery + scan of every vhost on its IP ----------
    if a.vhosts:
        web = {}                                     # ip -> [web ports]
        already_scanned = set()                      # (hostname, ip, port) given as targets
        for r in list(rows):
            t = r[0]
            if "@" in t or "://" in t or r[3] in ("ERROR", "NOT HTTP"):
                continue
            h, p = split_hostport(t)
            if not is_ip(h):                         # hostname target: discover on its IP
                ips = sorted(resolve(h))
                if not ips:
                    continue
                already_scanned.add((h.lower(), ips[0], p))
                SEED_NAMES.setdefault(ips[0], set()).add(h.lower())   # start discovery from it
                if r[1].startswith("https://") and p is not None:
                    SNI_ONLY.add(f"{ips[0]}:{p}")                     # port speaks TLS (with SNI)
                h = ips[0]
            if p is None:                            # -n mode: port from the final URL
                p = 443 if r[1].startswith("https") else 80
            web.setdefault(h, []).append(p)
        if not web:
            print("\nNo web server found on any IP, no vhosts to discover.", file=sys.stderr)
        else:
            print(f"\nDiscovering vhosts on {len(web)} IP(s)...", file=sys.stderr, flush=True)
            vchecks, vinfo = [], {}
            with cf.ThreadPoolExecutor(max_workers=10) as ex:
                futs = {ex.submit(discover_vhosts, ip, sorted(set(ps)), a): ip for ip, ps in web.items()}
                for f in cf.as_completed(futs):
                    ip = futs[f]
                    names, dns, dlog = f.result()
                    ip_norm = str(ipaddress.ip_address(ip))
                    n_here = sum(ip_norm in dns[n] for n in names)
                    by_src = {}
                    for srcs in names.values():
                        for s in srcs:
                            by_src[s] = by_src.get(s, 0) + 1
                    src_txt = ", ".join(f"{k} {v}" for k, v in sorted(by_src.items()))
                    print(f"[VHOST] {ip}: {len(names)} name(s) ({src_txt or 'none'}), "
                          f"{n_here} resolve to this IP", file=sys.stderr, flush=True)
                    for line in dlog:
                        print(f"[VHOST] {ip}: {line}", file=sys.stderr, flush=True)
                    for n, srcs in names.items():
                        if DEBUG:
                            print(f"[VHOST]   {n:<40} src={','.join(sorted(srcs)):<16} "
                                  f"dns={','.join(sorted(dns[n])) or 'none'}", file=sys.stderr)
                        if ip_norm in dns[n]:
                            dns_txt = "dns ok"
                        elif dns[n]:
                            dns_txt = "dns -> " + ",".join(sorted(dns[n])[:2])
                        else:
                            dns_txt = "no dns"
                        for p in sorted(set(web[ip])):
                            if (n, ip, p) in already_scanned:     # was a target itself
                                continue
                            vt = f"{n}@{ip}:{p}" if ":" not in ip else f"{n}@[{ip}]:{p}"
                            vchecks.append(vt)
                            vinfo[vt] = (ip, p, f"[{','.join(sorted(srcs))}; {dns_txt}]")

            if vchecks:
                print(f"Checking {len(vchecks)} vhost endpoint(s)...\n", file=sys.stderr, flush=True)
                W = max(W, max(len(v) for v in vchecks) + 1)     # long names: keep columns aligned
                print(f"\n{'VHOST@IP:PORT':<{W}} {'VERDICT':<16} {APPS_LABEL:<24} {'SERVER':<28} EVIDENCE")
                with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
                    for row in ex.map(lambda t: check(t, a.timeout, options), vchecks):
                        ip, p, tag = vinfo[row[0]]
                        default = RESULT_META.get(f"{ip}:{p}") or RESULT_META.get(ip)
                        mine = RESULT_META.get(row[0])
                        same = bool(default and mine and default["hash"] == mine["hash"])
                        vhost = row[0].split("@", 1)[0]
                        # HTTP vhost that only redirects to its own HTTPS version: the HTTPS
                        # row already covers it
                        fu = urlparse(row[1]) if row[1] else None
                        to_https = bool(fu and fu.scheme == "https"
                                        and (fu.hostname or "").lower() == vhost
                                        and (fu.port or 443) != p
                                        and f"{vhost}@{ip}:{fu.port or 443}" in vinfo)
                        row[7] = (f"{tag} " + ("same as default site; " if same else "")
                                  + ("redirects to https; " if to_https else "") + row[7])
                        if row[3] == "ERROR":
                            add_row(row, hidden=True)
                        elif same:
                            add_row(row, hidden=True, key="SAME AS DEFAULT")
                        else:
                            add_row(row, hidden=to_https, key="HTTP->HTTPS" if to_https else None)

    if a.out:
        with open(a.out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(cols)
            w.writerows(rows)

    summary = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
    print(f"\n{len(targets)} target(s), {len(rows)} result(s) ({summary})" + (f" -> {a.out}" if a.out else ""))
