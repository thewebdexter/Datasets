#!/usr/bin/env python3
"""
build_feed.py — Downloads all threat-intel feeds, deduplicates entries,
and writes three output files:

  data/phishing_urls.json  — full URLs from PhishTank + OpenPhish (URL-level match)
  data/malware_urls.json   — full URLs from URLhaus (URL-level match)
  data/domain_map.json     — domains from all other feeds (domain-level match)
  data/feed_meta.json      — stats / health check

Place this file at: scripts/build_feed.py
"""

import csv
import gzip
import io
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
import tldextract

# ── Config ────────────────────────────────────────────────────────────────────

OUTPUT_DIR           = Path("data")
PHISHING_URLS_FILE   = OUTPUT_DIR / "phishing_urls.json"  # full URLs — PhishTank + OpenPhish
MALWARE_URLS_FILE    = OUTPUT_DIR / "malware_urls.json"   # full URLs — URLhaus only
DOMAIN_MAP_FILE      = OUTPUT_DIR / "domain_map.json"     # domains — all other feeds
META_FILE            = OUTPUT_DIR / "feed_meta.json"

TIMEOUT = 30   # seconds per request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "LinkSentinel-FeedBot/1.0"})

# ── Helpers ───────────────────────────────────────────────────────────────────

def fetch(url: str, **kwargs) -> requests.Response:
    """GET with retry (3×) and exponential back-off."""
    for attempt in range(1, 4):
        try:
            r = SESSION.get(url, timeout=TIMEOUT, **kwargs)
            r.raise_for_status()
            return r
        except requests.RequestException as exc:
            log.warning("Attempt %d failed for %s: %s", attempt, url, exc)
            if attempt < 3:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"All retries exhausted for {url}")


def normalise_url(raw: str) -> str | None:
    """Return a cleaned, lower-cased URL string or None if unparseable."""
    raw = raw.strip().rstrip("/")
    if not raw or raw.startswith("#"):
        return None
    # Ensure scheme exists so urlparse works
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw
    try:
        p = urlparse(raw.lower())
        if not p.hostname:
            return None
        return p.geturl()
    except Exception:
        return None


def extract_domain(url: str) -> str | None:
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return None


# ── Feed downloaders ──────────────────────────────────────────────────────────

def feed_phishtank() -> list[dict]:
    """PhishTank – community-verified phishing URLs (JSON)."""
    api_key = os.getenv("PHISHTANK_API_KEY", "")
    url = (
        f"http://data.phishtank.com/data/{api_key}/online-valid.json.gz"
        if api_key
        else "http://data.phishtank.com/data/online-valid.json.gz"
    )
    log.info("PhishTank …")
    try:
        r = fetch(url, stream=True)
        with gzip.GzipFile(fileobj=io.BytesIO(r.content)) as gz:
            entries = json.load(gz)
        return [
            {"url": e["url"], "source": "phishtank", "category": "phishing"}
            for e in entries
            if e.get("url")
        ]
    except Exception as exc:
        log.error("PhishTank failed: %s", exc)
        return []


def feed_openphish() -> list[dict]:
    """OpenPhish – free-tier phishing feed (plain text, one URL per line)."""
    log.info("OpenPhish …")
    try:
        r = fetch("https://openphish.com/feed.txt")
        return [
            {"url": line, "source": "openphish", "category": "phishing"}
            for line in r.text.splitlines()
            if line.strip()
        ]
    except Exception as exc:
        log.error("OpenPhish failed: %s", exc)
        return []


def feed_urlhaus() -> list[dict]:
    """
    URLhaus (abuse.ch) – malware distribution URLs (plain CSV).
    Tagged as 'malware_url' so the pipeline writes them to malware_urls.json
    at full URL granularity — URLhaus regularly lists compromised legitimate
    sites where only a specific path is malicious, not the whole domain.
    """
    log.info("URLhaus …")
    try:
        r = fetch("https://urlhaus.abuse.ch/downloads/csv_recent/")
        reader = csv.DictReader(
            (line for line in r.text.splitlines() if not line.startswith("#")),
        )
        results = []
        for row in reader:
            url = row.get("url", "").strip()
            if url:
                results.append({"url": url, "source": "urlhaus", "category": "malware_url"})
        return results
    except Exception as exc:
        log.error("URLhaus failed: %s", exc)
        return []


def feed_malware_domain_list() -> list[dict]:
    """
    Steven Black's unified hosts file – malware + adware domains.
    Replaces malwaredomainlist.com which is no longer maintained.
    """
    log.info("Steven Black hosts (malware + adware) …")
    try:
        r = fetch(
            "https://raw.githubusercontent.com/StevenBlack/hosts/master"
            "/alternates/fakenews-gambling-porn-social/hosts"
        )
        domains = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Format: "0.0.0.0  evil.com"
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                domain = parts[1].lower()
                if domain not in ("0.0.0.0", "localhost", "local", "broadcasthost"):
                    domains.append({
                        "url": f"http://{domain}",
                        "source": "steven_black_hosts",
                        "category": "malware",
                    })
        return domains
    except Exception as exc:
        log.error("Steven Black hosts failed: %s", exc)
        return []


def feed_disconnect_me() -> list[dict]:
    """Disconnect.me – tracker / ad domain list (official GitHub repo)."""
    log.info("Disconnect.me …")
    url = (
        "https://raw.githubusercontent.com/disconnectme"
        "/disconnect-tracking-protection/master/services.json"
    )
    try:
        r = fetch(url)
        data = r.json()
        results = []
        for category_name, services in data.get("categories", {}).items():
            for service in services:
                for _svc_name, domains_dict in service.items():
                    if isinstance(domains_dict, dict):
                        for domain_list in domains_dict.values():
                            if isinstance(domain_list, list):
                                for domain in domain_list:
                                    results.append({
                                        "url": f"http://{domain}",
                                        "source": "disconnect_me",
                                        "category": category_name.lower(),
                                    })
        return results
    except Exception as exc:
        log.error("Disconnect.me failed: %s", exc)
        return []


def feed_easylist_privacy() -> list[dict]:
    """EasyPrivacy – tracker domains extracted from Adblock rules."""
    log.info("EasyPrivacy …")
    try:
        r = fetch("https://easylist.to/easylist/easyprivacy.txt")
        domains = []
        # Extract ||domain^ style rules (host-level blocks)
        pattern = re.compile(r"^\|\|([a-z0-9.\-]+)\^", re.I)
        for line in r.text.splitlines():
            m = pattern.match(line.strip())
            if m:
                domain = m.group(1).lower()
                domains.append({
                    "url": f"http://{domain}",
                    "source": "easyprivacy",
                    "category": "tracker",
                })
        return domains
    except Exception as exc:
        log.error("EasyPrivacy failed: %s", exc)
        return []


def _hagezi_feed(name: str, url: str, category: str) -> list[dict]:
    """Generic loader for Hagezi plain-text domain lists."""
    log.info("Hagezi %s …", name)
    try:
        r = fetch(url)
        results = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            domain = line.lower()
            if domain:
                results.append({
                    "url": f"http://{domain}",
                    "source": f"hagezi_{name}",
                    "category": category,
                })
        return results
    except Exception as exc:
        log.error("Hagezi %s failed: %s", name, exc)
        return []


def feed_hagezi_tif() -> list[dict]:
    """Hagezi TIF (Threat Intelligence Feeds) – malware, phishing, botnet C2."""
    return _hagezi_feed(
        "tif",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/domains/tif.txt",
        "malware",
    )


def feed_hagezi_pro() -> list[dict]:
    """Hagezi Pro – comprehensive ads, trackers, and telemetry block list."""
    return _hagezi_feed(
        "pro",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/domains/pro.txt",
        "tracker",
    )


def feed_cisco_umbrella_top1m() -> list[dict]:
    """
    Cisco Umbrella Top 1M – KNOWN-GOOD domains (allowlist / inverse use).
    Returns entries with category 'known_good' so the extension can whitelist them.
    """
    log.info("Cisco Umbrella Top 1M …")
    try:
        r = fetch(
            "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
            stream=True,
        )
        import zipfile
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            name = z.namelist()[0]
            with z.open(name) as f:
                text = f.read().decode("utf-8", errors="replace")
        results = []
        for line in text.splitlines()[:1_000_000]:
            parts = line.strip().split(",", 1)
            if len(parts) == 2:
                domain = parts[1].strip().lower()
                if domain:
                    results.append({
                        "url": f"http://{domain}",
                        "source": "cisco_umbrella",
                        "category": "known_good",
                    })
        return results
    except Exception as exc:
        log.error("Cisco Umbrella failed: %s", exc)
        return []


# ── Pipeline ──────────────────────────────────────────────────────────────────

FEED_FUNCTIONS = [
    feed_phishtank,
    feed_openphish,
    feed_urlhaus,
    feed_malware_domain_list,
    feed_disconnect_me,
    feed_easylist_privacy,
    feed_hagezi_tif,
    feed_hagezi_pro,
    feed_cisco_umbrella_top1m,
]


def build():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_entries: list[dict] = []
    feed_stats: dict[str, int] = {}

    for fn in FEED_FUNCTIONS:
        raw = fn()
        feed_stats[fn.__name__] = len(raw)
        log.info("  ↳ %d raw entries", len(raw))
        all_entries.extend(raw)

    log.info("Total raw entries: %d — deduplicating …", len(all_entries))

    # Three buckets:
    #   phishing_urls  — full URLs (PhishTank, OpenPhish) — category "phishing"
    #   malware_urls   — full URLs (URLhaus)              — category "malware_url"
    #   domain_map     — domain-level (everything else)
    seen_phishing_urls: set[str] = set()
    seen_malware_urls:  set[str] = set()
    seen_urls:          set[str] = set()       # global dedup across all entries
    seen_domains:       dict[str, str] = {}    # domain → category
    clean: list[dict] = []

    for entry in all_entries:
        norm = normalise_url(entry["url"])
        if not norm:
            continue
        if norm in seen_urls:
            continue
        seen_urls.add(norm)

        entry["url"] = norm
        domain = extract_domain(norm)
        entry["domain"] = domain or ""
        clean.append(entry)

        cat = entry["category"]

        if cat == "phishing":
            # Full URL — phishing lives on legitimate hosts (Google Docs, OneDrive…)
            seen_phishing_urls.add(norm)

        elif cat == "malware_url":
            # Full URL — URLhaus lists compromised sites where only a path is hostile
            seen_malware_urls.add(norm)

        else:
            # Domain-level — dedicated malicious infrastructure, trackers, spam
            # known_good only wins if no threat category has claimed this domain yet
            if domain and (domain not in seen_domains or cat != "known_good"):
                seen_domains[domain] = cat

    log.info(
        "Unique entries: %d  |  phishing URLs: %d  |  malware URLs: %d  |  domains: %d",
        len(clean), len(seen_phishing_urls), len(seen_malware_urls), len(seen_domains),
    )

    now = datetime.now(timezone.utc).isoformat()

    # ── phishing_urls.json ─────────────────────────────────────────────────
    PHISHING_URLS_FILE.write_text(
        json.dumps({
            "generated_at": now,
            "total": len(seen_phishing_urls),
            "urls": sorted(seen_phishing_urls),   # sorted → O(log n) binary search
        }, separators=(",", ":")),
        encoding="utf-8",
    )
    log.info("Wrote %s (%.1f MB)", PHISHING_URLS_FILE, PHISHING_URLS_FILE.stat().st_size / 1e6)

    # ── malware_urls.json ──────────────────────────────────────────────────
    MALWARE_URLS_FILE.write_text(
        json.dumps({
            "generated_at": now,
            "total": len(seen_malware_urls),
            "urls": sorted(seen_malware_urls),    # sorted → O(log n) binary search
        }, separators=(",", ":")),
        encoding="utf-8",
    )
    log.info("Wrote %s (%.1f MB)", MALWARE_URLS_FILE, MALWARE_URLS_FILE.stat().st_size / 1e6)

    # ── domain_map.json ────────────────────────────────────────────────────
    DOMAIN_MAP_FILE.write_text(
        json.dumps(seen_domains, separators=(",", ":")),
        encoding="utf-8",
    )
    log.info("Wrote %s (%.1f MB)", DOMAIN_MAP_FILE, DOMAIN_MAP_FILE.stat().st_size / 1e6)

    # ── feed_meta.json ─────────────────────────────────────────────────────
    meta = {
        "generated_at": now,
        "total_entries": len(clean),
        "phishing_urls": len(seen_phishing_urls),
        "malware_urls": len(seen_malware_urls),
        "unique_domains": len(seen_domains),
        "feed_stats": feed_stats,
        "categories": _count_by(clean, "category"),
        "sources":    _count_by(clean, "source"),
    }
    META_FILE.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    log.info("Wrote %s", META_FILE)

    return len(clean)


def _count_by(entries: list[dict], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for e in entries:
        counts[e.get(key, "unknown")] = counts.get(e.get(key, "unknown"), 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


if __name__ == "__main__":
    n = build()
    sys.exit(0 if n > 0 else 1)
