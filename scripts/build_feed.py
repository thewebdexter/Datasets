#!/usr/bin/env python3
"""
build_feed.py — Downloads all threat-intel feeds, deduplicates entries,
and writes data/master_feed.json + data/feed_meta.json.

Place this file at: scripts/build_feed.py
Output files land in:  data/
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

OUTPUT_DIR   = Path("data")
MASTER_FILE  = OUTPUT_DIR / "master_feed.json"
META_FILE    = OUTPUT_DIR / "feed_meta.json"

TIMEOUT      = 30          # seconds per request
MAX_ENTRIES  = 500_000     # safety cap – raise if needed

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
    """URLhaus (abuse.ch) – malware distribution URLs (CSV)."""
    log.info("URLhaus …")
    try:
        r = fetch("https://urlhaus.abuse.ch/downloads/csv_recent/", stream=True)
        with gzip.GzipFile(fileobj=io.BytesIO(r.content)) as gz:
            text = gz.read().decode("utf-8", errors="replace")
        reader = csv.DictReader(
            (line for line in text.splitlines() if not line.startswith("#")),
        )
        results = []
        for row in reader:
            url = row.get("url", "").strip()
            tag = row.get("tags", "malware").strip() or "malware"
            if url:
                results.append({"url": url, "source": "urlhaus", "category": tag})
        return results
    except Exception as exc:
        log.error("URLhaus failed: %s", exc)
        return []


def feed_malware_domain_list() -> list[dict]:
    """Malware Domain List – domains serving malware (plain text)."""
    log.info("Malware Domain List …")
    try:
        r = fetch("https://www.malwaredomainlist.com/hostslist/hosts.txt")
        domains = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Format: "127.0.0.1  evil.com"
            parts = line.split()
            domain = parts[-1] if parts else ""
            if domain and domain not in ("localhost", "0.0.0.0", "127.0.0.1"):
                domains.append({
                    "url": f"http://{domain}",
                    "source": "malware_domain_list",
                    "category": "malware",
                })
        return domains
    except Exception as exc:
        log.error("Malware Domain List failed: %s", exc)
        return []


def feed_disconnect_me() -> list[dict]:
    """Disconnect.me – tracker / ad domain list (JSON)."""
    log.info("Disconnect.me …")
    url = (
        "https://raw.githubusercontent.com/nickcoutsos/disconnect-privacy-lists"
        "/master/disconnect-me/services.json"
    )
    try:
        r = fetch(url)
        data = r.json()
        results = []
        for category_name, services in data.get("categories", {}).items():
            for service in services:
                for _svc_name, domains_dict in service.items():
                    if isinstance(domains_dict, dict):
                        for domain in domains_dict.get("", []):
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


def feed_spamhaus_dbl() -> list[dict]:
    """Spamhaus DBL – domain block list (plain text, zone-file format)."""
    log.info("Spamhaus DBL …")
    # Note: direct zone download requires a Spamhaus subscription.
    # We use the publicly mirrored subset maintained by hagezi instead.
    url = (
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main"
        "/wildcard/spam-onlydomains.txt"
    )
    try:
        r = fetch(url)
        results = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            # Format: *.domain.tld  →  strip leading "*."
            domain = line.lstrip("*.").lower()
            if domain:
                results.append({
                    "url": f"http://{domain}",
                    "source": "spamhaus_dbl",
                    "category": "spam",
                })
        return results
    except Exception as exc:
        log.error("Spamhaus DBL mirror failed: %s", exc)
        return []


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
    feed_spamhaus_dbl,
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

    # Normalise URLs and deduplicate by (normalised_url)
    seen_urls:    set[str] = set()
    seen_domains: dict[str, str] = {}   # domain → first category seen
    clean: list[dict] = []

    for entry in all_entries:
        norm = normalise_url(entry["url"])
        if not norm:
            continue
        if norm in seen_urls:
            continue
        seen_urls.add(norm)

        domain = extract_domain(norm)
        entry["url"]    = norm
        entry["domain"] = domain or ""
        clean.append(entry)

        if domain and domain not in seen_domains:
            seen_domains[domain] = entry["category"]

        if len(clean) >= MAX_ENTRIES:
            log.warning("Reached MAX_ENTRIES cap (%d) — truncating.", MAX_ENTRIES)
            break

    log.info("Unique entries after dedup: %d", len(clean))

    # ── Write master feed ──────────────────────────────────────────────────
    master = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_entries": len(clean),
        "entries": clean,
        # Domain-level lookup map for fast extension queries
        "domain_map": seen_domains,
    }

    MASTER_FILE.write_text(json.dumps(master, separators=(",", ":")), encoding="utf-8")
    log.info("Wrote %s (%.1f MB)", MASTER_FILE, MASTER_FILE.stat().st_size / 1e6)

    # ── Write metadata / stats ─────────────────────────────────────────────
    meta = {
        "generated_at": master["generated_at"],
        "total_entries": len(clean),
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
