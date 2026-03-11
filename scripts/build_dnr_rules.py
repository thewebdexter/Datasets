#!/usr/bin/env python3
"""
build_dnr_rules.py — Fetches the ClearURLs rule catalog and converts it to
Chrome Declarative Net Request (DNR) removeParams rules.

Sources:
  - ClearURLs data.minify.json  → auto-generated rules (IDs 70000+)
  - data/dnr_rules_manual.json  → your hand-crafted overrides (IDs 50000–60999)
    (rename your current dnr_rules.json to dnr_rules_manual.json)

Output:
  - data/dnr_rules.json         → merged file the extension fetches

Normal mode  = tracking params only (no affiliate/referral params)
Strict mode  = tracking params + referral/affiliate params

Place this file at: scripts/build_dnr_rules.py
"""

import hashlib
import json
import logging
import re
import sys
import time
from pathlib import Path

import requests

# ── Config ────────────────────────────────────────────────────────────────────

OUTPUT_DIR       = Path("data")
OUTPUT_FILE      = OUTPUT_DIR / "dnr_rules.json"
MANUAL_FILE      = OUTPUT_DIR / "dnr_rules_manual.json"   # your hand-crafted rules
HASH_CACHE_FILE  = OUTPUT_DIR / ".clearurls_hash"         # tracks last upstream hash

CLEARURLS_URL    = "https://rules1.clearurls.xyz/data.minify.json"
CLEARURLS_HASH   = "https://rules1.clearurls.xyz/rules.minify.hash"

# Auto-generated rule IDs start here — well above your manual range (50000–60999)
AUTO_ID_START    = 70000
TIMEOUT          = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "LinkSentinel-DNRBot/1.0"})


# ── Helpers ───────────────────────────────────────────────────────────────────

def fetch(url: str) -> requests.Response:
    for attempt in range(1, 4):
        try:
            r = SESSION.get(url, timeout=TIMEOUT)
            r.raise_for_status()
            return r
        except requests.RequestException as exc:
            log.warning("Attempt %d failed for %s: %s", attempt, url, exc)
            if attempt < 3:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"All retries exhausted for {url}")


def clearurls_pattern_to_dnr(pattern: str) -> str | None:
    """
    Convert a ClearURLs urlPattern (JS regex string) to a DNR regexFilter (RE2).

    ClearURLs patterns look like:  ^https?:\\/\\/(?:[a-z0-9-]+\\.)*?google\\.com
    DNR regexFilter looks like:    ^https?://(?:[a-z0-9-]+\\.)*?google\\.com

    Key differences:
    - JS regex uses \\/ for forward slashes — RE2 doesn't need escaping
    - JS regex uses \\. for literal dots — RE2 same
    - Named groups (?<name>…) → not supported in RE2, convert to (?:…)
    - Lookaheads/lookbehinds → not supported in RE2, skip those providers
    """
    if not pattern:
        return None

    # Unescape forward slashes (JS regex artifact)
    p = pattern.replace("\\/", "/")

    # Named capture groups → non-capturing
    p = re.sub(r"\(\?<[^>]+>", "(?:", p)

    # Bail out on constructs RE2 doesn't support
    unsupported = ["(?<=", "(?<!", "(?=", "(?!", "\\1", "\\2", "\\k<"]
    if any(u in p for u in unsupported):
        return None

    return p


def params_to_dnr_rule(
    rule_id: int,
    regex: str,
    params: list[str],
    resource_types: list[str] | None = None,
) -> dict:
    """Build a single DNR removeParams rule."""
    return {
        "id": rule_id,
        "priority": 1,
        "action": {
            "type": "redirect",
            "redirect": {
                "transform": {
                    "queryTransform": {
                        "removeParams": sorted(set(params)),
                    }
                }
            },
        },
        "condition": {
            "regexFilter": regex,
            "resourceTypes": resource_types or ["main_frame", "sub_frame"],
        },
    }


# ── Converter ─────────────────────────────────────────────────────────────────

def convert_clearurls(data: dict) -> tuple[list[dict], list[dict]]:
    """
    Returns (normal_rules, strict_rules).

    normal_rules — tracking params only (rules[])
    strict_rules — tracking params + referralMarketing[]
    """
    normal_rules: list[dict] = []
    strict_rules: list[dict] = []

    rule_id = AUTO_ID_START
    skipped = 0

    providers: dict = data.get("providers", {})

    for provider_name, provider in providers.items():
        # Skip test providers
        if "test" in provider_name.lower() or "clearurlstest" in provider_name.lower():
            continue

        # completeProvider=true means block the entire domain — not a param strip rule
        if provider.get("completeProvider"):
            skipped += 1
            continue

        raw_pattern = provider.get("urlPattern", "")
        regex = clearurls_pattern_to_dnr(raw_pattern)
        if not regex:
            skipped += 1
            continue

        tracking_params: list[str] = provider.get("rules", [])
        referral_params: list[str] = provider.get("referralMarketing", [])

        # ClearURLs "rules" are param name regexes — filter out complex ones
        # that DNR can't handle (DNR removeParams matches exact param names only)
        def is_simple_param(p: str) -> bool:
            # Accept plain names and names with one trailing wildcard
            return bool(re.match(r"^[a-zA-Z0-9_\-\.]+\*?$", p))

        simple_tracking = [p.rstrip("*") for p in tracking_params if is_simple_param(p)]
        simple_referral = [p.rstrip("*") for p in referral_params if is_simple_param(p)]

        if not simple_tracking and not simple_referral:
            skipped += 1
            continue

        # Normal rule — tracking params only
        if simple_tracking:
            normal_rules.append(
                params_to_dnr_rule(rule_id, regex, simple_tracking)
            )
            rule_id += 1

        # Strict rule — tracking + referral params combined
        all_params = list(set(simple_tracking + simple_referral))
        if all_params:
            strict_rules.append(
                params_to_dnr_rule(rule_id, regex, all_params)
            )
            rule_id += 1

    log.info(
        "ClearURLs → %d normal rules, %d strict rules (%d providers skipped)",
        len(normal_rules), len(strict_rules), skipped,
    )
    return normal_rules, strict_rules


# ── Version helpers ───────────────────────────────────────────────────────────

def bump_version(old: str, changed: bool) -> str:
    """Increment patch version if content changed, otherwise keep it."""
    if not changed:
        return old
    try:
        parts = [int(x) for x in old.split(".")]
        parts[-1] += 1
        return ".".join(str(x) for x in parts)
    except Exception:
        return old


# ── Main ──────────────────────────────────────────────────────────────────────

def build():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # ── Check upstream hash to avoid redundant rebuilds ────────────────────
    try:
        upstream_hash = fetch(CLEARURLS_HASH).text.strip()
    except Exception:
        upstream_hash = ""
        log.warning("Could not fetch ClearURLs hash — will rebuild anyway")

    cached_hash = ""
    if HASH_CACHE_FILE.exists():
        cached_hash = HASH_CACHE_FILE.read_text().strip()

    # ── Download ClearURLs rules ───────────────────────────────────────────
    log.info("Fetching ClearURLs rules from %s …", CLEARURLS_URL)
    clearurls_data = fetch(CLEARURLS_URL).json()

    # Verify hash integrity
    actual_hash = hashlib.sha256(
        json.dumps(clearurls_data, sort_keys=True).encode()
    ).hexdigest()

    content_changed = actual_hash != cached_hash
    log.info("Content %s since last run", "CHANGED" if content_changed else "unchanged")

    # ── Load manual rules ──────────────────────────────────────────────────
    if MANUAL_FILE.exists():
        manual = json.loads(MANUAL_FILE.read_text())
        manual_normal = manual.get("normal_rules", [])
        manual_strict = manual.get("strict_rules", [])
        old_version   = manual.get("version", "1.0.0")
        log.info(
            "Loaded manual rules: %d normal, %d strict",
            len(manual_normal), len(manual_strict),
        )
    else:
        log.warning(
            "%s not found — rename your current dnr_rules.json to dnr_rules_manual.json", MANUAL_FILE
        )
        manual_normal, manual_strict, old_version = [], [], "1.0.0"

    # ── Convert ClearURLs → DNR ────────────────────────────────────────────
    auto_normal, auto_strict = convert_clearurls(clearurls_data)

    # ── Merge: manual rules take precedence (they have lower IDs → higher priority) ──
    # Collect domains already covered by manual rules so we don't double-apply
    manual_patterns = set()
    for rule in manual_normal + manual_strict:
        pat = rule.get("condition", {}).get("regexFilter", "")
        if pat:
            manual_patterns.add(pat)

    def not_manual_duplicate(rule: dict) -> bool:
        return rule.get("condition", {}).get("regexFilter", "") not in manual_patterns

    merged_normal = manual_normal + [r for r in auto_normal if not_manual_duplicate(r)]
    merged_strict = manual_strict + [r for r in auto_strict if not_manual_duplicate(r)]

    log.info(
        "Merged totals → %d normal rules, %d strict rules",
        len(merged_normal), len(merged_strict),
    )

    # ── Write output ───────────────────────────────────────────────────────
    new_version = bump_version(old_version, content_changed)

    output = {
        "name": "SentraLink DNR Rules",
        "version": new_version,
        "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "sources": {
            "manual": str(MANUAL_FILE),
            "clearurls": CLEARURLS_URL,
        },
        "stats": {
            "manual_normal": len(manual_normal),
            "manual_strict": len(manual_strict),
            "auto_normal": len(auto_normal),
            "auto_strict": len(auto_strict),
            "total_normal": len(merged_normal),
            "total_strict": len(merged_strict),
        },
        "normal_rules": merged_normal,
        "strict_rules": merged_strict,
        "notes": {
            "id_ranges": "50000–60999 = manual overrides | 70000+ = auto-generated from ClearURLs",
            "skipped": "completeProvider rules and RE2-incompatible patterns are skipped",
        },
    }

    OUTPUT_FILE.write_text(json.dumps(output, indent=2), encoding="utf-8")
    log.info(
        "Wrote %s v%s (%.1f KB)",
        OUTPUT_FILE, new_version, OUTPUT_FILE.stat().st_size / 1e3,
    )

    # Cache the hash for next run
    if upstream_hash:
        HASH_CACHE_FILE.write_text(actual_hash)

    return len(merged_normal) + len(merged_strict)


if __name__ == "__main__":
    n = build()
    sys.exit(0 if n > 0 else 1)
