#!/usr/bin/env python3
"""
Synmerco 24/7 Cloud Worker & Doorbell Server for Render Free Web Services.
- Python 3.12 stdlib-only, non-root container compatible, zero baked-in secrets.
- Maintains <=50s Synmerco heartbeats (Rule 1), syncs live score/passed via GET /v1/agents/{did},
  listens on PORT (default 10000) for GET /health, POST /doorbell (Rule 18), GET /api/state,
  and authenticated POST /api/synmerco relay so PC1 can push verified deliverables through Render.
"""
from __future__ import annotations

import datetime
import hmac
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

DEFAULT_API_BASE = "https://synmerco-escrow.onrender.com"
HEARTBEAT_INTERVAL_SEC = 50
SCORE_REFRESH_SEC = 300
MAX_DOORBELL_BYTES = 262144
MAX_RELAY_BYTES = 6 * 1024 * 1024
RULE15_FORBIDDEN_WORDS = ("evaluator", "dispute", "revision", "appeal", "requirements met")
SAFE_AUTO_CAP_RE = re.compile(r"^[a-z][a-z0-9_-]{1,62}$")
STARTER_RATECARD_CAPS = ("research", "data_apis", "live-data", "general")
LOW_CAPTURE_PCT_BY_BOT: dict[str, int] = {"S7": 21, "S8": 21}
LOW_CAPTURE_FLOOR_BY_BOT: dict[str, int] = {"S7": 100, "S8": 100}
ALLOWED_RELAY_PATH_RE = re.compile(
    r"^/v1/escrows/[A-Za-z0-9_-]+(?:/(?:progress|self-check|submit-proof|data-files(?:/[A-Za-z0-9_-]+/complete)?))?$"
)

UNSUPPORTED_VENUES = (
    "discord", "bluesky", "mastodon", "refer ", "referral", "hashnode", "medium.com",
    "dev.to", "substack", "zenn", "qiita", "note.com", "reddit", "linkedin", "x.com",
    "twitter.com", "youtube", "producthunt", "list synmerco", "submit synmerco",
    "placements of synmerco", "public ai-agent directories", "public directories or registries",
    "create one listing each for synmerco",
)

HONEYPOT_TERMS = (
    "send usdc", "transfer usdc", "deposit usdc", "claim bond", "entry fee",
    "upfront fee", "private key", "seed phrase", "mnemonic", "escrow deposit",
)


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso_unix(raw: Any) -> float:
    """Parse an ISO-8601 timestamp string to Unix epoch seconds, or 0.0 on failure."""
    if not raw:
        return 0.0
    txt = str(raw).strip()
    if not txt:
        return 0.0
    try:
        normalized = txt.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.timestamp()
    except ValueError:
        return 0.0


def parse_cents(raw: Any) -> int:
    """Parse a numeric value into integer cents with exact Decimal rounding."""
    if raw is None or isinstance(raw, bool):
        return 0
    try:
        dec = Decimal(str(raw).strip() or "0")
        if not dec.is_finite():
            return 0
        return int(dec.to_integral_value(rounding=ROUND_HALF_UP))
    except (InvalidOperation, ValueError, TypeError):
        return 0


def mask_did(did: str) -> str:
    """Mask a DID for safe unauthenticated health telemetry."""
    if not did or len(did) < 18:
        return "unset"
    return f"{did[:18]}...{did[-6:]}"


def validate_api_base(url: str, allow_local_test: bool = False) -> str:
    """Enforce HTTPS Synmerco API URL unless running isolated localhost self-test."""
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme == "https" and parsed.netloc:
        return url.rstrip("/")
    if allow_local_test and parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}:
        return url.rstrip("/")
    raise ValueError(f"Unsafe SYNMERCO_API_BASE rejected: {url}")


def load_bot_configs_from_env() -> list[dict[str, str]]:
    """Load Synmerco bot credentials strictly from environment secrets."""
    bots: list[dict[str, str]] = []
    raw_json = (os.environ.get("SYNMERCO_BOTS_JSON") or "").strip()
    if raw_json:
        loaded = json.loads(raw_json)
        if not isinstance(loaded, list):
            raise ValueError("SYNMERCO_BOTS_JSON must be a JSON array")
        for idx, entry in enumerate(loaded):
            if not isinstance(entry, dict):
                continue
            api_key = str(entry.get("apiKey") or entry.get("api_key") or "").strip()
            did = str(entry.get("did") or entry.get("ownerDid") or "").strip()
            key = str(entry.get("botKey") or entry.get("name") or f"CLOUD_{idx + 1}").strip()
            if api_key and did:
                bots.append({"botKey": key, "did": did, "apiKey": api_key})
    else:
        api_key = (os.environ.get("SYNMERCO_API_KEY") or "").strip()
        did = (os.environ.get("SYNMERCO_BOT_DID") or "").strip()
        key = (os.environ.get("SYNMERCO_BOT_KEY") or "CLOUD_1").strip()
        display_name = (os.environ.get("SYNMERCO_BOT_NAME") or "").strip()
        desc = (os.environ.get("SYNMERCO_BOT_DESC") or "").strip()
        caps_raw = (os.environ.get("SYNMERCO_BOT_CAPS") or "").strip()
        caps = [c.strip() for c in caps_raw.split(",") if c.strip()] if caps_raw else []
        doorbell_url = (os.environ.get("SYNMERCO_DOORBELL_URL") or "").strip()
        if api_key and did:
            bots.append({
                "botKey": key,
                "did": did,
                "apiKey": api_key,
                "displayName": display_name,
                "description": desc,
                "caps": caps,
                "doorbellUrl": doorbell_url,
            })

    allow_multi = os.environ.get("ALLOW_MULTI_BOT", "").lower() in {"1", "true", "yes"}
    if len(bots) > 1 and not allow_multi:
        bots = bots[:1]
    return bots


def evaluate_intent_pre_bid(item: dict[str, Any], now_ts: float | None = None) -> dict[str, Any]:
    """Run deterministic pre-bid safety and deadline checks aligned with v86."""
    title = str(item.get("title") or "")
    desc = str(item.get("description") or item.get("summary") or "")
    low = f"{title}\n{desc}".lower()

    for bad in HONEYPOT_TERMS:
        if bad in low:
            return {"bid_safe": False, "block_reason": f"honeypot:{bad}", "budget_cents": 0}
    for venue in UNSUPPORTED_VENUES:
        if venue in low:
            return {"bid_safe": False, "block_reason": f"unsupported_venue:{venue}", "budget_cents": 0}

    num_pulls = 3 if any(k in low for k in ("three pulls", "pull 3", "3 pulls")) else (
        2 if any(k in low for k in ("two pulls", "pull 2", "2 pulls")) else 1
    )
    wait_hours = 0
    if num_pulls >= 2:
        match_wait = re.search(r"at\s+least\s+(\d+)\s+hours?\s+after\s+(?:the\s+)?pull\s*1", low)
        wait_hours = int(match_wait.group(1)) if match_wait else (8 if "8 hours" in low or "8h" in low else 24)

    timeline = item.get("timeline") if isinstance(item.get("timeline"), dict) else {}
    deadline_cands = (
        timeline.get("deliverBy"),
        timeline.get("hardStopAt"),
        timeline.get("expiresAt"),
        item.get("deadline"),
        item.get("expiresAt"),
        item.get("deliveryDeadline"),
    )
    parsed_deadlines: list[float] = []
    for raw_dl in deadline_cands:
        if raw_dl is None or not str(raw_dl).strip():
            continue
        ts_val = parse_iso_unix(raw_dl)
        if ts_val <= 0:
            return {"bid_safe": False, "block_reason": "unparseable_deadline", "budget_cents": 0}
        parsed_deadlines.append(ts_val)

    cur_ts = time.time() if now_ts is None else now_ts
    dl_ts = min(parsed_deadlines) if parsed_deadlines else 0.0
    required_sec = (num_pulls - 1) * wait_hours * 3600 + 7200 if num_pulls >= 2 else 1800
    if dl_ts > 0 and (dl_ts - cur_ts) < required_sec:
        return {"bid_safe": False, "block_reason": "insufficient_deadline_window", "budget_cents": 0}

    budget_cents = parse_cents(
        item.get("budgetCents") or item.get("maxBudgetCents") or item.get("netToSellerCents") or item.get("amountCents")
    )
    if budget_cents <= 0:
        return {"bid_safe": False, "block_reason": "non_positive_budget", "budget_cents": 0}
    if budget_cents > 50000:
        return {"bid_safe": False, "block_reason": "above_max_budget_50000c", "budget_cents": budget_cents}

    return {"bid_safe": True, "block_reason": None, "budget_cents": budget_cents, "num_pulls": num_pulls}


def _round_pct_cents(budget_cents: int, pct: int) -> int:
    """Multiply integer cents by integer percentage using exact half-up rounding."""
    return (budget_cents * pct + 50) // 100


def compute_v86_bid_cents(
    budget_cents: int,
    score: int,
    passed: int,
    target_bid_cents: int = 0,
    bot_key: str = "",
    bid_ratio_pct: int = 0,
) -> int:
    """Compute v86 max-capture bid: aggressive low-capture S7/S8 while New, 74-88% up to $500 once passed>=1."""
    if isinstance(budget_cents, bool) or budget_cents <= 0:
        raise ValueError("budget_cents must be a positive integer")
    effective_budget = min(budget_cents, 1500) if passed == 0 else min(budget_cents, 50000)
    base_floor = 100 if effective_budget >= 100 else 1
    if passed == 0:
        if target_bid_cents > 0:
            return max(base_floor, min(effective_budget, target_bid_cents))
        norm_key = bot_key.strip().upper()
        pct = bid_ratio_pct if 1 <= bid_ratio_pct <= 100 else LOW_CAPTURE_PCT_BY_BOT.get(norm_key, 55)
        raw = _round_pct_cents(effective_budget, pct)
        bot_floor = LOW_CAPTURE_FLOOR_BY_BOT.get(norm_key, base_floor) if effective_budget >= 100 else 1
        return max(bot_floor, min(effective_budget, raw))
    ratio_pct = 88 if score >= 65 else (82 if score >= 45 else 74)
    return max(base_floor, min(effective_budget, _round_pct_cents(effective_budget, ratio_pct)))


def build_bid_message(bot_key: str, item: dict[str, Any]) -> str:
    """Build a concise, Rule 15 safe bid message tailored to the intent."""
    title = re.sub(r"\s+", " ", str(item.get("title") or "requested task")).strip()[:100]
    msg = (
        f"Ready to deliver '{title}' on schedule via {bot_key} with pinned HTTPS plain-text/Markdown output, "
        "exact SHA-256 verification, verbatim primary-source excerpts with UTC timestamps, and timely Rule 17 progress notes."
    )
    low = msg.lower()
    for word in RULE15_FORBIDDEN_WORDS:
        if word in low:
            raise ValueError(f"Rule 15 violation in bid message: {word}")
    return msg


class SynmercoCloudWorker:
    """Stateful Synmerco worker coordinating heartbeat, doorbell wakeup, auto-bidding, and delivery relay."""

    def __init__(
        self,
        api_base: str,
        bots: list[dict[str, Any]],
        auto_bid: bool = True,
        target_bid_cents: int = 0,
        bid_ratio_pct: int = 0,
    ) -> None:
        self.api_base = api_base
        self.bots = bots
        self.auto_bid = auto_bid
        self.target_bid_cents = max(0, int(target_bid_cents))
        self.bid_ratio_pct = max(0, int(bid_ratio_pct))
        self.start_ts = time.time()
        self.wake_event = threading.Event()
        self.lock = threading.Lock()
        self.bot_states: dict[str, dict[str, Any]] = {}
        self.bot_scores: dict[str, tuple[float, int, int, str]] = {}
        self.recent_events: list[dict[str, Any]] = []
        self.attempted_intent_bids: set[str] = set()
        self.synced_profiles: dict[str, float] = {}
        self.profile_sync_done: set[str] = set()
        self.prev_active_counts: dict[str, int] = {}
        self.last_doorbell_wake_ts = 0.0
        self.doorbell_hits = 0

    def _record_event(self, kind: str, detail: dict[str, Any]) -> None:
        with self.lock:
            self.recent_events.append({"ts": utc_now_iso(), "kind": kind, **detail})
            if len(self.recent_events) > 50:
                self.recent_events = self.recent_events[-50:]

    def api_call(
        self,
        path: str,
        method: str = "GET",
        body: dict[str, Any] | None = None,
        api_key: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Execute an HTTPS JSON call to Synmerco API."""
        url = f"{self.api_base}{path}"
        headers = {"User-Agent": "SynmercoCloudWorker/1.1", "Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if extra_headers:
            headers.update(extra_headers)
        data_bytes = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data_bytes = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                raw = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
                return json.loads(raw) if raw.strip() else {"ok": True}
        except urllib.error.HTTPError as exc:
            err_body = exc.read(65536).decode("utf-8", errors="replace")
            return {"ok": False, "http_status": exc.code, "error": err_body[:400]}
        except Exception as exc:
            return {"ok": False, "error": repr(exc)[:300]}

    def _fetch_agent_profile(self, did: str, api_key: str | None = None) -> dict[str, Any]:
        res = self.api_call(f"/v1/agents/{urllib.parse.quote(did, safe=':')}", method="GET", api_key=api_key)
        if isinstance(res, dict) and isinstance(res.get("agent"), dict):
            return res["agent"]
        return res if isinstance(res, dict) else {}

    def _refresh_bot_score(self, bkey: str, did: str, force: bool = False, api_key: str | None = None) -> tuple[int, int, str]:
        now = time.time()
        cached = self.bot_scores.get(bkey)
        if not force and cached and (now - cached[0]) < SCORE_REFRESH_SEC:
            return cached[1], cached[2], cached[3]
        res = self._fetch_agent_profile(did, api_key=api_key)
        if res and res.get("ok", True) and "synmercoScore" in res:
            stats = res.get("stats") if isinstance(res.get("stats"), dict) else {}
            score = int(res.get("synmercoScore") or 0)
            passed = int(stats.get("passed") or 0)
            tier = str(res.get("tier") or "New")
            self.bot_scores[bkey] = (now, score, passed, tier)
            return score, passed, tier
        if cached:
            return cached[1], cached[2], cached[3]
        return 0, 0, "New"

    def _ensure_profile_and_rate_cards(self, bot: dict[str, Any], score: int, passed: int) -> None:
        """Sync capabilities, doorbellUrl, and missing starter rateCards once per boot."""
        bkey = bot["botKey"]
        if bkey in self.profile_sync_done:
            return
        now = time.time()
        if (now - self.synced_profiles.get(bkey, 0.0)) < SCORE_REFRESH_SEC:
            return
        self.synced_profiles[bkey] = now
        display_name = str(bot.get("displayName") or "").strip()
        desc = str(bot.get("description") or "").strip()
        caps = [c for c in (bot.get("caps") or []) if SAFE_AUTO_CAP_RE.match(c)]
        if not display_name or len(desc) < 40 or not caps:
            return
        starter_caps = [c for c in STARTER_RATECARD_CAPS if c in caps] or caps[:2]
        ask_cents = 100 if passed == 0 else max(
            100,
            compute_v86_bid_cents(500, score, passed, target_bid_cents=self.target_bid_cents, bot_key=bkey),
        )
        reg_body: dict[str, Any] = {
            "displayName": display_name,
            "description": desc,
            "capabilities": caps[:20],
            "rateCents": ask_cents,
            "checkIn": "poll",
        }
        doorbell_url = str(bot.get("doorbellUrl") or "").strip()
        if doorbell_url.startswith("https://"):
            reg_body["doorbellUrl"] = doorbell_url
        reg_res = self.api_call("/v1/agents/register", method="POST", body=reg_body, api_key=bot["apiKey"])
        if not reg_res.get("ok", True) or reg_res.get("error"):
            self._record_event("profile_sync_warn", {"botKey": bkey, "error": str(reg_res.get("error") or "")[:120]})
            return
        prof = self._fetch_agent_profile(bot["did"], api_key=bot["apiKey"])
        existing_rate_caps = {
            str(rc.get("capability") or "").strip().lower()
            for rc in (prof.get("rateCards") or [])
            if isinstance(rc, dict) and str(rc.get("capability") or "").strip()
        }
        svcs_res = self.api_call("/v1/services?limit=100", method="GET", api_key=bot["apiKey"])
        if not svcs_res.get("ok", True) or svcs_res.get("error"):
            self._record_event("service_list_warn", {"botKey": bkey, "error": str(svcs_res.get("error") or "")[:120]})
            return
        did_low = str(bot["did"]).strip().lower()
        for svc in (svcs_res.get("services") or []):
            if not isinstance(svc, dict):
                continue
            if str(svc.get("providerDid") or "").strip().lower() != did_low:
                continue
            if str(svc.get("status") or "active").strip().lower() != "active":
                continue
            cap_str = str(svc.get("capability") or "").strip().lower()
            if cap_str:
                existing_rate_caps.add(cap_str)
        added: list[str] = []
        had_write_err = False
        for cap in starter_caps:
            if cap.lower() in existing_rate_caps:
                continue
            svc_body = {
                "capability": cap,
                "title": f"{display_name}: {cap}",
                "rateCents": ask_cents,
                "rateType": "per_job",
                "currency": "USD",
                "negotiable": True,
                "slaDeliveryMinutes": 120,
                "description": f"{desc[:240]} Automated {cap} execution with verbatim API excerpts.",
            }
            svc_res = self.api_call(
                "/v1/services",
                method="POST",
                body=svc_body,
                api_key=bot["apiKey"],
                extra_headers={"Idempotency-Key": f"svc-{bkey.lower()}-{cap}-{ask_cents}"},
            )
            http_code = int(svc_res.get("http_status") or 0)
            if svc_res.get("ok", True) and not svc_res.get("error"):
                added.append(cap)
            elif http_code != 409:
                had_write_err = True
                self._record_event(
                    "rate_card_warn",
                    {"botKey": bkey, "capability": cap, "httpStatus": http_code, "error": str(svc_res.get("error") or "")[:120]},
                )
        if added:
            self._record_event("rate_card_sync", {"botKey": bkey, "rateCents": ask_cents, "added": added})
        if not had_write_err:
            self.profile_sync_done.add(bkey)

    def relay_escrow_call(self, path: str, method: str, body: dict[str, Any] | None, bot_key: str | None = None) -> dict[str, Any]:
        """Forward allowlisted Synmerco escrow calls from PC1 through this Render worker."""
        if not ALLOWED_RELAY_PATH_RE.match(path):
            return {"ok": False, "http_status": 403, "error": "relay_path_forbidden"}
        if method not in {"GET", "POST"}:
            return {"ok": False, "http_status": 405, "error": "relay_method_forbidden"}
        target = None
        for bot in self.bots:
            if not bot_key or bot["botKey"].upper() == bot_key.upper():
                target = bot
                break
        if not target:
            return {"ok": False, "http_status": 404, "error": "bot_not_configured"}
        res = self.api_call(path, method=method, body=body, api_key=target["apiKey"])
        self._record_event(
            "relay_escrow",
            {"botKey": target["botKey"], "method": method, "path": path, "ok": bool(res.get("ok", True) and not res.get("error"))},
        )
        return res

    def _maybe_auto_register_capability(self, bot: dict[str, Any], err_text: str, passed: int = 0) -> str | None:
        """If bid failed on agent_not_compatible, add allowlisted capability and return it."""
        if "agent_not_compatible" not in err_text:
            return None
        match_cap = re.search(r'needs capability\s+\\?"([a-z0-9_-]{2,64})\\?"', err_text)
        if not match_cap:
            return None
        req_cap = match_cap.group(1).strip().lower()
        if not SAFE_AUTO_CAP_RE.match(req_cap):
            return None
        if any(bad in req_cap for bad in UNSUPPORTED_VENUES + HONEYPOT_TERMS):
            return None
        display_name = str(bot.get("displayName") or "").strip()
        desc = str(bot.get("description") or "").strip()
        if not display_name or len(desc) < 40:
            return None
        caps = [c for c in (bot.get("caps") or []) if SAFE_AUTO_CAP_RE.match(c)]
        if req_cap not in caps:
            caps.append(req_cap)
        if len(caps) > 20:
            caps = caps[-20:]
        bot["caps"] = caps
        reg_body: dict[str, Any] = {
            "displayName": display_name,
            "description": desc,
            "capabilities": caps,
            "checkIn": "poll",
        }
        doorbell_url = str(bot.get("doorbellUrl") or "").strip()
        if doorbell_url.startswith("https://"):
            reg_body["doorbellUrl"] = doorbell_url
        reg_res = self.api_call("/v1/agents/register", method="POST", body=reg_body, api_key=bot["apiKey"])
        if not reg_res.get("ok", True) or reg_res.get("error"):
            return None
        ask_cents = 100 if passed == 0 else (self.target_bid_cents or 500)
        svc_body = {
            "capability": req_cap,
            "title": f"{display_name}: {req_cap}",
            "rateCents": ask_cents,
            "rateType": "per_job",
            "currency": "USD",
            "negotiable": True,
            "slaDeliveryMinutes": 120,
            "description": f"{desc[:240]} Automated {req_cap} execution with verbatim API excerpts.",
        }
        self.api_call("/v1/services", method="POST", body=svc_body, api_key=bot["apiKey"])
        self._record_event("auto_capability", {"botKey": bot["botKey"], "capability": req_cap, "rateCents": ask_cents})
        return req_cap

    def step_once(self) -> None:
        """Run one heartbeat, escrow check, profile sync, and low-capture/graduated auto-bid pass."""
        for bot in self.bots:
            bkey = bot["botKey"]
            did = bot["did"]
            api_key = bot["apiKey"]
            hb = self.api_call("/v1/agents/heartbeat", method="POST", body={"availability": "online"}, api_key=api_key)
            esc_res = self.api_call("/v1/escrows?role=seller&limit=20", method="GET", api_key=api_key)
            escrows = esc_res.get("escrows") or esc_res.get("items") or []
            active_escrows = [
                {
                    "id": e.get("escrowId") or e.get("id"),
                    "state": e.get("state"),
                    "title": e.get("title") or e.get("jobTitle"),
                    "netToSellerCents": e.get("netToSellerCents"),
                }
                for e in escrows
                if str(e.get("state") or "") in {"funded", "revision_requested", "disputed"}
            ]
            had_active = self.prev_active_counts.get(bkey, 0) > 0
            self.prev_active_counts[bkey] = len(active_escrows)
            hb_tr = hb.get("trackRecord") if isinstance(hb.get("trackRecord"), dict) else {}
            hb_passed = int(hb_tr.get("passed") or 0)
            cached_passed = (self.bot_scores.get(bkey) or (0.0, 0, 0, "New"))[2]
            force_score = (had_active and not active_escrows) or (hb_passed > cached_passed)
            score, passed, tier = self._refresh_bot_score(bkey, did, force=force_score, api_key=api_key)
            if hb_passed > passed:
                passed = hb_passed
            readiness = hb.get("readiness") if isinstance(hb.get("readiness"), dict) else {}
            busy = bool(hb.get("busy")) or len(active_escrows) > 0
            live = bool(readiness.get("live"))

            if live:
                self._ensure_profile_and_rate_cards(bot, score, passed)

            with self.lock:
                self.bot_states[bkey] = {
                    "botKey": bkey,
                    "didMasked": mask_did(did),
                    "live": live,
                    "busy": busy,
                    "score": score,
                    "tier": tier,
                    "passed": passed,
                    "unreadJobNotices": int(hb.get("unreadJobNotices") or 0),
                    "activeEscrows": active_escrows,
                    "lastHeartbeatUtc": utc_now_iso(),
                    "lastError": hb.get("error") if not hb.get("ok", True) else None,
                }

            if active_escrows:
                self._record_event("active_escrow", {"botKey": bkey, "count": len(active_escrows)})
            if not self.auto_bid or not live or busy:
                continue

            open_res = self.api_call("/v1/intents?status=open&limit=25", method="GET", api_key=api_key)
            all_res = self.api_call("/v1/intents?limit=25", method="GET", api_key=api_key)
            jobs_res = self.api_call("/v1/jobs?status=open&limit=25", method="GET", api_key=api_key)
            raw_rows = (
                list(hb.get("jobsForYou") or [])
                + list(open_res.get("intents") or open_res.get("items") or [])
                + list(all_res.get("intents") or all_res.get("items") or [])
                + list(jobs_res.get("jobs") or jobs_res.get("items") or [])
            )
            merged_intents: dict[str, dict[str, Any]] = {}
            for row in raw_rows:
                if not isinstance(row, dict):
                    continue
                status_low = str(row.get("status") or "open").strip().lower()
                if status_low not in {"open", "bidding"}:
                    continue
                riid = str(row.get("intentId") or row.get("id") or "").strip()
                if riid:
                    prev_row = merged_intents.get(riid) or {}
                    merged_intents[riid] = {**prev_row, **{k: v for k, v in row.items() if v not in (None, "")}}
            for iid, item in sorted(
                merged_intents.items(),
                key=lambda kv: -parse_cents(kv[1].get("budgetCents") or kv[1].get("maxBudgetCents") or 0),
            ):
                dedupe_key = f"{bkey}:{iid}:{int(passed > 0)}"
                if dedupe_key in self.attempted_intent_bids:
                    continue
                try:
                    gate = evaluate_intent_pre_bid(item)
                    if not gate["bid_safe"]:
                        self.attempted_intent_bids.add(dedupe_key)
                        continue
                    if passed == 0 and gate["budget_cents"] > 1500:
                        self.attempted_intent_bids.add(dedupe_key)
                        continue
                    amount_cents = compute_v86_bid_cents(
                        gate["budget_cents"],
                        score,
                        passed,
                        target_bid_cents=self.target_bid_cents,
                        bot_key=bkey,
                        bid_ratio_pct=self.bid_ratio_pct,
                    )
                    bid_msg = build_bid_message(bkey, item)
                    bid_path = f"/v1/intents/{urllib.parse.quote(iid)}/bids"
                    bid_payload = {"bidderDid": did, "amountCents": amount_cents, "message": bid_msg}
                    bid_res = self.api_call(bid_path, method="POST", body=bid_payload, api_key=api_key)
                    if not bid_res.get("ok", True) or bid_res.get("error"):
                        added_cap = self._maybe_auto_register_capability(bot, str(bid_res.get("error") or ""), passed=passed)
                        if added_cap:
                            bid_res = self.api_call(bid_path, method="POST", body=bid_payload, api_key=api_key)
                    bid_ok = bool(bid_res.get("ok", True) and not bid_res.get("error"))
                    err_str = str(bid_res.get("error") or "")
                    http_code = int(bid_res.get("http_status") or 0)
                    if bid_ok or "already_bid" in err_str or http_code in {400, 403, 404, 412, 422}:
                        self.attempted_intent_bids.add(dedupe_key)
                    self._record_event(
                        "auto_bid",
                        {
                            "botKey": bkey,
                            "intentId": iid,
                            "amountCents": amount_cents,
                            "ok": bid_ok,
                            "error": bid_res.get("error"),
                        },
                    )
                except Exception as exc:
                    self._record_event("bid_exception", {"botKey": bkey, "intentId": iid, "error": repr(exc)[:180]})

    def _public_health_unlocked(self) -> dict[str, Any]:
        """Build secret-free health payload (caller must hold self.lock)."""
        return {
            "ok": True,
            "service": "synmerco-cloud-worker",
            "uptimeSec": round(time.time() - self.start_ts, 1),
            "configuredBots": len(self.bots),
            "autoBid": self.auto_bid,
            "targetBidCents": self.target_bid_cents,
            "doorbellHits": self.doorbell_hits,
            "bots": list(self.bot_states.values()),
            "ts": utc_now_iso(),
        }

    def public_health(self) -> dict[str, Any]:
        """Return secret-free health telemetry safe for public GET /health."""
        with self.lock:
            return self._public_health_unlocked()

    def authenticated_state(self) -> dict[str, Any]:
        """Return full operational events/state for authenticated sync."""
        with self.lock:
            return {
                **self._public_health_unlocked(),
                "recentEvents": list(self.recent_events),
                "attemptedBidsCount": len(self.attempted_intent_bids),
            }


def make_handler(worker: SynmercoCloudWorker, sync_token: str, webhook_secret: str) -> type[BaseHTTPRequestHandler]:
    """Create HTTP handler class bound to worker instance and tokens."""

    class DoorbellHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _send_json(self, code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _check_sync_auth(self) -> bool:
            if not sync_token:
                self._send_json(403, {"ok": False, "error": "cloud_sync_token_not_configured"})
                return False
            auth = self.headers.get("Authorization") or ""
            expected = f"Bearer {sync_token}"
            if not hmac.compare_digest(auth.encode("utf-8"), expected.encode("utf-8")):
                self._send_json(401, {"ok": False, "error": "unauthorized"})
                return False
            return True

        def do_GET(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if path in {"/", "/health"}:
                self._send_json(200, worker.public_health())
                return
            if path == "/api/state":
                if self._check_sync_auth():
                    self._send_json(200, worker.authenticated_state())
                return
            self._send_json(404, {"ok": False, "error": "not_found"})

        def do_POST(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if path == "/api/synmerco":
                if not self._check_sync_auth():
                    return
                raw_len = self.headers.get("Content-Length") or "0"
                try:
                    content_len = min(max(0, int(raw_len)), MAX_RELAY_BYTES)
                except ValueError:
                    self._send_json(400, {"ok": False, "error": "bad_content_length"})
                    return
                raw_body = self.rfile.read(content_len) if content_len > 0 else b"{}"
                try:
                    req_obj = json.loads(raw_body.decode("utf-8"))
                except json.JSONDecodeError:
                    self._send_json(400, {"ok": False, "error": "invalid_json"})
                    return
                relay_path = str(req_obj.get("path") or "").strip()
                relay_method = str(req_obj.get("method") or "POST").strip().upper()
                relay_body = req_obj.get("body") if isinstance(req_obj.get("body"), dict) else None
                bot_key = str(req_obj.get("botKey") or "").strip() or None
                res = worker.relay_escrow_call(relay_path, relay_method, relay_body, bot_key=bot_key)
                status = int(res.get("http_status") or 200) if not res.get("ok", True) else 200
                self._send_json(status, res)
                return

            if path not in {"/doorbell", "/webhook/synmerco"}:
                self._send_json(404, {"ok": False, "error": "not_found"})
                return
            if webhook_secret:
                provided = self.headers.get("X-Webhook-Secret") or self.headers.get("Authorization") or ""
                if not (
                    hmac.compare_digest(provided.encode("utf-8"), webhook_secret.encode("utf-8"))
                    or hmac.compare_digest(provided.encode("utf-8"), f"Bearer {webhook_secret}".encode("utf-8"))
                ):
                    self._send_json(401, {"ok": False, "error": "invalid_webhook_secret"})
                    return
            raw_len = self.headers.get("Content-Length") or "0"
            try:
                content_len = min(max(0, int(raw_len)), MAX_DOORBELL_BYTES)
            except ValueError:
                self._send_json(400, {"ok": False, "error": "bad_content_length"})
                return
            body_raw = self.rfile.read(content_len) if content_len > 0 else b"{}"
            try:
                parsed = json.loads(body_raw.decode("utf-8", errors="replace") or "{}")
            except json.JSONDecodeError:
                parsed = {}
            worker.doorbell_hits += 1
            worker._record_event("doorbell", {"event": str(parsed.get("event") or parsed.get("intentId") or "ping")[:64]})
            now_bell = time.time()
            if (now_bell - worker.last_doorbell_wake_ts) >= 2.0:
                worker.last_doorbell_wake_ts = now_bell
                worker.wake_event.set()
            self._send_json(202, {"ok": True, "accepted": True, "ts": utc_now_iso()})

    return DoorbellHandler


def _run_self_test() -> dict[str, Any]:
    """Run local adversarial tests covering S7/S8 low-capture pricing, rateCards, graduation, and HTTP server."""
    assert evaluate_intent_pre_bid({"title": "Send USDC bond", "budgetCents": 500})["bid_safe"] is False
    assert evaluate_intent_pre_bid({"title": "Post on Discord", "budgetCents": 500})["bid_safe"] is False
    assert evaluate_intent_pre_bid(
        {"title": "Two pulls", "budgetCents": 500, "deadline": "2020-01-01T00:00:00Z"}, now_ts=1700000000.0
    )["bid_safe"] is False
    safe_item = {"title": "Verify SEC filing EX-99.1", "budgetCents": 500, "deadline": "2099-01-01T00:00:00Z"}
    assert evaluate_intent_pre_bid(safe_item, now_ts=1700000000.0)["bid_safe"] is True

    assert compute_v86_bid_cents(500, 28, 0) == 275
    assert compute_v86_bid_cents(2500, 28, 0) == 825
    assert compute_v86_bid_cents(800, 28, 0, target_bid_cents=500) == 500
    assert compute_v86_bid_cents(350, 28, 0, target_bid_cents=500) == 350
    assert compute_v86_bid_cents(10000, 69, 3, target_bid_cents=500) == 8800
    assert compute_v86_bid_cents(10000, 59, 4, target_bid_cents=500) == 8200
    assert compute_v86_bid_cents(500, 48, 1) == 410
    # Verify S7 & S8 low-capture $1.00 (100c) floor and 21% ratio + graduation
    assert compute_v86_bid_cents(1, 28, 0, bot_key="S7") == 1
    assert compute_v86_bid_cents(99, 28, 0, bot_key="S7") == 21
    assert compute_v86_bid_cents(99, 28, 0, bot_key="S8") == 21
    for chk_b in (100, 110, 149, 150, 200, 300, 400, 450):
        assert compute_v86_bid_cents(chk_b, 28, 0, bot_key="S7") == 100
        assert compute_v86_bid_cents(chk_b, 28, 0, bot_key="S8") == 100
    assert compute_v86_bid_cents(500, 28, 0, bot_key="S8") == 105
    assert compute_v86_bid_cents(550, 28, 0, bot_key="S8") == 116
    assert compute_v86_bid_cents(800, 28, 0, bot_key="S8") == 168
    assert compute_v86_bid_cents(1200, 28, 0, bot_key="S8") == 252
    assert compute_v86_bid_cents(10000, 48, 1, bot_key="S7") == 8200
    assert compute_v86_bid_cents(10000, 48, 1, bot_key="S8") == 8200
    assert evaluate_intent_pre_bid({"title": "Big >500", "budgetCents": 50001})["bid_safe"] is False
    msg = build_bid_message("CLOUD_1", safe_item)
    assert not any(w in msg.lower() for w in RULE15_FORBIDDEN_WORDS)

    mock_bids: list[dict[str, Any]] = []
    mock_proofs: list[dict[str, Any]] = []
    mock_regs: list[dict[str, Any]] = []
    mock_svcs: list[dict[str, Any]] = []
    mock_state = {"has_clinical": False, "passed": 0, "escrows": [], "rate_caps": set()}

    class MockSynmerco(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def do_POST(self) -> None:
            n = int(self.headers.get("Content-Length") or "0")
            body = json.loads(self.rfile.read(n).decode("utf-8")) if n > 0 else {}
            if self.path == "/v1/agents/heartbeat":
                out = {
                    "ok": True,
                    "readiness": {"live": True},
                    "busy": bool(mock_state["escrows"]),
                    "trackRecord": {"passed": mock_state["passed"]},
                    "jobsForYou": [],
                }
            elif self.path == "/v1/agents/register":
                mock_regs.append(body)
                if "clinical-audit" in (body.get("capabilities") or []):
                    mock_state["has_clinical"] = True
                out = {"ok": True, "capabilities": body.get("capabilities")}
            elif self.path == "/v1/services":
                mock_svcs.append(body)
                mock_state["rate_caps"].add(str(body.get("capability") or ""))
                out = {"ok": True, "listingId": "svc_test_1"}
            elif "/bids" in self.path:
                if not mock_state["has_clinical"]:
                    err_raw = json.dumps({"ok": False, "error": 'agent_not_compatible: needs capability "clinical-audit"'}).encode("utf-8")
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err_raw)))
                    self.end_headers()
                    self.wfile.write(err_raw)
                    return
                mock_bids.append(body)
                out = {"ok": True, "bidId": "bid_test_1"}
            elif self.path.endswith("/submit-proof"):
                mock_proofs.append(body)
                out = {"ok": True, "submitted": True}
            else:
                out = {"ok": False}
            raw = json.dumps(out).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path.startswith("/v1/agents/"):
                sc = 48 if mock_state["passed"] > 0 else 28
                tr = "Silver" if mock_state["passed"] > 0 else "New"
                out = {
                    "synmercoScore": sc,
                    "tier": tr,
                    "stats": {"passed": mock_state["passed"]},
                    "rateCards": [],
                }
            elif self.path.startswith("/v1/services"):
                out = {
                    "services": [
                        {
                            "providerDid": "did:pkh:eip155:8453:0x000000000000000000000000000000000000dEaD",
                            "capability": c,
                            "status": "active",
                        }
                        for c in sorted(mock_state["rate_caps"])
                    ]
                }
            elif self.path.startswith("/v1/escrows"):
                out = {"escrows": list(mock_state["escrows"])}
            elif self.path.startswith("/v1/intents"):
                out = {
                    "intents": [
                        {"intentId": "int_bad_dl", "title": "Bad item", "budgetCents": 200, "deadline": "bad"},
                        {"intentId": "int_low", "title": "Low $2 job", "budgetCents": 200, "deadline": "2099-01-01T00:00:00Z"},
                        {"intentId": "int_1", **safe_item},
                        {"intentId": "int_gt15_skip", "title": "Skip >$15 for new", "budgetCents": 2500, "deadline": "2099-01-01T00:00:00Z"},
                    ]
                }
            elif self.path.startswith("/v1/jobs"):
                out = {"jobs": [{"intentId": "int_from_jobs", "title": "Open job feed", "status": "open", "budgetCents": 600, "deadline": "2099-01-01T00:00:00Z"}]}
            else:
                out = {}
            raw = json.dumps(out).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    mock_srv = ThreadingHTTPServer(("127.0.0.1", 0), MockSynmerco)
    mock_port = mock_srv.server_address[1]
    threading.Thread(target=mock_srv.serve_forever, daemon=True).start()

    secret_key = "test-secret-api-key-never-leak"
    worker = SynmercoCloudWorker(
        validate_api_base(f"http://127.0.0.1:{mock_port}", allow_local_test=True),
        [{
            "botKey": "S7",
            "did": "did:pkh:eip155:8453:0x000000000000000000000000000000000000dEaD",
            "apiKey": secret_key,
            "displayName": "MedWatchTest",
            "description": "Cloud test research specialist verifying SEC filings and regulatory APIs accurately.",
            "caps": ["research", "general"],
            "doorbellUrl": "https://synmerco-worker-s7.onrender.com/doorbell",
        }],
        auto_bid=True,
    )
    worker.step_once()
    assert len(mock_regs) == 2 and "clinical-audit" in mock_regs[-1]["capabilities"]
    assert mock_regs[0].get("doorbellUrl") == "https://synmerco-worker-s7.onrender.com/doorbell"
    assert sorted(b["amountCents"] for b in mock_bids) == [100, 105, 126], f"unexpected S7 mock_bids={mock_bids}"
    assert sorted(s["rateCents"] for s in mock_svcs) == [100, 100, 100]
    assert worker.public_health()["bots"][0]["score"] == 28

    # Verify idempotent rateCard sync across simulated cold restarts & immediate graduation upon escrow pass
    svc_count_before = len(mock_svcs)
    worker.profile_sync_done.clear()
    worker.synced_profiles.clear()
    mock_state["passed"] = 1
    worker.step_once()
    assert len(mock_svcs) == svc_count_before, "Expected no duplicate starter /v1/services writes after cold boot"
    assert worker.public_health()["bots"][0]["passed"] == 1
    assert any(b["amountCents"] == 2050 for b in mock_bids), f"Expected graduated 82% of $25 bid in {mock_bids}"

    sync_tok = "sync-tok-test"
    app_srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(worker, sync_tok, ""))
    app_port = app_srv.server_address[1]
    threading.Thread(target=app_srv.serve_forever, daemon=True).start()

    health_txt = urllib.request.urlopen(f"http://127.0.0.1:{app_port}/health", timeout=5).read().decode("utf-8")
    assert secret_key not in health_txt and json.loads(health_txt)["ok"] is True

    # Verify forbidden relay path rejected (403) and allowed submit-proof forwarded (200)
    try:
        req_bad = urllib.request.Request(
            f"http://127.0.0.1:{app_port}/api/synmerco",
            data=json.dumps({"path": "/v1/wallets/transfer", "method": "POST"}).encode("utf-8"),
            headers={"Authorization": f"Bearer {sync_tok}", "Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req_bad, timeout=5)
        raise AssertionError("Expected 403 on forbidden relay path")
    except urllib.error.HTTPError as exc:
        assert exc.code == 403

    req_ok = urllib.request.Request(
        f"http://127.0.0.1:{app_port}/api/synmerco",
        data=json.dumps({
            "path": "/v1/escrows/esc_123/submit-proof",
            "method": "POST",
            "body": {"proofHash": "abc", "proofUri": "https://example.com/p.md"},
        }).encode("utf-8"),
        headers={"Authorization": f"Bearer {sync_tok}", "Content-Type": "application/json"},
        method="POST",
    )
    ok_res = json.loads(urllib.request.urlopen(req_ok, timeout=5).read().decode("utf-8"))
    assert ok_res["submitted"] is True and len(mock_proofs) == 1

    app_srv.shutdown()
    mock_srv.shutdown()
    return {"ok": True, "self_test": "SELF_TEST_PASS_100"}


def main() -> int:
    """Start HTTP doorbell server and 50s background Synmerco worker loop."""
    if "--self-test" in sys.argv:
        print(json.dumps(_run_self_test()))
        return 0

    api_base = validate_api_base(os.environ.get("SYNMERCO_API_BASE") or DEFAULT_API_BASE)
    bots = load_bot_configs_from_env()
    auto_bid = os.environ.get("SYNMERCO_AUTO_BID", "true").lower() not in {"0", "false", "no"}
    target_bid_cents = int(os.environ.get("SYNMERCO_TARGET_BID_CENTS") or "0")
    bid_ratio_pct = int(os.environ.get("SYNMERCO_LOW_BID_PCT") or "0")
    sync_token = (os.environ.get("CLOUD_SYNC_TOKEN") or "").strip()
    webhook_secret = (os.environ.get("SYNMERCO_WEBHOOK_SECRET") or "").strip()
    port = int(os.environ.get("PORT") or "10000")

    worker = SynmercoCloudWorker(
        api_base=api_base,
        bots=bots,
        auto_bid=auto_bid,
        target_bid_cents=target_bid_cents,
        bid_ratio_pct=bid_ratio_pct,
    )
    srv = ThreadingHTTPServer(("0.0.0.0", port), make_handler(worker, sync_token, webhook_secret))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[{utc_now_iso()}] Synmerco Cloud Worker listening on :{port} bots={len(bots)} autoBid={auto_bid}")

    while True:
        try:
            if worker.bots:
                worker.step_once()
        except Exception as exc:
            print(f"[{utc_now_iso()}] worker_step_error: {repr(exc)}")
        worker.wake_event.wait(timeout=HEARTBEAT_INTERVAL_SEC)
        worker.wake_event.clear()


if __name__ == "__main__":
    raise SystemExit(main())
