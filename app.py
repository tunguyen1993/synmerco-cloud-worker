#!/usr/bin/env python3
"""
Synmerco 24/7 Cloud Worker & Doorbell Server for Render Free Web Services.
- Python 3.12 stdlib-only, non-root container compatible, zero baked-in secrets.
- Maintains <=50s Synmerco heartbeats (Rule 1), listens on PORT (default 10000) for
  GET /health and POST /doorbell webhook wakeups (Rule 18), and applies
  v86-Aligned pre-bid filtering/pricing (Rule 14, Rule 15, Rule 18, Rule 26, Rule 29).
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
MAX_DOORBELL_BYTES = 262144
RULE15_FORBIDDEN_WORDS = ("evaluator", "dispute", "revision", "appeal", "requirements met")

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
        if api_key and did:
            bots.append({"botKey": key, "did": did, "apiKey": api_key})

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

    return {"bid_safe": True, "block_reason": None, "budget_cents": budget_cents, "num_pulls": num_pulls}


def compute_v86_bid_cents(budget_cents: int, score: int, passed: int) -> int:
    """Compute v86-Aligned bid amount respecting Rule 18 tiers and Rule 26 $15 cap."""
    effective_budget = min(budget_cents, 1500) if passed == 0 else budget_cents
    if passed == 0:
        raw = int(round(effective_budget * 0.22))
        floor = 135 if effective_budget >= 250 else (100 if effective_budget >= 100 else 1)
        return max(floor, min(effective_budget, raw))
    if score >= 65:
        ratio = 0.68
    elif score >= 55:
        ratio = 0.76
    else:
        ratio = 0.52
    return max(100 if effective_budget >= 100 else 1, min(effective_budget, int(round(effective_budget * ratio))))


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
    """Stateful Synmerco worker coordinating heartbeat, doorbell wakeup, and auto-bidding."""

    def __init__(self, api_base: str, bots: list[dict[str, str]], auto_bid: bool = True) -> None:
        self.api_base = api_base
        self.bots = bots
        self.auto_bid = auto_bid
        self.start_ts = time.time()
        self.wake_event = threading.Event()
        self.lock = threading.Lock()
        self.bot_states: dict[str, dict[str, Any]] = {}
        self.recent_events: list[dict[str, Any]] = []
        self.attempted_intent_bids: set[str] = set()
        self.doorbell_hits = 0

    def _record_event(self, kind: str, detail: dict[str, Any]) -> None:
        with self.lock:
            self.recent_events.append({"ts": utc_now_iso(), "kind": kind, **detail})
            if len(self.recent_events) > 50:
                self.recent_events = self.recent_events[-50:]

    def api_call(self, path: str, method: str = "GET", body: dict[str, Any] | None = None, api_key: str | None = None) -> dict[str, Any]:
        """Execute an HTTPS JSON call to Synmerco API."""
        url = f"{self.api_base}{path}"
        headers = {"User-Agent": "SynmercoCloudWorker/1.0", "Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        data_bytes = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data_bytes = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
                return json.loads(raw) if raw.strip() else {"ok": True}
        except urllib.error.HTTPError as exc:
            err_body = exc.read(65536).decode("utf-8", errors="replace")
            return {"ok": False, "http_status": exc.code, "error": err_body[:300]}
        except Exception as exc:
            return {"ok": False, "error": repr(exc)[:300]}

    def step_once(self) -> None:
        """Run one heartbeat, escrow check, and optional auto-bid pass across configured bots."""
        for bot in self.bots:
            bkey = bot["botKey"]
            did = bot["did"]
            api_key = bot["apiKey"]
            hb = self.api_call("/v1/agents/heartbeat", method="POST", body={}, api_key=api_key)
            esc_res = self.api_call("/v1/escrows?role=seller&limit=20", method="GET", api_key=api_key)
            escrows = esc_res.get("escrows") or esc_res.get("items") or []
            active_escrows = [
                {
                    "id": e.get("escrowId") or e.get("id"),
                    "state": e.get("state"),
                    "netToSellerCents": e.get("netToSellerCents"),
                }
                for e in escrows
                if str(e.get("state") or "") in {"funded", "revision_requested", "disputed"}
            ]
            readiness = hb.get("readiness") if isinstance(hb.get("readiness"), dict) else {}
            track = hb.get("trackRecord") if isinstance(hb.get("trackRecord"), dict) else {}
            stats = track.get("stats") if isinstance(track.get("stats"), dict) else {}
            score = int(hb.get("synmercoScore") or track.get("synmercoScore") or 0)
            passed = int(stats.get("passed") or 0)
            busy = bool(hb.get("busy")) or len(active_escrows) > 0
            live = bool(readiness.get("live"))

            with self.lock:
                self.bot_states[bkey] = {
                    "botKey": bkey,
                    "didMasked": mask_did(did),
                    "live": live,
                    "busy": busy,
                    "score": score,
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

            intents_res = self.api_call("/v1/intents?limit=25", method="GET", api_key=api_key)
            intents = intents_res.get("intents") or intents_res.get("items") or []
            for item in intents:
                iid = str(item.get("intentId") or item.get("id") or "").strip()
                if not iid:
                    continue
                dedupe_key = f"{bkey}:{iid}"
                if dedupe_key in self.attempted_intent_bids:
                    continue
                gate = evaluate_intent_pre_bid(item)
                if not gate["bid_safe"]:
                    self.attempted_intent_bids.add(dedupe_key)
                    continue
                amount_cents = compute_v86_bid_cents(gate["budget_cents"], score, passed)
                bid_msg = build_bid_message(bkey, item)
                bid_res = self.api_call(
                    f"/v1/intents/{urllib.parse.quote(iid)}/bids",
                    method="POST",
                    body={"bidderDid": did, "amountCents": amount_cents, "message": bid_msg},
                    api_key=api_key,
                )
                self.attempted_intent_bids.add(dedupe_key)
                self._record_event(
                    "auto_bid",
                    {
                        "botKey": bkey,
                        "intentId": iid,
                        "amountCents": amount_cents,
                        "ok": bool(bid_res.get("ok", True) and not bid_res.get("error")),
                        "error": bid_res.get("error"),
                    },
                )

    def _public_health_unlocked(self) -> dict[str, Any]:
        """Build secret-free health payload (caller must hold self.lock)."""
        return {
            "ok": True,
            "service": "synmerco-cloud-worker",
            "uptimeSec": round(time.time() - self.start_ts, 1),
            "configuredBots": len(self.bots),
            "autoBid": self.auto_bid,
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

        def do_GET(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if path in {"/", "/health"}:
                self._send_json(200, worker.public_health())
                return
            if path == "/api/state":
                if not sync_token:
                    self._send_json(403, {"ok": False, "error": "cloud_sync_token_not_configured"})
                    return
                auth = self.headers.get("Authorization") or ""
                expected = f"Bearer {sync_token}"
                if not hmac.compare_digest(auth.encode("utf-8"), expected.encode("utf-8")):
                    self._send_json(401, {"ok": False, "error": "unauthorized"})
                    return
                self._send_json(200, worker.authenticated_state())
                return
            self._send_json(404, {"ok": False, "error": "not_found"})

        def do_POST(self) -> None:
            path = urllib.parse.urlparse(self.path).path
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
            worker.wake_event.set()
            self._send_json(202, {"ok": True, "accepted": True, "ts": utc_now_iso()})

    return DoorbellHandler


def _run_self_test() -> dict[str, Any]:
    """Run local adversarial tests covering v86 pricing, honeypot gate, auth, and HTTP server."""
    assert evaluate_intent_pre_bid({"title": "Send USDC bond", "budgetCents": 500})["bid_safe"] is False
    assert evaluate_intent_pre_bid({"title": "Post on Discord", "budgetCents": 500})["bid_safe"] is False
    assert evaluate_intent_pre_bid(
        {"title": "Two pulls", "budgetCents": 500, "deadline": "2020-01-01T00:00:00Z"}, now_ts=1700000000.0
    )["bid_safe"] is False
    safe_item = {"title": "Verify SEC filing EX-99.1", "budgetCents": 500, "deadline": "2099-01-01T00:00:00Z"}
    assert evaluate_intent_pre_bid(safe_item, now_ts=1700000000.0)["bid_safe"] is True

    assert compute_v86_bid_cents(500, 28, 0) == 135
    assert compute_v86_bid_cents(2500, 28, 0) == 330
    assert compute_v86_bid_cents(500, 69, 3) == 340
    assert compute_v86_bid_cents(500, 59, 4) == 380
    assert compute_v86_bid_cents(500, 48, 1) == 260
    msg = build_bid_message("CLOUD_1", safe_item)
    assert not any(w in msg.lower() for w in RULE15_FORBIDDEN_WORDS)

    mock_bids: list[dict[str, Any]] = []

    class MockSynmerco(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def do_POST(self) -> None:
            if self.path == "/v1/agents/heartbeat":
                out = {"ok": True, "readiness": {"live": True}, "busy": False, "synmercoScore": 28, "trackRecord": {"stats": {"passed": 0}}}
            elif "/bids" in self.path:
                n = int(self.headers.get("Content-Length") or "0")
                mock_bids.append(json.loads(self.rfile.read(n).decode("utf-8")))
                out = {"ok": True, "bidId": "bid_test_1"}
            else:
                out = {"ok": False}
            raw = json.dumps(out).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path.startswith("/v1/escrows"):
                out = {"escrows": []}
            elif self.path.startswith("/v1/intents"):
                out = {"intents": [{"intentId": "int_1", **safe_item}]}
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
        [{"botKey": "CLOUD_1", "did": "did:pkh:eip155:8453:0x000000000000000000000000000000000000dEaD", "apiKey": secret_key}],
        auto_bid=True,
    )
    worker.step_once()
    assert len(mock_bids) == 1 and mock_bids[0]["amountCents"] == 135

    sync_tok = "sync-tok-test"
    app_srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(worker, sync_tok, "hook-sec"))
    app_port = app_srv.server_address[1]
    threading.Thread(target=app_srv.serve_forever, daemon=True).start()

    health_txt = urllib.request.urlopen(f"http://127.0.0.1:{app_port}/health", timeout=5).read().decode("utf-8")
    assert secret_key not in health_txt and json.loads(health_txt)["ok"] is True

    try:
        urllib.request.urlopen(f"http://127.0.0.1:{app_port}/api/state", timeout=5)
        raise AssertionError("Expected 401 on unauthenticated /api/state")
    except urllib.error.HTTPError as exc:
        assert exc.code == 401

    req_state = urllib.request.Request(f"http://127.0.0.1:{app_port}/api/state", headers={"Authorization": f"Bearer {sync_tok}"})
    state_json = json.loads(urllib.request.urlopen(req_state, timeout=5).read().decode("utf-8"))
    assert state_json["attemptedBidsCount"] == 1

    req_hook = urllib.request.Request(
        f"http://127.0.0.1:{app_port}/doorbell",
        data=b'{"event":"job.available"}',
        headers={"Content-Type": "application/json", "X-Webhook-Secret": "hook-sec"},
        method="POST",
    )
    hook_res = json.loads(urllib.request.urlopen(req_hook, timeout=5).read().decode("utf-8"))
    assert hook_res["accepted"] is True and worker.wake_event.is_set()

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
    sync_token = (os.environ.get("CLOUD_SYNC_TOKEN") or "").strip()
    webhook_secret = (os.environ.get("SYNMERCO_WEBHOOK_SECRET") or "").strip()
    port = int(os.environ.get("PORT") or "10000")

    worker = SynmercoCloudWorker(api_base=api_base, bots=bots, auto_bid=auto_bid)
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
