#!/usr/bin/env python3
"""authd — WhiteMagic hosted-recall gateway sidecar.

Single responsibility: decide, per request, whether it may pass to the
read-only wm SSE upstream, and account for it. One JSON line per request
in state/access.jsonl = the audit trail.

Design constraints (AGENTIC_ECONOMY_PLAN_V1):
- Bearer-key auth; keys.json = {token, name, daily_cap, x402: bool}
- Free eval tier default cap 50/day; metered keys bypass cap via x402 (phase 2)
- Keyless discovery (bounded JSON-RPC methods, globally capped) so directory
  probes and pre-key agents can read metadata
- Zero-friction trial: `X-WM-Trial: 1` grants a few `tools/call`s/day per
  client IP, counters in memory only (no IP stored, hashed, or logged; global
  ceiling). Plain unauthenticated calls still answer the 402 challenge, so
  directory/validator probes read a clean x402 surface
- OAuth 2.1 (oauthd, 2026-09-25): with `--oauth-state` set, live `wm_oa_`
  access tokens are a second key source (sha256 at rest, expiry checked);
  keys.json entries may carry `token_sha256` instead of a plaintext `token`;
  the 401 challenge carries the RFC 9728 resource-metadata pointer when
  `--oauth-resource-metadata` is set
- Keep-alive for self-delimiting responses (upstream JSON buffered <=
  BUFFER_LIMIT, gateway JSON, bodyless HEAD); large/streamed responses stay
  close-delimited so a reused connection never races a close
- Never logs content — only key id, method, status, bytes, latency,
  *bounded* client/UA families (whitelisted categories, never raw strings),
  and the request path on error statuses (query stripped, bounded length).
  Unknown UAs (family `other`) additionally record a content-free fingerprint
  `uah = sha256(UA)[:12]` for crawler correlation. The JSON-RPC method name
  (`rpc`, sanitized/bounded) is recorded where a body exists, and every x402
  payment failure is audited as `x402-payment-invalid` with a bounded reason —
  without that, a buyer whose payment fails would be invisible in the logs
- The 402 body carries machine-readable `free_paths` (trial + evaluation key)
  beside `accepts`, so agents that never read prose hints still see the free
  alternatives (PRICING_ETHICS)
- stdlib only, no deps; loopback-only, no telemetry
"""
import argparse
import base64
import concurrent.futures
import datetime as dt
import hashlib
import hmac
import json
import http.server
import os
import pathlib
import re
import secrets
import threading
import time
import urllib.parse
import urllib.request
import urllib.error

# One lock for usage.json: concurrent requests otherwise race a truncating
# write against reads (a reader can see an empty file -> JSONDecodeError ->
# dropped connection -> Caddy 502 under burst).
USAGE_LOCK = threading.Lock()

BATCH_TOOL_DEF = {
    "name": "memory.search_batch",
    "description": "Execute multiple memory search queries concurrently in a single turn. Unpacks up to 10 queries, searches the curated corpus, and returns consolidated results.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "queries": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of query strings to search (1 to 10 queries)."
            },
            "limit_per_query": {
                "type": "integer",
                "description": "Max results per query (default 5, max 20).",
                "default": 5
            }
        },
        "required": ["queries"]
    }
}

TOKEN_HEADER = "Authorization"

CRYSTAL_ASSERTION_HEADER = "X-WM-Crystal-Assertion"
CRYSTAL_INTERNAL_SECRET_FILE = "crystal_assertion.secret"
CRYSTAL_OWNER_RE = re.compile(r"^[0-9a-f]{64}$")

def _crystal_b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _make_crystal_assertion(secret: bytes, owner_id: str, method: str, target: str, body: bytes) -> str:
    now = int(time.time())
    claims = {
        "v": 1,
        "owner_id": owner_id,
        "method": method.upper(),
        "target": target,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "iat": now,
        "exp": now + 30,
        "nonce": secrets.token_hex(16),
    }
    encoded = _crystal_b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signature = _crystal_b64(hmac.new(secret, ("wm-crystal-assertion-v1." + encoded).encode("ascii"), hashlib.sha256).digest())
    return encoded + "." + signature

# Keyless discovery: MCP directory probes (Glama, mcp.so, Bazaar) and agents
# browsing before they commit cannot send a Bearer key. These JSON-RPC methods
# pass without auth, under a global anonymous daily cap; everything else
# (tools/call, resource reads) still requires a key.
DISCOVERY_METHODS = {
    "initialize", "notifications/initialized", "tools/list", "ping",
    # Metadata-only listings gateways and censuses probe; the server
    # advertises/returns empty sets, so keyless is safe and keeps directory
    # validation warnings-free (Smithery flagged these 2026-09-22).
    "prompts/list", "resources/list", "resources/templates/list",
}
ANON_NAME = "anonymous"

# Zero-friction trial (2026-09-24): an explicit opt-in header lets an agent
# try `tools/call` without a key or payment, a few calls/day per client IP.
# Plain unauthenticated calls keep answering 402, so directory and validator
# probes still read a clean x402 challenge. Counters live in memory only —
# no IP (raw or hashed) is ever written to disk or to the audit stream.
TRIAL_NAME = "anon-trial"
TRIAL_HEADER = "X-WM-Trial"

# Responses up to this size are read whole so the gateway can set
# Content-Length and keep the client connection alive (directory probes issue
# initialize + tools/list back to back; keep-alive saves a fresh TCP+TLS per
# request). Larger responses stay close-delimited: a reused connection must
# never race the handler's close (Caddy turns that into a 502 under burst).
BUFFER_LIMIT = 64 * 1024
PAID_RESPONSE_LIMIT = 8 * 1024 * 1024

# A dead-end 401 wastes the one probe that mattered. Failed auth (and a
# daily-cap 429) answer with a JSON body pointing at the guide's hosted
# section, where free evaluation keys are issued on request.
FREE_KEY_DOCS = "https://www.whitemagic.dev/whitemagic/guide#hosted"
FREE_KEY_CONTACT = "https://www.whitemagic.dev/contact"
UNAUTH_HINT = (
    "Get an instant free evaluation key (50 recalls/day, no account) at"
    " https://mcp.whitemagic.dev/keys — or request one via"
    " whitemagic.dev/contact. Discovery methods (initialize, tools/list,"
    " prompts/list, resources/list, ping) work without a key."
)

# Bounded analytics families (2026-09-22): the audit line answers "which
# clients and which directory probes use the lanes" without ever storing a
# raw client name or User-Agent. Order matters: first match wins.
CLIENT_FAMILIES = (
    "claude-code", "claude-desktop", "cursor", "codex", "opencode",
    "antigravity", "devin", "windsurf", "vscode", "gemini", "chatgpt",
    "generic-mcp",
)
UA_FAMILIES = (
    ("sentineloracle", "sentinel-oracle"), ("glimind", "sentinel-oracle"),
    ("mcpqueen", "mcpqueen"), ("akashi", "akashi"), ("roninforge", "akashi"),
    ("smithery", "smithery"), ("glama", "glama"), ("pulsemcp", "pulsemcp"),
    ("mcp.so", "mcp-so"), ("mcp-so", "mcp-so"), ("cursor", "cursor"),
    ("fetchgate", "fetchgate"), ("lobehub", "lobehub"), ("docker", "docker"),
    ("uptimerobot", "uptimerobot"),
    # Identified 2026-09-24 via uah fingerprint + loopback UA capture:
    # mcpbeat does a full MCP discovery handshake as its liveness check;
    # f17-reaper GETs the metered route as an x402-discovery probe.
    # PayAI-Bazaar HEAD-probes the catalog (~30 min); x402lens-indexer POSTs
    # (~20 min); BrickBlueBot crawls for the brick.blue agentic-web registry.
    ("mcpbeat", "mcpbeat"), ("f17-reaper", "f17-reaper"),
    ("payai", "payai-bazaar"), ("x402lens", "x402lens"), ("brickblue", "brickblue"),
    ("whitemagic-scorecard", "wm-scorecard"), ("wm-surface-check", "wm-surface-check"),
    ("curl", "curl"), ("python-httpx", "python"), ("python-requests", "python"),
    ("aiohttp", "python"),
    ("go-http-client", "go"), ("node-fetch", "node"), ("undici", "node"),
    ("mozilla", "browser"),
)


def client_family(body):
    """Bounded family from JSON-RPC initialize clientInfo; never raw text."""
    if not body:
        return None
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(doc, dict) or doc.get("method") != "initialize":
        return None
    params = doc.get("params") or {}
    info = params.get("clientInfo") or {}
    name = str(info.get("name", "")).lower().replace("_", " ").replace("-", " ")
    if not name:
        return None
    for family in CLIENT_FAMILIES:
        if family.replace("-", " ") in name:
            return family
    return "other"


def ua_family(user_agent):
    """Bounded family from the User-Agent header; never raw text."""
    ua = (user_agent or "").lower()
    if not ua:
        return "none"
    for needle, family in UA_FAMILIES:
        if needle in ua:
            return family
    return "other"


def rpc_method(body):
    """Bounded JSON-RPC method name from a request body; never content.

    Auditing the method (tools/call vs tools/list vs prompts/get) makes
    paywall probes attributable without storing the request body.
    """
    if not body:
        return None
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return None
    method = doc.get("method") if isinstance(doc, dict) else None
    if not isinstance(method, str) or not method:
        return None
    return re.sub(r"[^a-zA-Z0-9_/.-]", "", method)[:40]


def rpc_tool(body):
    """Bounded tool name from a tools/call body; never arguments or content.

    Corroborating real tool outcomes (the Glimind OTel feed) needs to know
    which tool ran, not what it was given: only `params.name` is read,
    sanitized and capped. Anything else (args, results) is never touched.
    """
    if not body:
        return None
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(doc, dict) or doc.get("method") != "tools/call":
        return None
    params = doc.get("params")
    name = params.get("name") if isinstance(params, dict) else None
    if not isinstance(name, str) or not name:
        return None
    return re.sub(r"[^a-zA-Z0-9_.-]", "", name)[:60]


class Gateway(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # silence default logging; we keep our own line
        pass

    def handle_one_request(self):
        # Per-request reset: the handler instance survives across requests on
        # a kept-alive connection, and error paths bypass do_*.
        self.keep_alive = False
        super().handle_one_request()

    def end_headers(self):
        # Keep-alive only when the response is self-delimiting (Content-Length
        # or a bodyless HEAD) AND the request body was consumed; the flag is
        # set per response. Everything else forces close, so a reused
        # connection can never be written to as this handler closes it
        # (Caddy sees EOF -> 502 under burst).
        keep = False
        if getattr(self, "keep_alive", False):
            headers = getattr(self, "headers", None)
            conn = ((headers.get("Connection") if headers else "") or "").lower()
            if "close" not in conn:
                keep = not (
                    getattr(self, "request_version", "") == "HTTP/1.0"
                    and "keep-alive" not in conn
                )
        if keep:
            self.close_connection = False
        else:
            self.send_header("Connection", "close")
            self.close_connection = True
        super().end_headers()

    # ── error responses ──────────────────────────────────────────────
    def request_path(self):
        """Bounded path for error audits: query stripped, length capped."""
        return self.path.split("?", 1)[0][:64]

    def send_json(self, status, payload, extra_headers=()):
        body = json.dumps(payload).encode()
        self.send_response(status)
        for name, value in extra_headers:
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.keep_alive = True  # buffered + self-delimiting
        self.end_headers()
        self.wfile.write(body)

    # ── x402 metered lane (testnet-first; mainnet off by default) ─────
    def x402_requirements(self, amount=None):
        srv = self.server
        amt = amount if amount is not None else srv.x402_price
        if srv.x402_version == 1:
            # x402 v1 (PayAI ecosystem): resource fields live inside accepts.
            return {
                "scheme": "exact",
                "network": srv.x402_network,
                "maxAmountRequired": str(amt),
                "resource": srv.x402_resource,
                "description": self.lane_description(),
                "mimeType": "application/json",
                "payTo": srv.x402_pay_to,
                "maxTimeoutSeconds": 60,
                "asset": srv.x402_asset,
                "extra": {"name": srv.x402_asset_name, "version": srv.x402_asset_version},
                # PayAI Bazaar discovery: v1 declarations ride in outputSchema
                # (server-side; the buyer does not need to echo anything).
                # NOTE: PayAI's v1 extractor only accepts HTTP-shaped
                # declarations (type/method); an MCP-shaped one is silently
                # ignored (verified 2026-09-23 via /verify probes). So the
                # Bazaar entry catalogs as an HTTP POST resource; v2/CDP can
                # later carry the proper MCP per-tool declaration.
                "outputSchema": {
                    "input": {
                        "type": "http",
                        "method": "POST",
                        "discoverable": True,
                        "bodyType": "json",
                        "body": {
                            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "wm",
                                       "arguments": {"thought": "recall where we left off"}},
                        },
                    },
                    "output": {"type": "json", "example": {"result": "recall results"}},
                },
            }
        return {
            "scheme": "exact",
            "network": srv.x402_network,
            "amount": str(amt),
            "asset": srv.x402_asset,
            "payTo": srv.x402_pay_to,
            "maxTimeoutSeconds": 60,
            "extra": {"name": srv.x402_asset_name, "version": srv.x402_asset_version},
        }

    def lane_kind(self) -> str:
        path = urllib.parse.urlparse(self.server.x402_resource).path or "/mcp"
        return "verify" if "verify" in path else "recall"

    def lane_description(self) -> str:
        if self.lane_kind() == "verify":
            return ("WhiteMagic continuity-receipt verification: POST a signed receipt "
                    "bundle and receive a verdict (TRUSTED / PROVISIONAL / "
                    "INSUFFICIENT_EVIDENCE / UNTRUSTED) with coded errors and an optional "
                    "signed verification receipt. Verification is stateless, "
                    "offline-verifiable, and fail-closed; keyless /health, /info, "
                    "/revocations and GET /anchors remain free.")
        return ("WhiteMagic hosted recall: read-only hybrid memory search (BM25 + vector + "
                "associative) over a curated public corpus for agent continuity. Call when "
                "an agent needs durable context from prior sessions or the public knowledge "
                "store. Keyless discovery (initialize/tools/list) is free; free evaluation "
                "keys and a daily no-key trial are available. One paid tool call per payment.")

    def x402_bazaar(self):
        """Bazaar discovery declaration (CDP indexes the resource on settlement)."""
        path = urllib.parse.urlparse(self.server.x402_resource).path or "/mcp"
        if self.lane_kind() == "verify":
            info = {
                "input": {
                    "type": "http", "method": "POST", "path": path,
                    "bodyType": "json",
                    "body": {"bundle": {"note": "a continuity-receipt bundle object"}},
                    "description": ("POST a signed continuity-receipt bundle; the response "
                                    "is the verdict with coded errors."),
                },
                "output": {"example": {"verdict": "TRUSTED",
                                       "summary": {"receipts": 6, "terminated": True, "settled": True}}},
            }
        else:
            info = {
                "input": {
                    "type": "http", "method": "POST", "path": path,
                    "bodyType": "json",
                    "body": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": "memory.search",
                                        "arguments": {"query": "recall where we left off"}}},
                    "description": ("Any read-only recall call (memory.search/read/list/"
                                    "hybrid_recall/count/stats, session.list/recall/continuity, "
                                    "gnosis.status); initialize and tools/list are free."),
                },
                "output": {"example": {"jsonrpc": "2.0", "id": 1,
                                       "result": {"content": [{"type": "text", "text": "recall results"}]}}},
            }
        return {
            "info": info,
            "schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {"input": {"type": "object"}, "output": {"type": "object"}},
            },
        }

    def x402_resource_info(self):
        return {
            "url": self.server.x402_resource,
            "description": self.lane_description(),
            "mimeType": "application/json",
        }

    def send_402(self, head_only=False, hint=None):
        if hint is None:
            if self.lane_kind() == "verify":
                hint = ("Free evaluation keys for the verification API are available on "
                        "request (contact@whitemagic.dev); /health, /info, /notarize/* and "
                        "/revocations are keyless. A $0.01 payment activates a 5-minute task lease; "
                        "$0.002 activates a 1-minute call; $0.05 activates a 15-minute swarm lease; "
                        "$0.50 activates a 24-hour day pass. Or POST /faucet for a 10-minute trial pass.")
                # Machine-readable free paths beside the paid one (PRICING_ETHICS).
                free_paths = [
                    {
                        "type": "evaluation_key",
                        "url": "https://api.whitemagic.dev/info",
                        "account_required": False,
                    },
                    {
                        "type": "faucet",
                        "url": "https://api.whitemagic.dev/faucet",
                        "description": "POST /faucet to claim a 10-minute trial session pass (1/day per IP/address).",
                        "account_required": False,
                    },
                ]
            else:
                hint = ("Prefer a free evaluation key (50 recalls/day, no account)? "
                        "https://mcp.whitemagic.dev/keys. A $0.01 payment activates a 5-minute task lease; "
                        "$0.002 activates a 1-minute call; $0.05 activates a 15-minute swarm lease; "
                        "$0.50 activates a 24-hour day pass. Or POST /faucet for a 10-minute trial pass.")
                # Machine-readable free paths beside the paid one (PRICING_ETHICS):
                # agents that parse only structured fields never read the prose hint.
                free_paths = [
                    {
                        "type": "evaluation_key",
                        "url": "https://mcp.whitemagic.dev/keys",
                        "calls_per_day": 50,
                        "account_required": False,
                    },
                    {
                        "type": "faucet",
                        "url": "https://mcp.whitemagic.dev/faucet",
                        "description": "POST /faucet to claim a 10-minute trial session pass (1/day per IP/address).",
                        "account_required": False,
                    },
                ]
            if self.server.trial_per_ip:
                hint += (f" Or send header {TRIAL_HEADER}: 1 for"
                         f" {self.server.trial_per_ip} free calls/day (no key, no account).")
                free_paths.insert(0, {
                    "type": "trial",
                    "header": f"{TRIAL_HEADER}: 1",
                    "calls_per_day": self.server.trial_per_ip,
                    "account_required": False,
                })
            if self.server.oauth_resource_metadata:
                # OAuth 2.1 is a third free path (2026-09-25): MCP clients that
                # speak OAuth discover the authorization server from the pointer
                # in the WWW-Authenticate header below or the resource metadata.
                hint += (" OAuth 2.1 clients: discover the authorization server at"
                         " /.well-known/oauth-protected-resource.")
                free_paths.append({
                    "type": "oauth",
                    "url": self.server.oauth_resource_metadata,
                    "calls_per_day": 50,
                    "account_required": False,
                })
        else:
            free_paths = []
        call_price = 2000
        task_price = self.server.x402_price
        swarm_price = 50000
        day_price = 500000
        accepts = [
            self.x402_requirements(amount=call_price),
            self.x402_requirements(amount=task_price),
            self.x402_requirements(amount=swarm_price),
            self.x402_requirements(amount=day_price),
        ]
        if self.server.x402_version == 1:
            body = {
                "x402Version": 1,
                "error": "X-PAYMENT required for this method",
                "hint": hint,
                "free_paths": free_paths,
                "accepts": accepts,
            }
        else:
            body = {
                "x402Version": 2,
                "error": "PAYMENT-SIGNATURE (or X-PAYMENT) required for this method",
                "hint": hint,
                "free_paths": free_paths,
                "resource": self.x402_resource_info(),
                "accepts": accepts,
                "extensions": {
                    "bazaar": self.x402_bazaar(),
                    "session_lease": {
                        "duration_seconds": getattr(self.server, "session_pass_duration", 300),
                        "price_usdc_atomic": task_price,
                        "price_usd": f"${task_price / 1000000:.2f}",
                        "token_header": "Authorization: Bearer <wm_pass_...>",
                        "alternate_header": "X-Session-Pass: <wm_pass_...>",
                        "rate_limit_rpm": 10000,
                        "tiers": {
                            "call": {
                                "name": "1-Minute Single Call",
                                "duration_seconds": 60,
                                "price_usdc_atomic": call_price,
                                "price_usd": "$0.002",
                            },
                            "task": {
                                "name": "5-Minute Task Lease",
                                "duration_seconds": getattr(self.server, "session_pass_duration", 300),
                                "price_usdc_atomic": task_price,
                                "price_usd": f"${task_price / 1000000:.2f}",
                            },
                            "swarm": {
                                "name": "15-Minute Swarm Lease",
                                "duration_seconds": 900,
                                "price_usdc_atomic": swarm_price,
                                "price_usd": "$0.05",
                            },
                            "day": {
                                "name": "24-Hour Day Pass",
                                "duration_seconds": 86400,
                                "price_usdc_atomic": day_price,
                                "price_usd": "$0.50",
                            },
                        },
                    },
                },
            }
        # x402 v2: the full PaymentRequired object also travels in a base64
        # PAYMENT-REQUIRED header (validators read this, not the body).
        hdr = base64.b64encode(json.dumps(body).encode()).decode()
        # RFC 9728 pointer beside the payment challenge: OAuth-capable clients
        # read WWW-Authenticate, x402 clients read PAYMENT-REQUIRED.
        auth_headers = [("PAYMENT-REQUIRED", hdr)]
        if self.server.oauth_resource_metadata:
            auth_headers.append(("WWW-Authenticate", self.www_authenticate()))
        if head_only:
            # HEAD probe (e.g. PayAI Bazaar catalog worker): headers only,
            # Content-Length of the GET representation.
            self.send_response(402)
            for k, v in auth_headers:
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(json.dumps(body).encode())))
            self.keep_alive = True  # bodyless HEAD is self-delimiting
            self.end_headers()
            return
        self.send_json(402, body, extra_headers=tuple(auth_headers))

    def x402_nonces(self):
        p = self.server.state_dir / "x402_nonces.jsonl"
        if not p.exists():
            return set()
        return {line.strip() for line in p.read_text().splitlines() if line.strip()}

    def mark_x402_nonce(self, nonce):
        with open(self.server.state_dir / "x402_nonces.jsonl", "a") as f:
            f.write(nonce + "\n")

    def facilitator_post(self, path, payload):
        req = urllib.request.Request(
            self.server.x402_facilitator.rstrip("/") + path,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     "User-Agent": "whitemagic-x402/0.2 (+https://mcp.whitemagic.dev)"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return True, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read() or b"{}")
                if not isinstance(body, dict):
                    body = {"error": "invalid_facilitator_response"}
                if e.code >= 500:
                    body["_transport_error"] = True
                return False, body
            except ValueError:
                return False, {"error": f"facilitator HTTP {e.code}",
                               "_transport_error": e.code >= 500}
        except Exception as e:  # noqa: BLE001
            return False, {"error": str(e), "_transport_error": True}

    def verify_x402(self, body):
        # Every failure path audits `x402-payment-invalid` with a bounded
        # reason: without it a buyer whose payment fails is invisible in the
        # logs (the challenge audit only fires when no payment header is sent),
        # and the funnel would show "nobody tried" instead of "payment broke".
        header = self.headers.get("PAYMENT-SIGNATURE") or self.headers.get("X-PAYMENT", "")
        ua = ua_family(self.headers.get("User-Agent"))
        _raw_ua = self.headers.get("User-Agent") or ""
        uah = hashlib.sha256(_raw_ua.encode()).hexdigest()[:12] if _raw_ua else None
        try:
            payment = json.loads(base64.b64decode(header))
        except Exception:  # noqa: BLE001
            self.send_json(402, {"error": "invalid_payment", "hint": "X-PAYMENT must be base64 JSON"})
            self.audit("x402", self.command, 402, 0, "x402-payment-invalid",
                       reason="undecodable", ua=ua, uah=uah, path=self.request_path(),
                       rpc=rpc_method(body))
            return None
        auth = ((payment.get("payload") or {}).get("authorization") or {})
        nonce = str(auth.get("nonce", ""))
        if not nonce or nonce in self.x402_nonces():
            self.send_json(402, {"error": "payment_replayed" if nonce else "invalid_payment"})
            self.audit("x402", self.command, 402, 0, "x402-payment-invalid",
                       reason="replayed" if nonce else "missing-nonce",
                       ua=ua, uah=uah, path=self.request_path(), rpc=rpc_method(body))
            return None

        # Resolve tier: query param, header, or payment payload amount
        query_params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        tier_param = (query_params.get("tier", [""])[0] or self.headers.get("X-Lease-Tier", "")).lower()
        amt_raw = (
            auth.get("value")
            or (payment.get("payload") or {}).get("amount")
            or (payment.get("accepted") or {}).get("amount")
        )
        parsed_amt = None
        if amt_raw is not None:
            try:
                parsed_amt = int(amt_raw)
            except (ValueError, TypeError):
                pass

        if tier_param == "day" or (parsed_amt is not None and parsed_amt >= 500000):
            target_amount = 500000
            target_duration = 86400
            tier_name = "day"
        elif tier_param == "swarm" or (parsed_amt is not None and parsed_amt >= 50000):
            target_amount = 50000
            target_duration = 900
            tier_name = "swarm"
        elif tier_param == "call" or (parsed_amt is not None and 0 < parsed_amt <= 2000):
            target_amount = 2000
            target_duration = 60
            tier_name = "call"
        elif tier_param == "task" or (parsed_amt is not None and parsed_amt >= 10000):
            target_amount = self.server.x402_price
            target_duration = getattr(self.server, "session_pass_duration", 300)
            tier_name = "task"
        else:
            target_amount = self.server.x402_price
            target_duration = getattr(self.server, "session_pass_duration", 300)
            tier_name = "task"

        reqs = self.x402_requirements(amount=target_amount)
        ok, info = self.facilitator_post("/verify", {
            "x402Version": self.server.x402_version, "paymentPayload": payment,
            "paymentRequirements": reqs,
        })
        if not ok or not info.get("isValid"):
            reason = str(info.get("invalidReason") or info.get("errorMessage")
                         or info.get("errorType") or info.get("error") or info)[:120]
            cid = str(info.get("correlationId") or "")
            if cid:
                reason = (reason + " [" + cid[:40] + "]")[:160]
            self.send_json(402, {"error": "payment_invalid", "detail": reason[:300]})
            self.audit("x402", self.command, 402, 0, "x402-payment-invalid",
                       reason=reason, ua=ua, uah=uah, path=self.request_path(),
                       rpc=rpc_method(body))
            return None
        # Verification can be concurrent. Reserve the nonce atomically after
        # facilitator verification and before any upstream work; failed or
        # ambiguous settlement remains consumed to avoid replaying a possibly
        # submitted on-chain authorization.
        with self.server.x402_nonce_lock:
            if nonce in self.x402_nonces():
                self.send_json(402, {"error": "payment_replayed"})
                self.audit("x402", self.command, 402, 0, "x402-payment-invalid",
                           reason="replayed", ua=ua, uah=uah,
                           path=self.request_path(), rpc=rpc_method(body))
                return None
            self.mark_x402_nonce(nonce)
        self._x402 = {
            "payment": payment, "nonce": nonce, "ua": ua, "uah": uah,
            "payer": auth.get("from"),
            "amount": target_amount,
            "duration": target_duration,
            "tier": tier_name,
            "rpc": rpc_method(body), "tool": rpc_tool(body),
        }
        return {"name": "x402", "daily_cap": self.server.x402_daily_cap}

    def emit_payment_receipt(self, tx: str):
        """Best-effort: ask the loopback signer for a content-free receipt.

        A missing signer, bad token, or network error never affects the settle
        or its audit line; the digest is attached only when it was issued.
        """
        url = self.server.payment_receipts_url
        if not url or not tx:
            return None
        token = ""
        if self.server.internal_token_file:
            try:
                token = pathlib.Path(self.server.internal_token_file).read_text().strip()
            except OSError:
                token = ""
        info = self._x402 or {}
        payload = {
            "tx": tx, "network": self.server.x402_network, "asset": self.server.x402_asset,
            "amount": str(info.get("amount") or self.server.x402_price), "payTo": self.server.x402_pay_to,
            "path": self.request_path(), "rpc": info.get("rpc"), "tool": info.get("tool"),
        }
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "X-Internal-Token": token},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                body = json.loads(response.read() or b"{}")
            return body.get("digest")
        except Exception:  # noqa: BLE001 - receipt emission is best-effort
            return None

    def settle_x402(self, key_name):
        info = self._x402
        reqs = self.x402_requirements(amount=info.get("amount", self.server.x402_price))
        ok, resp = self.facilitator_post("/settle", {
            "x402Version": self.server.x402_version, "paymentPayload": info["payment"],
            "paymentRequirements": reqs,
        })
        tx = (resp or {}).get("transaction") or (resp or {}).get("txHash") or ""
        success = bool(ok and (resp or {}).get("success") is True and tx)
        ambiguous = bool((resp or {}).get("_transport_error"))
        reason = None if success else str(
            (resp or {}).get("errorMessage") or (resp or {}).get("errorType")
            or (resp or {}).get("error") or
            ("settlement_status_unknown" if ambiguous else "settlement_failed")
        )[:120]
        if not success:
            outcome = "settlement_status_unknown" if ambiguous else "settlement_failed"
            payment_response = {"success": False, "errorReason": outcome,
                                "transaction": "", "network": self.server.x402_network,
                                "payer": info.get("payer")}
            payment_header = ("PAYMENT-RESPONSE" if self.server.x402_version == 2
                              else "X-PAYMENT-RESPONSE")
            self.send_json(502 if ambiguous else 402,
                           {"error": outcome, "detail": reason},
                           extra_headers=((payment_header,
                               base64.b64encode(json.dumps(payment_response).encode()).decode()),))
            self.audit(key_name, self.command, 502 if ambiguous else 402, 0,
                       "x402-settlement-unknown" if ambiguous else "x402-settle-failed",
                       path=self.request_path(), reason=reason, ua=info.get("ua"),
                       uah=info.get("uah"))
            return None
        receipt_digest = self.emit_payment_receipt(tx)
        self._x402_settlement = {
            "success": True, "transaction": tx, "network": self.server.x402_network,
            "payer": (resp or {}).get("payer") or info.get("payer"),
            "amount": info.get("amount", self.server.x402_price),
            "tier": info.get("tier", "task"),
            "duration": info.get("duration", 300),
            "receipt_digest": receipt_digest,
        }
        self.audit(key_name, self.command, 200, 0, "x402-settled",
                   path=self.request_path(), tx=tx, receipt_digest=receipt_digest,
                   receipt_status="issued" if receipt_digest else "unavailable",
                   tier=info.get("tier", "task"), amount=info.get("amount", self.server.x402_price),
                   ua=info.get("ua"), uah=info.get("uah"))
        return self._x402_settlement

    # ── accounting ────────────────────────────────────────────────────
    def audit(self, key, method, status, req_bytes, note="", **extra):
        line = {
            "ts": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "key": key, "method": method, "status": status,
            "bytes": req_bytes, "note": note,
        }
        line.update({k: v for k, v in extra.items() if v is not None})
        # Unknown-UA correlation (2026-09-24): for UAs outside the bounded
        # families, store a truncated content-free fingerprint so a recurring
        # crawler is correlatable without ever storing the raw UA. `none`
        # (no header) is already its own class, so only `other` fingerprints.
        if line.get("ua") == "other":
            raw = self.headers.get("User-Agent") or ""
            if raw:
                line["uah"] = hashlib.sha256(raw.encode()).hexdigest()[:12]
        with open(self.server.state_dir / "access.jsonl", "a") as f:
            f.write(json.dumps(line) + "\n")

    def issue_session_pass(self, payer="", duration=None):
        """Issue an HMAC-signed session pass for high-throughput calls (task or day)."""
        dur = duration if duration is not None else getattr(self.server, "session_pass_duration", 300)
        expires_ts = int(time.time()) + dur
        nonce = secrets.token_hex(8)
        payer_clean = re.sub(r"[^a-zA-Z0-9_.-]", "", payer or "")[:32] or "agent"
        payload = f"{expires_ts}:{nonce}:{payer_clean}"
        secret = getattr(self.server, "session_pass_secret", b"wm_default_session_pass_secret_key_32b")
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        sig = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
        pass_token = f"wm_pass_{expires_ts}_{nonce}_{payer_clean}_{sig}"
        return pass_token, dur

    def verify_session_pass(self, token):
        """Verify an HMAC-signed session pass. Pure in-memory check (<0.05ms)."""
        if not token or not token.startswith("wm_pass_"):
            return None
        parts = token.split("_", 4)
        # Format: "wm", "pass", "<expires_ts>", "<nonce>", "<payer>_<sig>"
        if len(parts) != 5 or parts[0] != "wm" or parts[1] != "pass":
            return None
        expires_str, nonce, rest = parts[2], parts[3], parts[4]
        if "_" not in rest:
            return None
        payer, sig = rest.rsplit("_", 1)
        if len(sig) != 32:
            return None
        try:
            expires_ts = int(expires_str)
        except ValueError:
            return None
        now = time.time()
        if now > expires_ts:
            return None  # expired
        payload = f"{expires_ts}:{nonce}:{payer}"
        secret = getattr(self.server, "session_pass_secret", b"wm_default_session_pass_secret_key_32b")
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        expected_sig = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, expected_sig):
            return None  # forged or invalid signature
        remaining = max(1, int(expires_ts - now))
        if remaining > 3600:
            tier = "day"
        elif remaining > 600:
            tier = "swarm"
        elif payer.startswith("faucet") or (remaining > 300 and remaining <= 600):
            tier = "faucet"
        elif remaining > 60:
            tier = "task"
        else:
            tier = "call"
        return {
            "name": f"pass:{payer[:16]}",
            "payer": payer,
            "session_pass": True,
            "tier": tier,
            "daily_cap": None,
            "remaining_seconds": remaining,
        }

    def load_keys(self):
        # A missing or unreadable key file means "no keys" (fail closed with
        # a clean 401), never a crashed handler: the file is created on first
        # issuance, so a fresh lane must serve 401s until then.
        try:
            return json.loads((self.server.state_dir / "keys.json").read_text())
        except (OSError, ValueError):
            return {"keys": []}

    def load_oauth_token(self, token):
        """OAuth access tokens issued by oauthd (sha256 at rest, 2026-09-25).

        Secondary key source: the record carries the display name, the daily
        cap, and an expiry. A missing/expired record is a clean miss (401).
        """
        if not self.server.oauth_state or not token.startswith("wm_oa_"):
            return None
        try:
            data = json.loads(
                (pathlib.Path(self.server.oauth_state) / "tokens.json").read_text())
        except (OSError, ValueError):
            return None
        rec = (data.get("access") or {}).get(hashlib.sha256(token.encode()).hexdigest())
        if not rec or rec.get("expires_ts", 0) < time.time():
            return None
        return {"name": rec.get("name", "oauth"),
                "daily_cap": rec.get("daily_cap", 50), "oauth": True}

    def www_authenticate(self):
        """RFC 9728: point OAuth-capable clients at the resource metadata."""
        value = 'Bearer realm="whitemagic-hosted"'
        if self.server.oauth_resource_metadata:
            value += (', resource_metadata="'
                      + self.server.oauth_resource_metadata + '"')
        return value

    def send_401(self, error, client, ua, rpc):
        self.send_json(
            401,
            {
                "error": error,
                "message": ("The evaluation key is not valid."
                            if error == "invalid_key"
                            else "This method needs an evaluation key."),
                "hint": UNAUTH_HINT,
                "docs": FREE_KEY_DOCS,
                "contact": FREE_KEY_CONTACT,
            },
            extra_headers=(("WWW-Authenticate", self.www_authenticate()),),
        )
        self.audit("unknown", self.command, 401, 0, client=client, ua=ua,
                   path=self.request_path(), error=error, rpc=rpc)

    def today_count(self, key):
        today = dt.date.today().isoformat()
        p = self.server.state_dir / "usage.json"
        with USAGE_LOCK:
            try:
                data = json.loads(p.read_text()) if p.exists() else {}
            except ValueError:
                data = {}
        return data.get(f"{key}:{today}", 0)

    def bump(self, key):
        p = self.server.state_dir / "usage.json"
        today = dt.date.today().isoformat()
        with USAGE_LOCK:
            try:
                data = json.loads(p.read_text()) if p.exists() else {}
            except ValueError:
                data = {}
            data[f"{key}:{today}"] = data.get(f"{key}:{today}", 0) + 1
            tmp = p.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data))
            os.replace(tmp, p)

    def rate_limit_headers(self, match):
        """X-RateLimit-* for the caller's bucket (daily caps, 00:00 UTC reset).

        `Remaining` counts the current request against the bucket, so a
        successful response reports what is left after it.
        """
        now = dt.datetime.now(dt.UTC)
        tomorrow = (now + dt.timedelta(days=1)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        reset = max(1, int((tomorrow - now).total_seconds()))
        if match.get("session_pass"):
            return (
                ("X-Session-Active", "1"),
                ("X-Session-Tier", match.get("tier", "task")),
                ("X-Session-Remaining-Seconds", str(match.get("remaining_seconds", 0))),
                ("X-RateLimit-Limit", "10000"),
                ("X-RateLimit-Remaining", "9999"),
                ("X-RateLimit-Reset", str(match.get("remaining_seconds", 0))),
            )
        if match.get("daily_cap") is None:
            # anon-trial: per-IP in-memory bucket, reported under the same
            # header names; the trial header confirms which bucket this is.
            return (
                ("X-RateLimit-Limit", str(self.server.trial_per_ip)),
                ("X-RateLimit-Remaining",
                 str(max(0, getattr(self, "trial_remaining", 0)))),
                ("X-RateLimit-Reset", str(reset)),
                (TRIAL_HEADER, "1"),
            )
        cap = match.get("daily_cap", 50)
        used = self.today_count(match["name"])
        return (
            ("X-RateLimit-Limit", str(cap)),
            ("X-RateLimit-Remaining", str(max(0, cap - used - 1))),
            ("X-RateLimit-Reset", str(reset)),
        )

    # ── request handling ─────────────────────────────────────────────
    def do_GET(self):
        self.keep_alive = False
        self.relay("GET")

    def do_HEAD(self):
        self.keep_alive = False
        # Read-only discovery probes (PayAI Bazaar catalog worker, uptime
        # monitors) send HEAD on the metered route; Python's handler 501s
        # unknown methods, which reads as unreachable. Answer the x402
        # challenge headers-only so a live 402 is the probe's proof.
        if self.server.x402_enabled and not (
            self.headers.get("PAYMENT-SIGNATURE") or self.headers.get("X-PAYMENT")
        ):
            # Consume any body so a kept-alive connection starts the next
            # request at the right offset.
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            self.send_402(head_only=True)
            self.audit("unknown", "HEAD", 402, 0, "x402-challenge",
                       client=client_family(None),
                       ua=ua_family(self.headers.get("User-Agent")),
                       path=self.request_path())
            return
        self.relay("HEAD")

    def do_POST(self):
        self.keep_alive = False
        self.relay("POST")

    def handle_batch_search(self, body, key_info, method, client, ua, t0):
        paid = getattr(self, "_x402", None) is not None
        settlement = None
        if paid:
            settlement = self.settle_x402(key_info["name"])
            if settlement is None:
                return

        try:
            doc = json.loads(body)
        except Exception:
            self.send_json(400, {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}})
            return
        req_id = doc.get("id")
        args = (doc.get("params") or {}).get("arguments") or {}
        raw_queries = args.get("queries")
        if not isinstance(raw_queries, list) or not raw_queries:
            self.send_json(200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: 'queries' must be a non-empty array of strings (max 10)."
                }
            })
            return
        queries = [str(q).strip() for q in raw_queries if str(q).strip()][:10]
        if not queries:
            self.send_json(200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: 'queries' contains no non-empty query strings."
                }
            })
            return
        try:
            limit = min(20, max(1, int(args.get("limit_per_query", 5))))
        except (ValueError, TypeError):
            limit = 5

        def run_subquery(idx, q):
            sub_req_data = json.dumps({
                "jsonrpc": "2.0",
                "id": f"{req_id}_{idx}",
                "method": "tools/call",
                "params": {
                    "name": "memory.search",
                    "arguments": {"query": q, "limit": limit}
                }
            }).encode("utf-8")
            req = urllib.request.Request(
                self.server.upstream + self.path,
                data=sub_req_data,
                method="POST",
                headers={k: v for k, v in self.headers.items()
                         if k.lower() not in ("host", "authorization", "content-length",
                                              TRIAL_HEADER.lower())}
            )
            req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=15) as res:
                    raw = res.read()
                    return json.loads(raw.decode("utf-8"))
            except Exception as err:
                return {"error": str(err)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(queries), 5)) as pool:
            futures = [pool.submit(run_subquery, i, q) for i, q in enumerate(queries)]
            sub_results = [f.result() for f in futures]

        sections = []
        batch_results = []
        for i, (q, res) in enumerate(zip(queries, sub_results)):
            res_obj = res.get("result", {})
            content_list = res_obj.get("content", [])
            text_chunks = []
            for c in content_list:
                if isinstance(c, dict) and c.get("type") == "text":
                    text_chunks.append(c.get("text", ""))
            combined_q_text = "\n".join(text_chunks) if text_chunks else json.dumps(res)
            sections.append(f"### Query {i+1}: {q}\n{combined_q_text}")
            batch_results.append({
                "query": q,
                "status": "error" if "error" in res else "success",
                "result": res_obj or res.get("error")
            })

        response_payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "\n\n".join(sections)
                    }
                ],
                "batch_results": batch_results
            }
        }
        resp_bytes = json.dumps(response_payload).encode("utf-8")
        extra_headers = list(self.rate_limit_headers(key_info))
        if paid:
            tier_name = self._x402.get("tier", "task")
            duration_val = self._x402.get("duration", 300)
            pass_token, duration = self.issue_session_pass(
                payer=settlement.get("payer", ""),
                duration=duration_val
            )
            response_header = {k: v for k, v in settlement.items() if k != "receipt_digest"}
            response_header["session_pass"] = pass_token
            response_header["session_duration"] = duration
            response_header["session_tier"] = tier_name
            payment_header = ("PAYMENT-RESPONSE" if self.server.x402_version == 2 else "X-PAYMENT-RESPONSE")
            extra_headers.append((payment_header, base64.b64encode(json.dumps(response_header).encode()).decode()))
            extra_headers.append(("X-Session-Pass", pass_token))
            extra_headers.append(("X-Session-Tier", tier_name))
            extra_headers.append(("X-Session-Expires-In", str(duration)))
            if settlement.get("receipt_digest"):
                public_base = self.server.payment_receipts_public_base_url.rstrip("/")
                extra_headers.append(("WM-PAYMENT-RECEIPT", public_base + "/receipts/" + settlement["transaction"] if public_base else "unavailable"))
                extra_headers.append(("WM-PAYMENT-RECEIPT-DIGEST", settlement["receipt_digest"]))
            else:
                extra_headers.append(("WM-PAYMENT-RECEIPT", "unavailable"))

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_bytes)))
        for name, value in extra_headers:
            self.send_header(name, value)
        self.keep_alive = True
        self.end_headers()
        self.wfile.write(resp_bytes)

        note = f"batch-search (count={len(queries)})"
        self.audit(key_info["name"], method, 200, len(resp_bytes), note,
                   ms=int((time.monotonic() - t0) * 1000), client=client, ua=ua,
                   rpc=rpc_method(body), tool="memory.search_batch")
        if not key_info.get("session_pass"):
            self.bump(key_info["name"])

    def relay(self, method):
        t0 = time.monotonic()
        # Per-request scope: a keep-alive handler serves many requests, and a
        # stale _x402 would re-settle the previous payment on the next call.
        self._x402 = None
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        ua = ua_family(self.headers.get("User-Agent"))
        client = client_family(body)

        # Dedicated faucet route (free onboarding, anti-Sybil 1/day per IP/address):
        clean_path = self.path.split("?", 1)[0]
        if clean_path in ("/faucet", "/grant/welcome"):
            if method == "GET":
                resp = {
                    "endpoint": clean_path,
                    "method": "POST",
                    "description": "Claim a 10-minute trial session pass for autonomous agents.",
                    "duration_seconds": getattr(self.server, "faucet_duration", 600),
                    "limits": "1 claim per IP or agent address per 24 hours (max 50 global/day).",
                    "usage": "POST to this endpoint with optional JSON {'payer': '0x...' or 'agent_name'}. Returns 'session_pass' token.",
                    "paid_tiers": {
                        "call": "$0.002 / 1 min (60s)",
                        "task": "$0.01 / 5 min (300s)",
                        "swarm": "$0.05 / 15 min (900s)",
                        "day": "$0.50 / 24 hours (86400s)",
                    },
                }
                self.send_json(200, resp)
                return
            if method == "POST":
                payer_id = "agent"
                if body:
                    try:
                        bdoc = json.loads(body)
                        if isinstance(bdoc, dict):
                            payer_id = str(bdoc.get("payer") or bdoc.get("agent") or bdoc.get("address") or "agent").strip()
                    except Exception:
                        pass

                ip = self.client_ip()
                today = dt.date.today().isoformat()
                now_ts = time.time()

                srv = self.server
                lock = getattr(srv, "faucet_lock", None)
                if lock is None:
                    srv.faucet_lock = threading.Lock()
                    srv.faucet_claims = {}
                    srv.faucet_global = {}
                    lock = srv.faucet_lock

                faucet_global_cap = getattr(srv, "faucet_global_cap", 50)

                with lock:
                    if len(srv.faucet_claims) > 2048:
                        srv.faucet_claims = {k: v for k, v in srv.faucet_claims.items() if k[0] == today}
                        srv.faucet_global = {k: v for k, v in srv.faucet_global.items() if k == today}

                    global_claims = srv.faucet_global.get(today, 0)
                    if global_claims >= faucet_global_cap:
                        self.send_json(429, {
                            "error": "faucet_global_cap_reached",
                            "message": f"Daily global faucet cap ({faucet_global_cap}) reached for today. Use x402 payment tiers to acquire leases ($0.002 / $0.01 / $0.05 / $0.50).",
                            "reset_utc": "00:00",
                        })
                        self.audit("faucet", method, 429, 0, "faucet-global-cap-reached", ip=ip, payer=payer_id)
                        return

                    ip_key = (today, f"ip:{ip}")
                    if ip_key in srv.faucet_claims:
                        self.send_json(429, {
                            "error": "faucet_limit_reached",
                            "message": "A faucet trial pass has already been claimed for this IP address today. Use x402 payment tiers to acquire leases ($0.002 / $0.01 / $0.05 / $0.50).",
                            "reset_utc": "00:00",
                        })
                        self.audit("faucet", method, 429, 0, "faucet-ip-limit-reached", ip=ip, payer=payer_id)
                        return

                    if payer_id and payer_id != "agent":
                        payer_key = (today, f"payer:{payer_id.lower()[:42]}")
                        if payer_key in srv.faucet_claims:
                            self.send_json(429, {
                                "error": "faucet_limit_reached",
                                "message": f"A faucet trial pass has already been claimed for address/id '{payer_id}' today.",
                                "reset_utc": "00:00",
                            })
                            self.audit("faucet", method, 429, 0, "faucet-payer-limit-reached", ip=ip, payer=payer_id)
                            return
                        srv.faucet_claims[payer_key] = now_ts

                    srv.faucet_claims[ip_key] = now_ts
                    srv.faucet_global[today] = global_claims + 1

                faucet_dur = getattr(srv, "faucet_duration", 600)
                clean_payer = "faucet" if payer_id == "agent" else f"faucet-{payer_id[:20]}"
                clean_payer = re.sub(r"[^a-zA-Z0-9.-]", "", clean_payer)
                pass_token, duration = self.issue_session_pass(payer=clean_payer, duration=faucet_dur)

                resp = {
                    "status": "granted",
                    "session_pass": pass_token,
                    "tier": "faucet",
                    "expires_in": duration,
                    "rate_limit_rpm": 60,
                    "payer": clean_payer,
                    "message": "Welcome to WhiteMagic! 10-minute trial session pass granted. Include 'Authorization: Bearer <session_pass>' or 'X-Session-Pass: <session_pass>' in subsequent requests. To continue after expiration, use the x402 payment tiers (call: $0.002, task: $0.01, swarm: $0.05, day: $0.50).",
                }
                extra_headers = [
                    ("X-Session-Pass", pass_token),
                    ("X-Session-Tier", "faucet"),
                    ("X-Session-Expires-In", str(duration)),
                    ("X-Session-Active", "1"),
                    ("X-RateLimit-Limit", "60"),
                    ("X-RateLimit-Remaining", "59"),
                    ("X-RateLimit-Reset", str(duration)),
                ]
                self.send_json(200, resp, extra_headers=tuple(extra_headers))
                self.audit("faucet", method, 200, len(json.dumps(resp)), "faucet-granted",
                           ms=int((time.monotonic() - t0) * 1000), client=client, ua=ua,
                           ip=ip, payer=clean_payer, duration=duration)
                return
            self.send_json(405, {"error": "method_not_allowed", "allowed": ["GET", "POST"]})
            return

        key_info = self.authorize(body)
        if key_info is None:
            return

        target_path = urllib.parse.urlsplit(self.path).path
        is_crystal_request = target_path == "/crystals" or target_path.startswith("/crystals/")
        crystal_assertion = None
        if is_crystal_request:
            owner_id = key_info.get("owner_id")
            if not isinstance(owner_id, str) or not CRYSTAL_OWNER_RE.fullmatch(owner_id):
                self.send_json(403, {"error": "crystal_owner_not_mapped"})
                self.audit(key_info.get("name", "unknown"), method, 403, 0,
                           "crystal-owner-unmapped", path=self.request_path())
                return
            try:
                secret = (self.server.state_dir / CRYSTAL_INTERNAL_SECRET_FILE).read_bytes()
                if len(secret) < 32:
                    raise ValueError("internal assertion secret is too short")
                crystal_assertion = _make_crystal_assertion(
                    secret, owner_id, method, self.path, body or b""
                )
            except (OSError, ValueError):
                self.send_json(503, {"error": "crystal_internal_auth_unavailable"})
                return

        # Dedicated session lease route:
        clean_path = self.path.split("?", 1)[0]
        if clean_path in ("/lease", "/session/lease"):
            if key_info.get("session_pass"):
                resp = {
                    "status": "active",
                    "session_pass": self.headers.get("X-Session-Pass") or (self.headers.get("Authorization", "").split()[-1] if self.headers.get("Authorization") else ""),
                    "tier": key_info.get("tier", "task"),
                    "remaining_seconds": key_info.get("remaining_seconds", 0),
                    "rate_limit_rpm": 10000,
                    "payer": key_info.get("payer", ""),
                    "message": "Session lease is currently active.",
                }
                self.send_json(200, resp, extra_headers=self.rate_limit_headers(key_info))
                self.audit(key_info["name"], method, 200, len(json.dumps(resp)), "session-lease-status",
                           ms=int((time.monotonic() - t0) * 1000), client=client, ua=ua, path=self.request_path())
                return
            if getattr(self, "_x402", None) is not None:
                settlement = self.settle_x402(key_info["name"])
                if settlement is None:
                    return
                tier_name = self._x402.get("tier", "task")
                duration_val = self._x402.get("duration", 300)
                pass_token, duration = self.issue_session_pass(
                    payer=settlement.get("payer", ""),
                    duration=duration_val
                )
                resp = {
                    "status": "active",
                    "session_pass": pass_token,
                    "tier": tier_name,
                    "expires_in": duration,
                    "rate_limit_rpm": 10000,
                    "payer": settlement.get("payer", ""),
                    "transaction": settlement.get("transaction", ""),
                    "message": f"Session lease ({tier_name}) active. Include 'Authorization: Bearer <session_pass>' or 'X-Session-Pass: <session_pass>' in subsequent requests.",
                }
                response_header = {k: v for k, v in settlement.items() if k != "receipt_digest"}
                response_header["session_pass"] = pass_token
                response_header["session_duration"] = duration
                response_header["session_tier"] = tier_name
                payment_header = ("PAYMENT-RESPONSE" if self.server.x402_version == 2 else "X-PAYMENT-RESPONSE")
                extra = [
                    (payment_header, base64.b64encode(json.dumps(response_header).encode()).decode()),
                    ("X-Session-Pass", pass_token),
                    ("X-Session-Tier", tier_name),
                    ("X-Session-Expires-In", str(duration)),
                    ("X-Session-Active", "1"),
                    ("X-RateLimit-Limit", "10000"),
                    ("X-RateLimit-Remaining", "9999"),
                    ("X-RateLimit-Reset", str(duration)),
                ]
                if settlement.get("receipt_digest"):
                    public_base = self.server.payment_receipts_public_base_url.rstrip("/")
                    extra.append(("WM-PAYMENT-RECEIPT", public_base + "/receipts/" + settlement["transaction"] if public_base else "unavailable"))
                    extra.append(("WM-PAYMENT-RECEIPT-DIGEST", settlement["receipt_digest"]))
                self.send_json(200, resp, extra_headers=tuple(extra))
                self.audit("x402", method, 200, len(json.dumps(resp)), "session-lease-issued",
                           ms=int((time.monotonic() - t0) * 1000), client=client, ua=ua, path=self.request_path(),
                           tier=tier_name, duration=duration)
                return
            resp = {
                "status": "active",
                "key_name": key_info.get("name"),
                "daily_cap": key_info.get("daily_cap"),
                "message": "Authenticated with API key.",
            }
            self.send_json(200, resp, extra_headers=self.rate_limit_headers(key_info))
            self.audit(key_info["name"], method, 200, len(json.dumps(resp)), "session-lease-key-check",
                       ms=int((time.monotonic() - t0) * 1000), client=client, ua=ua, path=self.request_path())
            return

        # Batch memory search (memory.search_batch):
        if self.is_batch_search(body):
            self.handle_batch_search(body, key_info, method, client, ua, t0)
            return

        # forward to upstream, streaming both ways
        forwarded_headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in ("host", "authorization", TRIAL_HEADER.lower())
            and not (is_crystal_request and k.lower() in (
                "x-wm-crystal-assertion", "x-wm-crystal-owner", "x-wm-principal",
                "x-tenant-hash",
            ))
        }
        if is_crystal_request:
            forwarded_headers[CRYSTAL_ASSERTION_HEADER] = crystal_assertion
        req = urllib.request.Request(
            self.server.upstream + self.path,
            data=body,
            method=method,
            headers=forwarded_headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as up:
                paid = getattr(self, "_x402", None) is not None
                paid_payload = None
                settlement = None
                if paid:
                    # A paid body is never released before the facilitator has
                    # confirmed settlement. Buffer bounded content, including
                    # responses larger than the normal keep-alive threshold.
                    if not 200 <= up.status < 300:
                        self.send_json(502, {"error": "paid_upstream_failed"})
                        self.audit(key_info["name"], method, 502, 0,
                                   "x402-upstream-failed", path=self.request_path(),
                                   upstream_status=up.status)
                        return
                    chunks = []
                    total = 0
                    while True:
                        chunk = up.read(min(65536, PAID_RESPONSE_LIMIT + 1 - total))
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > PAID_RESPONSE_LIMIT:
                            self.send_json(502, {"error": "paid_response_too_large"})
                            self.audit(key_info["name"], method, 502, 0,
                                       "x402-response-too-large", path=self.request_path())
                            return
                        chunks.append(chunk)
                    paid_payload = b"".join(chunks)
                    settlement = self.settle_x402(key_info["name"])
                    if settlement is None:
                        return
                self.send_response(up.status)
                for k, v in up.headers.items():
                    if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                        self.send_header(k, v)
                for name, value in self.rate_limit_headers(key_info):
                    self.send_header(name, value)
                if paid:
                    tier_name = self._x402.get("tier", "task")
                    duration_val = self._x402.get("duration", 300)
                    pass_token, duration = self.issue_session_pass(
                        payer=settlement.get("payer", ""),
                        duration=duration_val
                    )
                    response_header = {k: v for k, v in settlement.items()
                                       if k != "receipt_digest"}
                    response_header["session_pass"] = pass_token
                    response_header["session_duration"] = duration
                    response_header["session_tier"] = tier_name
                    payment_header = ("PAYMENT-RESPONSE" if self.server.x402_version == 2
                                      else "X-PAYMENT-RESPONSE")
                    self.send_header(payment_header, base64.b64encode(
                        json.dumps(response_header).encode()).decode())
                    self.send_header("X-Session-Pass", pass_token)
                    self.send_header("X-Session-Tier", tier_name)
                    self.send_header("X-Session-Expires-In", str(duration))
                    if settlement["receipt_digest"]:
                        public_base = self.server.payment_receipts_public_base_url.rstrip("/")
                        self.send_header("WM-PAYMENT-RECEIPT",
                                         public_base + "/receipts/" + settlement["transaction"]
                                         if public_base else "unavailable")
                        self.send_header("WM-PAYMENT-RECEIPT-DIGEST",
                                         settlement["receipt_digest"])
                    else:
                        self.send_header("WM-PAYMENT-RECEIPT", "unavailable")
                cl = up.headers.get("Content-Length")
                if paid:
                    self.send_header("Content-Length", str(len(paid_payload)))
                    self.keep_alive = True
                    self.end_headers()
                    self.wfile.write(paid_payload)
                    n = len(paid_payload)
                elif (method != "HEAD" and cl is not None and cl.isdigit()
                        and int(cl) <= BUFFER_LIMIT):
                    # Small JSON response (initialize/tools/list, short tool
                    # calls): buffer so we can delimit it and keep the
                    # connection alive for the next request in the session.
                    payload = up.read()
                    if self.is_tools_list(body):
                        try:
                            t_doc = json.loads(payload)
                            if isinstance(t_doc, dict) and "result" in t_doc and isinstance(t_doc["result"].get("tools"), list):
                                tools_list = t_doc["result"]["tools"]
                                if not any(t.get("name") == "memory.search_batch" for t in tools_list):
                                    tools_list.append(BATCH_TOOL_DEF)
                                    payload = json.dumps(t_doc).encode("utf-8")
                        except Exception:
                            pass
                    self.send_header("Content-Length", str(len(payload)))
                    self.keep_alive = True
                    self.end_headers()
                    self.wfile.write(payload)
                    n = len(payload)
                else:
                    # Large or streamed: forward as-is and close-delimit.
                    if cl is not None:
                        self.send_header("Content-Length", cl)
                    if method == "HEAD":
                        self.keep_alive = True  # bodyless, self-delimiting
                    self.end_headers()
                    n = 0
                    while True:
                        chunk = up.read(4096)
                        if not chunk:
                            break
                        n += len(chunk)
                        self.wfile.write(chunk)
                note = "trial" if key_info["name"] == TRIAL_NAME else (
                    "session-pass" if key_info.get("session_pass") else (
                    "oauth" if key_info.get("oauth") else ""))
                self.audit(key_info["name"], method, up.status, n, note,
                           ms=int((time.monotonic() - t0) * 1000),
                           client=client, ua=ua, rpc=rpc_method(body),
                           tool=rpc_tool(body))
                if not key_info.get("session_pass"):
                    self.bump(key_info["name"])
        except urllib.error.HTTPError as e:
            # HTTPError subclasses URLError: it must be caught first.
            err_body = e.read()
            if getattr(self, "_x402", None) is not None:
                # An upstream error body is still protected content. Do not
                # disclose it, and do not settle a call that did not succeed.
                self.send_json(502, {"error": "paid_upstream_failed"})
                self.audit(key_info["name"], method, 502, 0,
                           "x402-upstream-failed", path=self.request_path(),
                           upstream_status=e.code)
                return
            self.send_response(e.code)
            self.send_header("Content-Length", str(len(err_body)))
            for name, value in self.rate_limit_headers(key_info):
                self.send_header(name, value)
            self.keep_alive = True  # buffered + self-delimiting
            self.end_headers()
            self.wfile.write(err_body)
            if e.code == 304:
                note = "not-modified"
            elif e.code == 404:
                note = "not-found"
            elif e.code in (400, 422):
                note = "bad-request"
            elif e.code == 429:
                note = "rate-limited"
            elif e.code in (401, 403):
                note = "upstream-forbidden"
            elif e.code >= 500:
                note = "upstream-error"
            else:
                note = f"upstream-http-{e.code}"
            self.audit(key_info["name"], method, e.code, 0, note,
                       ms=int((time.monotonic() - t0) * 1000),
                       client=client, ua=ua, path=self.request_path(),
                       rpc=rpc_method(body), tool=rpc_tool(body))
        except urllib.error.URLError as e:
            # Upstream unreachable (wm restarting/down): answer a clean 502 and
            # audit it — an unhandled URLError would drop the connection with
            # no audit line, hiding an outage from the funnel and the surface.
            err_body = json.dumps({
                "error": "upstream_unavailable",
                "hint": "The recall backend is restarting; retry shortly.",
            }).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err_body)))
            for name, value in self.rate_limit_headers(key_info):
                self.send_header(name, value)
            self.keep_alive = True  # buffered + self-delimiting
            self.end_headers()
            self.wfile.write(err_body)
            self.audit(key_info["name"], method, 502, 0, "upstream-down",
                       ms=int((time.monotonic() - t0) * 1000),
                       client=client, ua=ua, path=self.request_path(),
                       rpc=rpc_method(body), tool=rpc_tool(body),
                       reason=str(getattr(e, "reason", e))[:80])

    @staticmethod
    def is_discovery(body):
        if not body:
            return False
        try:
            doc = json.loads(body)
        except (ValueError, TypeError):
            return False
        return doc.get("method") in DISCOVERY_METHODS

    @staticmethod
    def is_tools_list(body):
        if not body:
            return False
        try:
            doc = json.loads(body)
        except (ValueError, TypeError):
            return False
        return isinstance(doc, dict) and doc.get("method") == "tools/list"

    @staticmethod
    def is_batch_search(body):
        if not body:
            return False
        try:
            doc = json.loads(body)
        except (ValueError, TypeError):
            return False
        if not isinstance(doc, dict) or doc.get("method") != "tools/call":
            return False
        params = doc.get("params") or {}
        name = str(params.get("name", "")).strip().lower()
        return name in ("memory.search_batch", "memory_search_batch", "search_batch")

    def is_keyless_path(self) -> bool:
        """Keyless REST paths: exact matches, plus prefix entries ending in `*` (safe methods GET/HEAD only)."""
        if self.command not in ("GET", "HEAD"):
            return False
        path = self.path.split("?", 1)[0]
        for entry in self.server.keyless_paths:
            if entry.endswith("*"):
                if path.startswith(entry[:-1]):
                    return True
            elif path == entry:
                return True
        return False

    @staticmethod
    def is_tools_call(body):
        if not body:
            return False
        try:
            doc = json.loads(body)
        except (ValueError, TypeError):
            return False
        return isinstance(doc, dict) and doc.get("method") == "tools/call"

    def client_ip(self):
        """Rightmost X-Forwarded-For entry (Caddy appends the real peer)."""
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[-1].strip()
        return self.client_address[0] if self.client_address else "unknown"

    def maybe_anon_trial(self, body):
        """Explicit opt-in trial call; returns a match or None.

        In-memory counters only (per-IP + global, daily): nothing about the
        client is persisted and the audit line carries no IP. Plain calls
        without the header fall through to the normal 402 challenge.
        """
        srv = self.server
        if not srv.trial_per_ip or self.headers.get(TRIAL_HEADER) != "1":
            return None
        if self.command != "POST" or not self.is_tools_call(body):
            return None
        ip = self.client_ip()
        today = dt.date.today().isoformat()
        with srv.trial_lock:
            used = srv.trial_counts.get((today, ip), 0)
            glob = srv.trial_global.get(today, 0)
            if used >= srv.trial_per_ip:
                return None
            if srv.trial_global_cap and glob >= srv.trial_global_cap:
                return None
            srv.trial_counts[(today, ip)] = used + 1
            srv.trial_global[today] = glob + 1
            if len(srv.trial_counts) > 4096:
                # Drop stale day-buckets under the same lock.
                srv.trial_counts = {k: v for k, v in srv.trial_counts.items()
                                    if k[0] == today}
                srv.trial_global = {k: v for k, v in srv.trial_global.items()
                                    if k == today}
        self.trial_remaining = max(0, srv.trial_per_ip - used - 1)
        return {"name": TRIAL_NAME, "daily_cap": None}

    def authorize(self, body=None):
        ua = ua_family(self.headers.get("User-Agent"))
        client = client_family(body)
        keys = self.load_keys()
        # Token sources: `Authorization: Bearer <token>` (direct clients),
        # a bare Authorization value, or `X-WM-Key` — the header Smithery's
        # gateway forwards when a remote listing declares x-to: X-WM-Key.
        auth = self.headers.get(TOKEN_HEADER, "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        else:
            token = auth.strip()
        if not token:
            token = self.headers.get("X-Session-Pass", "").strip()
        if not token:
            token = self.headers.get("X-WM-Key", "").strip()

        # Session pass authentication (5-minute lease, instant in-memory check):
        if token.startswith("wm_pass_"):
            match = self.verify_session_pass(token)
            if match is not None:
                self.session_pass_info = match
                self.audit(match["name"], self.command, 200, 0, "session-pass-authed",
                           client=client, ua=ua, path=self.request_path(),
                           remaining_s=match["remaining_seconds"], rpc=rpc_method(body))
                return match
            # Expired or forged session pass
            if self.server.x402_enabled:
                self.send_402(hint="Your 5-minute session pass has expired. Please provide payment to acquire a new lease.")
                self.audit("unknown", self.command, 402, 0, "session-pass-expired",
                           client=client, ua=ua, path=self.request_path(), rpc=rpc_method(body))
                return None
            self.send_401("invalid_pass", client, ua, rpc_method(body))
            return None

        digest = hashlib.sha256(token.encode()).hexdigest() if token else ""
        match = next(
            (k for k in keys["keys"]
             if k.get("token") == token
             or (digest and k.get("token_sha256") == digest)),
            None,
        )
        if match is None and token:
            match = self.load_oauth_token(token)
        if match is None and (self.is_discovery(body) or self.is_keyless_path()):
            # Keyless discovery path (metadata only, globally capped). MCP
            # directory probes use JSON-RPC methods; REST lanes declare
            # metadata paths (e.g. /health, /info) with --keyless-paths.
            match = {"name": ANON_NAME, "daily_cap": self.server.anon_daily_cap}
        if match is None:
            match = self.maybe_anon_trial(body)
        if match is None and token:
            # A presented token that resolved to nothing is an auth failure,
            # not a payment challenge: answer 401 (+ resource_metadata) so
            # OAuth clients refresh or re-authorize instead of paying.
            self.send_401("invalid_key", client, ua, rpc_method(body))
            return None
        if match is None and self.server.x402_enabled:
            if self.headers.get("PAYMENT-SIGNATURE") or self.headers.get("X-PAYMENT"):
                match = self.verify_x402(body)
                if match is None:
                    return None  # error response already sent
                self.audit("x402", self.command, 402, 0, "x402-verified",
                           client=client, ua=ua, path=self.request_path(),
                           rpc=rpc_method(body))
            else:
                self.send_402()
                self.audit("unknown", self.command, 402, 0, "x402-challenge",
                           client=client, ua=ua, path=self.request_path(),
                           rpc=rpc_method(body))
                return None
        if match is None:
            self.send_401("missing_key", client, ua, rpc_method(body))
            return None
        if match.get("daily_cap") is not None and \
                self.today_count(match["name"]) >= match["daily_cap"]:
            self.send_json(
                429,
                {
                    "error": "daily_cap_reached",
                    "message": "Daily request cap reached; it resets at 00:00 UTC.",
                    "hint": UNAUTH_HINT,
                    "docs": FREE_KEY_DOCS,
                },
                extra_headers=(("Retry-After", "86400"),) + self.rate_limit_headers(match),
            )
            self.audit(match["name"], self.command, 429, 0, "cap-reached",
                       client=client, ua=ua, path=self.request_path(),
                       rpc=rpc_method(body))
            return None
        return match


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:18790")
    ap.add_argument("--upstream", default="http://127.0.0.1:18789")
    ap.add_argument("--state", required=True)
    ap.add_argument("--keyless-paths", default="",
                    help="comma-separated request paths allowed without a key (anonymous cap)")
    ap.add_argument("--anon-daily-cap", type=int, default=2000,
                    help="global daily cap for keyless discovery requests")
    ap.add_argument("--x402", action="store_true", help="enable the x402 metered lane")
    ap.add_argument("--x402-version", type=int, default=2, choices=(1, 2),
                    help="x402 protocol version spoken to the facilitator")
    ap.add_argument("--x402-facilitator", default="https://x402.org/facilitator")
    ap.add_argument("--x402-pay-to", default="")
    ap.add_argument("--x402-asset", default="")
    ap.add_argument("--x402-asset-name", default="USDC",
                    help='EIP-712 domain name of the asset ("USD Coin" on Base mainnet)')
    ap.add_argument("--x402-asset-version", default="2")
    ap.add_argument("--x402-network", default="base-sepolia")
    ap.add_argument("--x402-price", type=int, default=3000,
                    help="atomic USDC units per call (3000 = $0.003)")
    ap.add_argument("--x402-daily-cap", type=int, default=1000,
                    help="daily call cap across x402 payments")
    ap.add_argument("--x402-resource", default="https://mcp.whitemagic.dev/mcp")
    ap.add_argument("--payment-receipts-url", default="",
                    help="loopback signer that issues content-free payment receipts on settle")
    ap.add_argument("--payment-receipts-public-base-url",
                    default="https://api.whitemagic.dev",
                    help="public base URL for buyer receipt pointers")
    ap.add_argument("--internal-token-file", default="",
                    help="file holding the internal token for the payment-receipts signer")
    ap.add_argument("--anon-trial-per-ip", type=int, default=0,
                    help="free tools/call trials per client IP per day via X-WM-Trial: 1"
                         " (0 = disabled)")
    ap.add_argument("--anon-trial-global", type=int, default=0,
                    help="global daily ceiling across anonymous trial calls (0 = uncapped)")
    ap.add_argument("--oauth-state", default="",
                    help="directory containing oauthd's tokens.json; when set,"
                         " live wm_oa_ access tokens are accepted as keys")
    ap.add_argument("--oauth-resource-metadata", default="",
                    help="URL advertised in WWW-Authenticate resource_metadata (RFC 9728)")
    ap.add_argument("--session-pass-duration", type=int, default=300,
                    help="validity duration in seconds for issued session passes (default 300 = 5m)")
    ap.add_argument("--session-pass-secret-file", default="",
                    help="path to HMAC secret key file for session passes (defaults to <state>/session_pass.key)")
    ap.add_argument("--faucet-duration", type=int, default=600,
                    help="validity duration in seconds for faucet trial passes (default 600 = 10m)")
    ap.add_argument("--faucet-global-cap", type=int, default=50,
                    help="global daily ceiling for faucet trial passes (default 50)")
    args = ap.parse_args()
    host, port = args.listen.rsplit(":", 1)

    state_path = pathlib.Path(args.state)
    state_path.mkdir(parents=True, exist_ok=True)
    if args.session_pass_secret_file:
        secret_path = pathlib.Path(args.session_pass_secret_file)
    elif pathlib.Path("/etc/whitemagic-hosted/session_pass.key").exists():
        secret_path = pathlib.Path("/etc/whitemagic-hosted/session_pass.key")
    else:
        secret_path = state_path / "session_pass.key"
    if secret_path.exists():
        try:
            pass_secret = secret_path.read_bytes().strip()
        except OSError:
            pass_secret = secrets.token_bytes(32)
    else:
        pass_secret = secrets.token_bytes(32)
        try:
            with open(secret_path, "wb") as f:
                f.write(pass_secret)
            os.chmod(secret_path, 0o600)
        except OSError:
            pass

    class S(http.server.ThreadingHTTPServer):
        # Default backlog is 5; bursts of parallel clients (census probes,
        # agent fan-out) overflow it and Caddy turns the refusals into 502s.
        request_queue_size = 128
        state_dir = state_path
        upstream = args.upstream
        anon_daily_cap = args.anon_daily_cap
        keyless_paths = [p for p in args.keyless_paths.split(",") if p]
        x402_enabled = args.x402
        x402_version = args.x402_version
        x402_facilitator = args.x402_facilitator
        x402_pay_to = args.x402_pay_to
        x402_asset = args.x402_asset
        x402_asset_name = args.x402_asset_name
        x402_asset_version = args.x402_asset_version
        x402_network = args.x402_network
        x402_price = args.x402_price
        x402_daily_cap = args.x402_daily_cap
        x402_resource = args.x402_resource
        payment_receipts_url = args.payment_receipts_url
        payment_receipts_public_base_url = args.payment_receipts_public_base_url
        internal_token_file = args.internal_token_file
        trial_per_ip = args.anon_trial_per_ip
        trial_global_cap = args.anon_trial_global
        oauth_state = args.oauth_state
        oauth_resource_metadata = args.oauth_resource_metadata
        session_pass_duration = args.session_pass_duration
        session_pass_secret = pass_secret
        faucet_duration = args.faucet_duration
        faucet_global_cap = args.faucet_global_cap
        x402_nonce_lock = threading.Lock()
        trial_lock = threading.Lock()
        trial_counts = {}   # (utc-date, client-ip) -> count, memory only
        trial_global = {}   # utc-date -> count, memory only
        faucet_lock = threading.Lock()
        faucet_claims = {}  # (utc-date, client-ip-or-payer) -> timestamp
        faucet_global = {}  # utc-date -> count

    pathlib.Path(args.state).mkdir(parents=True, exist_ok=True)
    print(f"authd listening on {args.listen} -> {args.upstream}", flush=True)
    S((host, int(port)), Gateway).serve_forever()


if __name__ == "__main__":
    main()
