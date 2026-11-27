"""Proxy mode recorder: a LiteLLM proxy callback that logs every LLM exchange as JSON lines.

The agent under test points its LLM base URL at the Aphasia proxy. Each request/response pair
is written to $APHASIA_PROXY_LOG as:
  - one `llm_exchange` line (context in, reply out, tool definitions, flags)
  - one `llm_tool_call` line per tool call the model asked the agent to run
Lines use flat fields so Wazuh rules can match them (source = "aphasia-proxy").
Tool-description drift is tracked per (session, tool). run_id, scenario and step are strings.

Run context (run_id, scenario, step, honey tokens) is read from the JSON file at
$APHASIA_RUN_CONTEXT, written by `aphasia run` before each step. Missing file = no context.
Provider API keys and request headers other than x-aphasia-* are never logged.
"""
import hashlib
import json
import os
import re
import time
from pathlib import Path

from litellm.integrations.custom_logger import CustomLogger

MAX_TEXT = 2000
INJECTION = re.compile(
    r"ignore (all |any )?(previous|prior|above)|<important>|disregard (the )?(system|previous)"
    r"|you are now|new instructions|do not (tell|inform) the user", re.I)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _text(content) -> str:
    """Message content as plain text (string or list of content parts)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return "" if content is None else str(content)


def _clip(text: str, full: bool) -> str:
    return text if full or len(text) <= MAX_TEXT else text[:MAX_TEXT] + "…"


class Recorder(CustomLogger):
    def __init__(self, log_path: str | None = None, context_path: str | None = None):
        super().__init__()
        self.log_path = Path(log_path or os.environ.get("APHASIA_PROXY_LOG", "proxy.jsonl"))
        self.context_path = context_path or os.environ.get("APHASIA_RUN_CONTEXT")
        self.full = os.environ.get("APHASIA_PROXY_FULL", "") == "1"
        self.first_desc: dict[tuple[str, str], str] = {}  # (session, tool) -> first description hash

    # ---------- helpers ----------
    def _context(self) -> dict:
        if not self.context_path:
            return {}
        try:
            return json.loads(Path(self.context_path).read_text())
        except (OSError, ValueError):
            return {}

    @staticmethod
    def _session(kwargs: dict) -> str:
        psr = (kwargs.get("litellm_params") or {}).get("proxy_server_request") or {}
        headers = {k.lower(): v for k, v in (psr.get("headers") or {}).items()}
        return str(headers.get("x-aphasia-session") or kwargs.get("user")
                   or kwargs.get("litellm_trace_id") or "default")

    def _write(self, rec: dict) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a") as f:
            f.write(json.dumps(rec, default=str) + "\n")

    # ---------- record ----------
    def build(self, kwargs: dict, response_obj, latency_ms: int) -> list[dict]:
        ctx = self._context()
        honey = [t for t in ctx.get("honey", []) if t]
        has_honey = lambda s: any(t in s for t in honey)  # noqa: E731

        msgs = kwargs.get("messages") or []
        tools = (kwargs.get("optional_params") or {}).get("tools") or []
        tool_results = [_text(m.get("content")) for m in msgs if m.get("role") == "tool"]
        system = " ".join(_text(m.get("content")) for m in msgs if m.get("role") == "system")
        context_text = " ".join(_text(m.get("content")) for m in msgs)

        session = self._session(kwargs)
        defs, changed = [], []
        for t in tools:
            fn = t.get("function", t)
            name, desc = str(fn.get("name", "")), str(fn.get("description", ""))
            h = _hash(desc)
            self.first_desc.setdefault((session, name), h)
            if self.first_desc[(session, name)] != h:
                changed.append(name)
            defs.append({"name": name, "desc_hash": h})

        choice = None
        if getattr(response_obj, "choices", None):
            choice = response_obj.choices[0].message
        reply = _text(getattr(choice, "content", None))
        calls = []
        for c in getattr(choice, "tool_calls", None) or []:
            raw = c.function.arguments or "{}"
            try:
                args = json.loads(raw)
            except ValueError:
                args = {"_raw": raw}
            calls.append({"name": c.function.name, "args": args, "raw": raw})

        base = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "aphasia-proxy", "component": "gateway",
            "session": session,
            **{k: str(ctx[k]) for k in ("run_id", "scenario", "step") if k in ctx},  # strings, as Wazuh returns them
        }
        exchange = {
            **base, "event": "llm_exchange",
            "model": kwargs.get("model"), "stream": bool(kwargs.get("stream")), "latency_ms": latency_ms,
            "roles": ",".join(str(m.get("role")) for m in msgs),
            "system_hash": _hash(system) if system else "",
            "tool_names": ",".join(d["name"] for d in defs),
            "tool_call_names": ",".join(c["name"] for c in calls),
            "desc_changed": bool(changed), "changed_tools": ",".join(changed),
            "injection_in_tool_result": any(INJECTION.search(r) for r in tool_results),
            "honey_in_context": has_honey(context_text),
            "honey_in_reply": has_honey(reply),
            # detail for the TUI trace view (Wazuh ignores nested arrays)
            "messages": [{"role": m.get("role"), "content": _clip(_text(m.get("content")), self.full)} for m in msgs],
            "tools": defs,
            "tool_calls": [{"name": c["name"], "args": c["args"]} for c in calls],
            "reply": _clip(reply, self.full),
        }
        out = [exchange]
        for c in calls:
            out.append({**base, "event": "llm_tool_call", "tool": c["name"], "args": c["args"],
                        "honey": has_honey(c["raw"])})
        return out

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        latency = int((end_time - start_time).total_seconds() * 1000)
        for rec in self.build(kwargs, response_obj, latency):
            self._write(rec)

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        self._write({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source": "aphasia-proxy",
                     "component": "gateway", "event": "llm_error", "session": self._session(kwargs),
                     "model": kwargs.get("model"), "error": str(kwargs.get("exception", ""))[:500]})


recorder = Recorder()
