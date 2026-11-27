"""Instance configuration: what `aphasia setup` (TUI first run) writes and every command reads.

Two LLMs, never mixed:
  attacker  — Aphasia's own LLM. Plans attack steps in adaptive/hybrid mode. Talks to its provider
              directly, never through the Aphasia proxy.
  upstream  — proxy mode only. The real provider behind the Aphasia proxy, serving the AGENT UNDER TEST.
              Aphasia never uses it for attack planning.

Files (directory = $APHASIA_HOME or ~/.config/aphasia):
  config.toml   settings, no secrets
  secrets.env   API keys and passwords, mode 0600, KEY=value lines

Precedence per value: CLI flag > environment variable > config file > default.
Secrets: environment variable > secrets.env. Secrets are never written to config.toml or logs.
"""
import os
import stat
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

# Secret names (env vars and secrets.env keys). Role-prefixed on purpose: generic names such as
# OPENAI_API_KEY would be shared by the attacker, the upstream and the agent under test.
ATTACKER_KEY = "APHASIA_ATTACKER_API_KEY"
UPSTREAM_KEY = "APHASIA_UPSTREAM_API_KEY"
PROXY_KEY = "APHASIA_PROXY_KEY"            # key the agent under test presents to the Aphasia proxy
WAZUH_PASSWORD = "APHASIA_WAZUH_PASSWORD"
SECRET_NAMES = (ATTACKER_KEY, UPSTREAM_KEY, PROXY_KEY, WAZUH_PASSWORD)

# Generic base-URL variables that LiteLLM / SDKs read implicitly. If one of them points at the
# Aphasia proxy, attacker traffic would be recorded as agent traffic.
GENERIC_BASE_VARS = ("OPENAI_BASE_URL", "OPENAI_API_BASE", "ANTHROPIC_BASE_URL", "ANTHROPIC_API_BASE")

# Hostnames that all mean "this machine" when comparing a URL with the proxy listen address.
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "::"}
# Model prefixes for self-hosted backends that need no API key.
KEYLESS_PREFIXES = ("ollama/", "ollama_chat/", "hosted_vllm/", "lm_studio/", "llamafile/")


def _host_port(url_or_listen: str) -> tuple[str, int | None]:
    u = urlparse(url_or_listen if "://" in url_or_listen else "http://" + url_or_listen)
    try:
        port = u.port or {"http": 80, "https": 443}.get(u.scheme)
    except ValueError:
        port = None
    return (u.hostname or "").lower(), port


def same_endpoint(url: str, listen: str) -> bool:
    """True if url points at the proxy listening on `listen` (host:port), treating local aliases as equal."""
    if not url:
        return False
    h1, p1 = _host_port(url)
    h2, p2 = _host_port(listen)
    if p1 != p2:
        return False
    return h1 == h2 or (h1 in LOCAL_HOSTS and h2 in LOCAL_HOSTS)


def needs_key(model: str, api_base: str) -> bool:
    """Hosted providers need a key; self-hosted ones (known prefix or custom api_base) may not."""
    return bool(model) and not api_base and not model.startswith(KEYLESS_PREFIXES)


@dataclass
class TargetCfg:
    kind: str = "fixture"            # fixture | http | mcp
    url: str = ""                    # http(s) chat URL or MCP endpoint; empty for fixture


@dataclass
class LLMCfg:
    model: str = ""                  # litellm model string, e.g. ollama_chat/qwen2.5:7b-instruct
    api_base: str = ""               # only for self-hosted / local providers
    enabled: bool = False


@dataclass
class ProxyCfg:
    enabled: bool = False
    listen: str = "127.0.0.1:4000"
    alias: str = "agent-model"       # model name the agent under test asks for
    dir: str = "runs/proxy"
    full_text: bool = False

    @property
    def url(self) -> str:
        return f"http://{self.listen}"


@dataclass
class WazuhCfg:
    enabled: bool = False
    indexer_url: str = ""
    user: str = "admin"
    ca_cert: str = ""
    insecure: bool = False


@dataclass
class Config:
    mode: str = "direct"             # direct | proxy (default for `aphasia run` and the TUI)
    target: TargetCfg = field(default_factory=TargetCfg)
    attacker: LLMCfg = field(default_factory=LLMCfg)
    upstream: LLMCfg = field(default_factory=LLMCfg)
    proxy: ProxyCfg = field(default_factory=ProxyCfg)
    wazuh: WazuhCfg = field(default_factory=WazuhCfg)
    secrets: dict[str, str] = field(default_factory=dict, repr=False)

    def secret(self, name: str) -> str:
        return os.environ.get(name) or self.secrets.get(name, "")

    def secret_source(self, name: str) -> str:
        if os.environ.get(name):
            return "env"
        return "file" if self.secrets.get(name) else ""


def home() -> Path:
    return Path(os.environ.get("APHASIA_HOME") or Path.home() / ".config" / "aphasia")


def is_first_run(base: Path | None = None) -> bool:
    return not ((base or home()) / "config.toml").exists()


def _read_secrets(path: Path) -> dict[str, str]:
    out = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                if k.strip() in SECRET_NAMES:
                    out[k.strip()] = v.strip()
    return out


def load(base: Path | None = None) -> Config:
    base = base or home()
    cfg = Config()
    f = base / "config.toml"
    if f.exists():
        raw = tomllib.loads(f.read_text())
        cfg.mode = raw.get("mode", cfg.mode)
        for name, cls in (("target", TargetCfg), ("attacker", LLMCfg), ("upstream", LLMCfg),
                          ("proxy", ProxyCfg), ("wazuh", WazuhCfg)):
            known = set(cls.__dataclass_fields__)
            setattr(cfg, name, cls(**{k: v for k, v in raw.get(name, {}).items() if k in known}))
    cfg.secrets = _read_secrets(base / "secrets.env")
    # environment overrides for non-secret values
    env = os.environ
    cfg.attacker.model = env.get("APHASIA_ATTACKER_MODEL", cfg.attacker.model)
    cfg.attacker.api_base = env.get("APHASIA_ATTACKER_API_BASE", cfg.attacker.api_base)
    cfg.upstream.model = env.get("APHASIA_UPSTREAM_MODEL", cfg.upstream.model)
    cfg.upstream.api_base = env.get("APHASIA_UPSTREAM_API_BASE", cfg.upstream.api_base)
    cfg.wazuh.indexer_url = env.get("APHASIA_WAZUH_URL", cfg.wazuh.indexer_url)
    return cfg


def _toml_value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def save(cfg: Config, base: Path | None = None) -> Path:
    """Write config.toml (no secrets) and secrets.env (0600, only non-empty values)."""
    base = base or home()
    base.mkdir(parents=True, exist_ok=True)
    lines = ["# Aphasia Agentry instance config. Secrets live in secrets.env (0600), never here.",
             f"mode = {_toml_value(cfg.mode)}", ""]
    for name in ("target", "attacker", "upstream", "proxy", "wazuh"):
        comment = {"attacker": "# Aphasia's own LLM: plans attacks (adaptive/hybrid). Never routed via the proxy.",
                   "upstream": "# Proxy mode only: real provider behind the proxy, serving the agent under test."}
        if name in comment:
            lines.append(comment[name])
        lines.append(f"[{name}]")
        lines += [f"{k} = {_toml_value(v)}" for k, v in asdict(getattr(cfg, name)).items()]
        lines.append("")
    (base / "config.toml").write_text("\n".join(lines))
    sec = base / "secrets.env"
    body = "".join(f"{k}={v}\n" for k, v in cfg.secrets.items() if k in SECRET_NAMES and v)
    fd = os.open(sec, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(body)
    os.chmod(sec, stat.S_IRUSR | stat.S_IWUSR)
    return base


def problems(cfg: Config) -> list[str]:
    """Configuration errors that must block a run. Empty list = OK."""
    out = []
    if cfg.target.kind in ("http", "mcp") and not cfg.target.url:
        out.append("target: url is required for http/mcp targets")
    if cfg.mode == "proxy" and not cfg.proxy.enabled:
        out.append("mode: proxy mode needs the proxy enabled (step 4)")
    if cfg.attacker.enabled:
        if not cfg.attacker.model:
            out.append("attacker: model is required when the attacker LLM is enabled")
        elif needs_key(cfg.attacker.model, cfg.attacker.api_base) and not cfg.secret(ATTACKER_KEY):
            out.append(f"attacker: {ATTACKER_KEY} is not set; Aphasia will not fall back to shared "
                       "provider variables (OPENAI_API_KEY, ...)")
    if cfg.proxy.enabled:
        listen = cfg.proxy.listen
        if not cfg.upstream.model:
            out.append("upstream: model is required in proxy mode")
        elif needs_key(cfg.upstream.model, cfg.upstream.api_base) and not cfg.secret(UPSTREAM_KEY):
            out.append(f"upstream: {UPSTREAM_KEY} is not set; the proxy will not fall back to shared "
                       "provider variables")
        if same_endpoint(cfg.attacker.api_base, listen):
            out.append("attacker: api_base points at the Aphasia proxy; the attacker LLM must not "
                       "go through the proxy (it would be recorded as agent traffic)")
        for var in GENERIC_BASE_VARS:
            if same_endpoint(os.environ.get(var, ""), listen):
                out.append(f"environment: {var} points at the Aphasia proxy in Aphasia's own "
                           "environment; set it only inside the agent under test")
        if same_endpoint(cfg.upstream.api_base, listen):
            out.append("upstream: api_base points at the Aphasia proxy itself (loop)")
    return out


def warnings(cfg: Config) -> list[str]:
    """Allowed but worth showing: same key reused, missing optional pieces."""
    out = []
    a, u = cfg.secret(ATTACKER_KEY), cfg.secret(UPSTREAM_KEY)
    if cfg.attacker.enabled and cfg.proxy.enabled and a and a == u:
        out.append("attacker and upstream use the same API key: provider usage and bills will mix")
    if cfg.attacker.enabled and cfg.proxy.enabled and cfg.attacker.model == cfg.upstream.model:
        out.append("attacker and upstream use the same model: allowed, but the attacker may share "
                   "the agent's blind spots")
    if cfg.wazuh.enabled and not cfg.secret(WAZUH_PASSWORD):
        out.append(f"wazuh: no password set ({WAZUH_PASSWORD})")
    if cfg.wazuh.insecure:
        out.append("wazuh: TLS verification disabled (lab only)")
    return out


def redacted(cfg: Config) -> dict:
    """Config as a dict for display: secrets shown only as set / not set."""
    d = asdict(cfg)
    d["secrets"] = {k: (f"set ({cfg.secret_source(k)})" if cfg.secret(k) else "not set") for k in SECRET_NAMES}
    return d
