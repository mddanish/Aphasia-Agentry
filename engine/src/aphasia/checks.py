"""Connection checks used by the setup wizard. Each returns (ok, message). Never logs secrets."""
import httpx


def target(kind: str, url: str) -> tuple[bool, str]:
    probe = "http://127.0.0.1:8000/" if kind == "fixture" else url
    if not probe:
        return False, "no URL"
    try:
        r = httpx.get(probe, timeout=5)
        return r.status_code < 500, f"HTTP {r.status_code} from {probe}"
    except httpx.HTTPError as e:
        return False, f"cannot reach {probe}: {type(e).__name__}"


def llm(model: str, api_base: str, api_key: str) -> tuple[bool, str]:
    """One tiny completion with explicit base and key (no ambient env fallback for the key)."""
    if not model:
        return False, "no model"
    from aphasia.config import needs_key
    if needs_key(model, api_base) and not api_key:
        return False, "no role API key set (shared provider variables are not used)"
    try:
        import litellm
        kw = {"model": model, "messages": [{"role": "user", "content": "Reply with: ok"}],
              "max_tokens": 5, "timeout": 30}
        if api_base:
            kw["api_base"] = api_base
        if api_key:
            kw["api_key"] = api_key
        litellm.completion(**kw)
        return True, f"{model} answered"
    except Exception as e:  # litellm raises many provider-specific types
        return False, f"{model}: {type(e).__name__}: {str(e)[:120]}"


def wazuh(url: str, user: str, password: str, ca_cert: str, insecure: bool) -> tuple[bool, str]:
    if not url:
        return False, "no indexer URL"
    verify = False if insecure else (ca_cert or True)
    try:
        r = httpx.get(url.rstrip("/") + "/_cluster/health", auth=(user, password), verify=verify, timeout=8)
        if r.status_code == 200:
            return True, f"indexer {r.json().get('status', '?')}"
        return False, f"HTTP {r.status_code}"
    except httpx.HTTPError as e:
        return False, f"cannot reach {url}: {type(e).__name__}"
