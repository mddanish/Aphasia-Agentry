# Quickstart (5 minutes)

**The fixture is INTENTIONALLY VULNERABLE. Run it on localhost only; never expose it.**

1. Start the fixture (HTTP agent on `127.0.0.1:8000`, MCP server on `127.0.0.1:8001`):

       docker compose -f fixture/docker-compose.yml up -d

   If you get a permission error, your shell has not picked up the `docker` group yet:
   run `newgrp docker` or prefix with `sudo`.

2. Fastest path — **seed mode, no LLM needed** (reproducible, runs in seconds):

       cd engine && uv run aphasia run --mode seed

   This drives the attacker from the curated seed-payload library
   instead of an LLM. Against the bundled fixture it proves all OWASP LLM Top 10
   categories deterministically. See the library with `uv run aphasia payloads`.

3. Adaptive / hybrid — add a real LLM attacker that adapts beyond the seeds. The
   backend is [litellm](https://github.com/BerriAI/litellm), so the `--model` string
   picks the provider; keys come from the provider's usual env var:

       cd engine
       aphasia run --model gpt-4o-mini                        # OpenAI (OPENAI_API_KEY)
       aphasia run --model anthropic/claude-3-5-haiku         # Anthropic (ANTHROPIC_API_KEY)
       aphasia run --model groq/llama-3.1-8b-instant          # Groq (GROQ_API_KEY)
       aphasia run --model ollama/llama3.2:1b --api-base http://<host>:11434   # local Ollama

   `--mode hybrid` (default) tries the seeds first, then the LLM adapts; `--mode adaptive`
   is LLM-only. `--api-base` points at a self-hosted backend (Ollama, vLLM, LM Studio).

4. Open `runs/<id>/report.html`. Exit code 1 means at least one attack was proven; 2 means a target/provider error.

Useful flags: `--mode seed|adaptive|hybrid`, `--scenario <id>` (repeatable), `--model`, `--max-steps`, `--out`, `--target <http-url | mcp-url>`.
To test the MCP scenario's server directly: `--target http://127.0.0.1:8001/mcp`.

Stop the fixture with `docker compose -f fixture/docker-compose.yml down`.
