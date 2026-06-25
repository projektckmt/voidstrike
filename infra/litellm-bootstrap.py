#!/usr/bin/env python3
"""LiteLLM proxy entrypoint: OpenRouter key-fallback, mirroring the app's
`_openrouter_fallback` (src/agent/models.py).

The static config (`/app/config.yaml`) pins each model to its native provider key
(`api_key: os.environ/ANTHROPIC_API_KEY`, etc.). At startup we check which native
keys are actually present: for any model whose native key is missing while
`OPENROUTER_API_KEY` is set, we rewrite that model's `litellm_params` to route via
OpenRouter (same equivalent slug the app uses). Then we exec the real proxy on the
transformed config. Self-gating: a present native key is left untouched, so the
proxy keeps using it.

This runs inside the `litellm` container (see docker-compose `litellm` service).
"""

from __future__ import annotations

import os
import sys

import yaml

# litellm `model_name` → OpenRouter slug. Mirrors `_OPENROUTER_EQUIVALENT` in
# src/agent/models.py (verified against the OpenRouter catalogue 2026-06; slugs
# use `.` not `-`). Keep the two in sync. A model absent here simply isn't
# remapped (it keeps its native key — which 401s if that key is missing).
OPENROUTER_SLUG = {
    "anthropic/claude-opus-4-8": "anthropic/claude-opus-4.8",
    "anthropic/claude-sonnet-4-6": "anthropic/claude-sonnet-4.6",
    "anthropic/claude-haiku-4-5": "anthropic/claude-haiku-4.5",
    "openai/gpt-5.5": "openai/gpt-5.5",
    "openai/gpt-5.4-mini": "openai/gpt-5.4-mini",
    "openai/gpt-5.4-nano": "openai/gpt-5.4-nano",
    "google/gemini-3-pro": "google/gemini-3.1-pro-preview",
    "google/gemini-flash": "google/gemini-2.5-flash",
}

SRC = os.environ.get("LITELLM_CONFIG_SRC", "/app/config.yaml")
DST = os.environ.get("LITELLM_CONFIG_RUNTIME", "/tmp/litellm.runtime.yaml")
PORT = os.environ.get("LITELLM_PORT", "4000")


def _native_key_var(api_key_field: object) -> str | None:
    """Extract VAR from an `os.environ/VAR` api_key field, else None."""
    if isinstance(api_key_field, str) and api_key_field.startswith("os.environ/"):
        return api_key_field.split("/", 1)[1]
    return None


def _has_key(var: str) -> bool:
    """True if env var holds a real-looking key — set, non-empty, and not a
    `.env.example` placeholder (those end in `...`). Mirrors `_has_key` in
    src/agent/models.py so a placeholder native key engages the fallback."""
    val = os.environ.get(var, "").strip()
    return bool(val) and not val.endswith("...")


def transform(cfg: dict) -> list[str]:
    """Rewrite missing-native-key models to OpenRouter in place; return a log of
    what was remapped."""
    or_present = _has_key("OPENROUTER_API_KEY")
    remapped: list[str] = []
    for entry in cfg.get("model_list", []):
        name = entry.get("model_name")
        params = entry.get("litellm_params", {})
        key_var = _native_key_var(params.get("api_key"))
        # Skip: models with no native key (ollama/api_base), the OpenRouter-native
        # entries themselves, models whose native key IS set, or when we have no
        # OpenRouter key to fall back to.
        if not key_var or key_var == "OPENROUTER_API_KEY":
            continue
        if _has_key(key_var) or not or_present:
            continue
        slug = OPENROUTER_SLUG.get(name)
        if not slug:
            print(f"[litellm-bootstrap] WARN {name}: {key_var} missing and no "
                  f"OpenRouter slug mapped — leaving as-is (will 401)", file=sys.stderr)
            continue
        entry["litellm_params"] = {
            "model": f"openrouter/{slug}",
            "api_key": "os.environ/OPENROUTER_API_KEY",
        }
        remapped.append(f"{name} -> openrouter/{slug} ({key_var} unset)")
    return remapped


def main() -> None:
    with open(SRC) as f:
        cfg = yaml.safe_load(f)
    remapped = transform(cfg)
    with open(DST, "w") as f:
        yaml.safe_dump(cfg, f)
    if remapped:
        print("[litellm-bootstrap] OpenRouter key-fallback active:", file=sys.stderr)
        for r in remapped:
            print(f"   {r}", file=sys.stderr)
    else:
        print("[litellm-bootstrap] all native keys present (or no OPENROUTER_API_KEY) "
              "— no remap", file=sys.stderr)
    os.execvp("litellm", ["litellm", "--config", DST, "--port", PORT])


if __name__ == "__main__":
    main()
