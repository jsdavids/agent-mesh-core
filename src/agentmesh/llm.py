"""Optional Claude calls for agents that want a model's judgment.

Every project in this repo runs deterministically without an API key; an
agent opts in with `ClaudeJSON.from_env()`, which returns None unless
AGENTMESH_LLM=1 and the `anthropic` package is installed. Credentials are
resolved by the SDK (ANTHROPIC_API_KEY, or an `ant auth login` profile).
"""

from __future__ import annotations

import json
import os
from typing import Any

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class LLMRefusal(Exception):
    pass


class ClaudeJSON:
    """Structured-output completions: the response is guaranteed to match
    the JSON schema you pass."""

    def __init__(self, model: str = DEFAULT_MODEL, effort: str = "medium"):
        import anthropic

        self.client = anthropic.AsyncAnthropic()
        self.model = model
        self.effort = effort

    @classmethod
    def from_env(cls) -> ClaudeJSON | None:
        if os.environ.get("AGENTMESH_LLM") != "1":
            return None
        try:
            return cls(model=os.environ.get("AGENTMESH_LLM_MODEL", DEFAULT_MODEL),
                       effort=os.environ.get("AGENTMESH_LLM_EFFORT", "medium"))
        except ImportError:
            return None

    async def complete(self, *, system: str, prompt: str, schema: dict[str, Any],
                       max_tokens: int = 16000) -> dict[str, Any]:
        # `fallbacks: "default"` re-runs a safety-classifier decline on the
        # recommended fallback model inside the same call.
        response = await self.client.beta.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": schema}},
            betas=[FALLBACK_BETA],
            fallbacks="default",
        )
        if response.stop_reason == "refusal":
            raise LLMRefusal(getattr(response.stop_details, "explanation", None) or "request declined")
        if response.stop_reason == "max_tokens":
            raise ValueError("response hit max_tokens before the JSON was complete")
        text = next(b.text for b in response.content if b.type == "text")
        return json.loads(text)
