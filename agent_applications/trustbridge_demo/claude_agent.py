"""A Claude Agent SDK chat agent that also accepts tool hooks.

Same shape as ``nlip_examples.nlip_agnostic_agents.ClaudeTestAgent``, plus a ``hooks``
argument so a pre-tool gate can be attached without changing the agent logic.
"""

from __future__ import annotations

import json
from shutil import which
from typing import Any, Sequence

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
)
from claude_agent_sdk.types import McpServerConfig

from ._config import RUNTIME_DIR

# One line per model turn: token usage and the API-price cost the SDK reports.
USAGE_LOG = RUNTIME_DIR / "usage_log.jsonl"


class ClaudeAgent:
    def __init__(
        self,
        name: str,
        system_prompt: str,
        mcp_servers: dict[str, McpServerConfig],
        allowed_tools: Sequence[str],
        hooks: dict[str, Any] | None = None,
        model: str = "haiku",
    ) -> None:
        self.name = name
        cli_path = which("claude")
        if cli_path is None:
            raise RuntimeError("Claude Code is not installed or is not on PATH.")
        self._client = ClaudeSDKClient(
            ClaudeAgentOptions(
                cli_path=cli_path,
                system_prompt=system_prompt,
                model=model,
                # Only the explicitly provided MCP tools are available.
                tools=[],
                mcp_servers=mcp_servers,
                allowed_tools=list(allowed_tools),
                hooks=hooks or {},
                # Isolate the agent from the developer's own Claude Code setup:
                # no account connectors, no user/project settings or memory files,
                # and no saved transcripts. Experiments must not depend on them.
                strict_mcp_config=True,
                setting_sources=[],
                extra_args={"no-session-persistence": None},
            )
        )

    async def __aenter__(self) -> "ClaudeAgent":
        await self._client.connect()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self._client.disconnect()

    async def chat(self, prompt: str) -> str:
        await self._client.query(prompt)
        text: list[str] = []
        async for message in self._client.receive_response():
            if isinstance(message, AssistantMessage):
                text.extend(
                    block.text for block in message.content if isinstance(block, TextBlock)
                )
            elif isinstance(message, ResultMessage):
                self._log_usage(message)
                if message.is_error:
                    detail = message.result or "; ".join(message.errors or []) or message.subtype
                    raise RuntimeError(f"Claude request failed: {detail}")
        return "".join(text).strip()

    def _log_usage(self, result: ResultMessage) -> None:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        record = {
            "agent": self.name,
            "cost_usd": result.total_cost_usd,
            "turns": result.num_turns,
            "duration_ms": result.duration_ms,
            "usage": result.usage,
        }
        with USAGE_LOG.open("a", encoding="utf-8") as log:
            log.write(json.dumps(record, default=str) + "\n")


def read_usage_log() -> list[dict[str, Any]]:
    if not USAGE_LOG.exists():
        return []
    return [json.loads(line) for line in USAGE_LOG.read_text().splitlines() if line]
