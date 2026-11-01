"""A Claude Agent SDK chat agent that also accepts tool hooks.

Same shape as ``nlip_examples.nlip_agnostic_agents.ClaudeTestAgent``, plus a ``hooks``
argument so a pre-tool gate can be attached without changing the agent logic.
"""

from __future__ import annotations

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


class ClaudeAgent:
    def __init__(
        self,
        system_prompt: str,
        mcp_servers: dict[str, McpServerConfig],
        allowed_tools: Sequence[str],
        hooks: dict[str, Any] | None = None,
        model: str = "haiku",
    ) -> None:
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
            elif isinstance(message, ResultMessage) and message.is_error:
                detail = message.result or "; ".join(message.errors or []) or message.subtype
                raise RuntimeError(f"Claude request failed: {detail}")
        return "".join(text).strip()
