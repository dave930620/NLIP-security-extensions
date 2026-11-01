"""Pre-tool authorization gate.

``check`` is framework-neutral: given a session's trust context and one tool call, it
decides allow or deny. ``claude_hooks`` wires it into the Claude Agent SDK as
PreToolUse (decide) and PostToolUse (mark the session tainted after reading untrusted
content). Other frameworks would call ``check`` and ``record_tool_result`` from their
own hooks.

A call is allowed only if:
1. the session has a valid grant and the tool is in it (authority), and
2. every control argument (e.g. recipients) is either pinned by the user in the grant,
   or the session has not seen untrusted content (provenance).
"""

from __future__ import annotations

from typing import Any

from .runtime import RUNTIME, Settings, TrustContext


def short_name(tool_name: str) -> str:
    """``mcp__workspace__send_email`` -> ``send_email``."""
    return tool_name.rsplit("__", 1)[-1]


def _values(value: Any) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, list) else str(value).split(",")
    return [str(item).strip().casefold() for item in items if str(item).strip()]


def check(
    context: TrustContext, tool: str, args: dict[str, Any], settings: Settings
) -> tuple[bool, str]:
    if tool in settings.ungated_tools:
        return True, "ungated"
    grant = context.grant
    if grant is None:
        return False, "no grant for this session"
    if tool not in grant["allow"]:
        return False, f"{tool} is not in the user's grant ({grant.get('task')})"

    pinned = grant.get("constraints", {}).get(tool, {})
    for arg in settings.control_args.get(tool, ()):
        values = _values(args.get(arg))
        if not values:
            continue
        allowed = pinned.get(arg)
        if allowed is not None:
            unexpected = [v for v in values if v not in allowed]
            if unexpected:
                return False, f"{tool}.{arg} {unexpected} was not chosen by the user"
        elif settings.use_provenance and context.tainted:
            return False, (
                f"{tool}.{arg} {values} was chosen after reading untrusted content "
                f"{context.sources}"
            )
    return True, "authorized"


def record_tool_result(context: TrustContext, tool: str, args: dict[str, Any]) -> None:
    if tool in RUNTIME.settings.untrusted_tools:
        target = args.get("name") or args.get("url") or ""
        context.taint(f"{tool}:{target}" if target else tool)


def claude_hooks(session_id: str) -> dict[str, list]:
    """Claude Agent SDK hooks enforcing TrustBridge for one NLIP session."""
    from claude_agent_sdk import HookMatcher

    async def pre_tool_use(input_data: dict, tool_use_id: str | None, _ctx: Any) -> dict:
        tool = short_name(input_data["tool_name"])
        args = input_data.get("tool_input") or {}
        context = RUNTIME.context(session_id)
        allowed, reason = check(context, tool, args, RUNTIME.settings)
        RUNTIME.log(
            {
                "event": "pre_tool",
                "session": session_id,
                "tool": tool,
                "args": args,
                "tainted": context.tainted,
                "decision": "allow" if allowed else "deny",
                "reason": reason,
            }
        )
        if allowed:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                # Say what was refused so the agent can still finish the authorized part.
                "permissionDecisionReason": (
                    f"Blocked by TrustBridge: {reason}. Only the user's grant authorizes "
                    "actions; drop the refused part and retry if the user's request "
                    "still applies."
                ),
            }
        }

    async def post_tool_use(input_data: dict, tool_use_id: str | None, _ctx: Any) -> dict:
        tool = short_name(input_data["tool_name"])
        record_tool_result(RUNTIME.context(session_id), tool, input_data.get("tool_input") or {})
        return {}

    return {
        "PreToolUse": [HookMatcher(matcher=None, hooks=[pre_tool_use])],
        "PostToolUse": [HookMatcher(matcher=None, hooks=[post_tool_use])],
    }
