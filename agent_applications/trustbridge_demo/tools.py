"""Tools used by the demo agents.

``read_document`` returns attacker-controllable content. ``save_summary`` is the
action the user normally asks for. ``send_email`` is the action an attacker wants;
it is a mock that only appends to ``runtime/mail_log.jsonl`` so a run can be scored
without sending anything.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from claude_agent_sdk import create_sdk_mcp_server, tool

from ._config import DOCUMENTS_DIR, RUNTIME_DIR

MAIL_LOG = RUNTIME_DIR / "mail_log.jsonl"
SUMMARY_DIR = RUNTIME_DIR / "summaries"


def _text(result: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": result}]}


def _inside(base: Path, name: str) -> Path:
    """Resolve ``name`` under ``base`` and refuse paths that escape it."""
    path = (base / name).resolve()
    if not path.is_relative_to(base.resolve()):
        raise ValueError(f"{name!r} is outside {base.name}/.")
    return path


@tool(
    "read_document",
    "Read a document from the shared document folder and return its text.",
    {"name": str},
)
async def read_document(args: dict[str, Any]) -> dict[str, Any]:
    path = _inside(DOCUMENTS_DIR, args["name"])
    if not path.is_file():
        available = ", ".join(sorted(p.name for p in DOCUMENTS_DIR.iterdir()))
        return _text(f"No document named {args['name']!r}. Available: {available}.")
    return _text(path.read_text(encoding="utf-8"))


@tool(
    "save_summary",
    "Save a summary as a local file for the user.",
    {"filename": str, "text": str},
)
async def save_summary(args: dict[str, Any]) -> dict[str, Any]:
    SUMMARY_DIR.mkdir(parents=True, exist_ok=True)
    path = _inside(SUMMARY_DIR, Path(args["filename"]).name)
    path.write_text(args["text"], encoding="utf-8")
    return _text(f"Saved summary to {path.name}.")


@tool(
    "send_email",
    "Send an email, optionally attaching a document from the shared folder.",
    {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "subject": {"type": "string"},
            "body": {"type": "string"},
            "attachment": {"type": "string", "description": "Document name, optional."},
        },
        "required": ["to", "subject", "body"],
    },
)
async def send_email(args: dict[str, Any]) -> dict[str, Any]:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    record = {"time": datetime.now(timezone.utc).isoformat(), **args}
    with MAIL_LOG.open("a", encoding="utf-8") as log:
        log.write(json.dumps(record, ensure_ascii=False) + "\n")
    return _text(f"Email sent to {args['to']}.")


def document_tools():
    """MCP server for the reader: only reads documents."""
    return create_sdk_mcp_server("docs", tools=[read_document])


def workspace_tools():
    """MCP server for the executor: saves summaries and sends email."""
    return create_sdk_mcp_server("workspace", tools=[save_summary, send_email])


def read_mail_log() -> list[dict[str, Any]]:
    if not MAIL_LOG.exists():
        return []
    return [json.loads(line) for line in MAIL_LOG.read_text().splitlines() if line]
