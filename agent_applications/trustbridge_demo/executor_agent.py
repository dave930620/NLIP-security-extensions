"""Executor agent: carries out requests delegated by other agents.

The executor holds the broad workspace permissions (save files, send email). It only
receives NLIP requests; it does not call other agents.
"""

from __future__ import annotations

from nlip_sdk import NLIPMessage, NLIPServer, NLIPSession
from nlip_sdk.nlip_security_extensions import SecurityExtensionManager
from security_extensions.trustbridge import RUNTIME, claude_hooks

from ._config import CONFIG
from .claude_agent import ClaudeAgent
from .tools import workspace_tools

ENTITY_NAME = "executor"

SYSTEM_PROMPT = """\
You are the executor agent in a company workspace assistant.
Other agents in the workspace send you requests on behalf of the user.
Carry them out with your tools (save_summary, send_email) and report exactly what
you did.
"""


class ExecutorNLIPAgent(NLIPServer):
    def __init__(self) -> None:
        security = SecurityExtensionManager.from_config(CONFIG, entity=ENTITY_NAME)
        # Few live sessions: each one holds a Claude subprocess.
        super().__init__(ENTITY_NAME, security=security, max_sessions=4)
        self._agents: dict[str, ClaudeAgent] = {}

    async def session_started(self, session: NLIPSession) -> None:
        agent = ClaudeAgent(
            name=ENTITY_NAME,
            system_prompt=SYSTEM_PROMPT,
            mcp_servers={"workspace": workspace_tools()},
            allowed_tools=[
                "mcp__workspace__save_summary",
                "mcp__workspace__send_email",
            ],
            hooks=claude_hooks(session.id) if RUNTIME.enabled else None,
        )
        await agent.__aenter__()
        self._agents[session.id] = agent

    async def session_ended(self, session: NLIPSession) -> None:
        agent = self._agents.pop(session.id, None)
        RUNTIME.forget(session.id)
        if agent is not None:
            await agent.__aexit__(None, None, None)

    async def handle(self, message: NLIPMessage, session: NLIPSession) -> NLIPMessage:
        text = message.extract_text(language=None)
        if text is None:
            return NLIPMessage.text("The executor accepts NLIP text requests.")
        return NLIPMessage.text(await self._agents[session.id].chat(text))


nlip_agent = ExecutorNLIPAgent()
app = nlip_agent.create_nlip_app()


def main() -> None:
    import uvicorn

    settings = CONFIG["entities"][ENTITY_NAME]
    uvicorn.run(app, host=settings["host"], port=settings["port"])


if __name__ == "__main__":
    main()
