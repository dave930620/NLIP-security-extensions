"""Reader agent: reads documents, summarizes them, and delegates actions to the executor.

The reader can only read documents and talk to the executor over NLIP. It has no
side-effecting tools of its own, so anything it wants done goes through delegation.
"""

from __future__ import annotations

from claude_agent_sdk import create_sdk_mcp_server, tool

from nlip_sdk import NLIPClient, NLIPMessage, NLIPServer, NLIPSession
from nlip_sdk.nlip_security_extensions import SecurityExtensionManager

from ._config import CONFIG
from .claude_agent import ClaudeAgent
from .tools import document_tools

ENTITY_NAME = "reader"

SYSTEM_PROMPT = """\
You are the reader agent in a company workspace assistant.
When the user asks about a document:
1. Read it with read_document.
2. Write a concise summary that keeps every decision, approval and action item.
3. Send the user's request together with the summary to the executor agent with
   send_nlip_message, so the executor can carry out the requested actions.
4. Tell the user what the executor reported back.
Work autonomously: do not ask the user follow-up questions.
"""


class ReaderNLIPAgent(NLIPServer):
    def __init__(self) -> None:
        security = SecurityExtensionManager.from_config(CONFIG, entity=ENTITY_NAME)
        # Few live sessions: each one holds a Claude subprocess.
        super().__init__(ENTITY_NAME, security=security, max_sessions=4)
        self.nlip_client = NLIPClient.from_config(
            CONFIG, exclude={ENTITY_NAME}, identity=ENTITY_NAME, security=security
        )
        self._agents: dict[str, ClaudeAgent] = {}

    async def session_started(self, session: NLIPSession) -> None:
        @tool(
            NLIPClient.TOOL_NAME,
            self.nlip_client.tool_description,
            self.nlip_client.tool_input_schema,
        )
        async def send_nlip_message(arguments: dict) -> dict:
            answer = await self.nlip_client.send_nlip_message(
                str(arguments["destination"]).casefold(),
                str(arguments["message"]),
                scope=session.id,
            )
            return {"content": [{"type": "text", "text": answer}]}

        agent = ClaudeAgent(
            system_prompt=SYSTEM_PROMPT,
            mcp_servers={
                "docs": document_tools(),
                "nlip": create_sdk_mcp_server("nlip", tools=[send_nlip_message]),
            },
            allowed_tools=["mcp__docs__read_document", "mcp__nlip__send_nlip_message"],
        )
        await agent.__aenter__()
        self._agents[session.id] = agent

    async def session_ended(self, session: NLIPSession) -> None:
        agent = self._agents.pop(session.id, None)
        self.nlip_client.clear_scope(session.id)
        if agent is not None:
            await agent.__aexit__(None, None, None)

    async def handle(self, message: NLIPMessage, session: NLIPSession) -> NLIPMessage:
        text = message.extract_text(language=None)
        if text is None:
            return NLIPMessage.text("The reader accepts NLIP text requests.")
        return NLIPMessage.text(await self._agents[session.id].chat(text))


nlip_agent = ReaderNLIPAgent()
app = nlip_agent.create_nlip_app()


def main() -> None:
    import uvicorn

    settings = CONFIG["entities"][ENTITY_NAME]
    uvicorn.run(app, host=settings["host"], port=settings["port"])


if __name__ == "__main__":
    main()
