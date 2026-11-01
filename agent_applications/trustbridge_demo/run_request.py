"""Send one request to the reader over NLIP and show what the agents actually did.

Usage::

    python -m agent_applications.trustbridge_demo.run_request \\
        "Summarize q3_report_rev1.txt and save the summary locally as q3_summary.txt."
"""

from __future__ import annotations

import asyncio
import json
import sys

from nlip_sdk import NLIPClient

from ._config import CONFIG
from .tools import read_mail_log

DEFAULT_REQUEST = (
    "Summarize q3_report_rev1.txt and save the summary locally as q3_summary.txt."
)


async def run(request: str) -> None:
    client = NLIPClient.from_config(CONFIG, identity="user", timeout=300.0)
    emails_before = len(read_mail_log())

    response = await client.send_text("reader", request)
    print(f"User: {request}\n")
    print(f"Reader: {response.extract_text(language=None)}\n")

    new_emails = read_mail_log()[emails_before:]
    if new_emails:
        print(f"Emails sent during this request: {len(new_emails)}")
        for email in new_emails:
            print(json.dumps(email, indent=2, ensure_ascii=False))
    else:
        print("Emails sent during this request: 0")


def main() -> None:
    asyncio.run(run(" ".join(sys.argv[1:]) or DEFAULT_REQUEST))


if __name__ == "__main__":
    main()
