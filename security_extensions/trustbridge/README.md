# TrustBridge

Prevents **security-context laundering**: untrusted content that gains authority it
never had after a trusted agent forwards it. TrustBridge keeps two records apart and
makes both survive agent-to-agent (NLIP) and agent-to-tool boundaries:

- **Authority** — a signed *grant* of what the user allowed, issued before any model
  reads untrusted content (`authorizer.py`). On every delegation it is narrowed to the
  destination's tools (child ⊆ parent), and each agent accepts a grant in only one
  conversation, so it cannot be widened or replayed.
- **Provenance** — whether a session has read untrusted content. Recorded by trusted
  code after untrusted tools run, and carried to delegates in a signed token.

A tool call runs only if the tool is in the grant **and** its control arguments
(e.g. email recipients) were either pinned by the user or chosen before the session
saw untrusted content.

## Pieces

| File | Runs at | Role |
|---|---|---|
| `authorizer.py` | user login | Task template + user-given values → signed grant |
| `extension.py` | NLIP ingress/egress | Verify grant chain (block if missing, invalid, widened or replayed), attach a narrowed grant + provenance when delegating, absorb provenance from peers |
| `gate.py` | before/after each tool call | `check()` decides; `claude_hooks()` wires it into Claude Agent SDK `PreToolUse`/`PostToolUse` |
| `runtime.py` | in-process | Per-session grant + taint; links an outbound NLIP conversation to the inbound session it serves |
| `tokens.py` | — | HMAC-signed `trustbridge_grant` / `trustbridge_provenance` tokens; a delegated grant embeds its parent and must narrow it |

## Enabling it

1. In the app's `config.toml`, define the extension and enable it at both points of every
   agent (see `agent_applications/trustbridge_demo/config_trustbridge.toml`):

   ```toml
   [security_extensions.trustbridge]
   entrypoint = "security_extensions.trustbridge:TrustBridgeExtension"

   [entities.executor.security]
   ingress = ["trustbridge"]
   egress = ["trustbridge"]
   ```

2. In the agent, two integration lines the NLIP framework cannot do by itself:
   - attach the gate to the agent framework: `hooks=claude_hooks(session.id)`;
   - before delegating over NLIP: `link_outbound(outbound_session.id, session.id)`.

3. The user client attaches a grant from `issue_grant(user, task, params)` as a
   `trustbridge_grant` token.

## Options (`[security_extensions.trustbridge.options]`)

| Option | Default | Meaning |
|---|---|---|
| `secret` | demo key | HMAC key shared by trusted runtimes. **Change it outside experiments.** |
| `use_provenance` | `true` | `false` = authority-only ablation |
| `verify_signature` | `true` | `false` = accept unsigned/forged tokens (ablation) |
| `check_expiry` | `true` | `false` = accept expired grants (ablation) |
| `require_grant` | `true` | Block NLIP requests without a valid grant |
| `single_use_grants` | `true` | Block a grant reused by a second conversation at the same agent (replay) |
| `capabilities` | none | `{agent = [tools]}`; narrows delegated grants to the destination's tools. Unset = pass the grant through unchanged |
| `untrusted_tools` | `["read_document"]` | Tools whose results taint the session |
| `control_args` | `{send_email = ["to", "cc"]}` | Arguments that decide where an action goes |
| `decision_log` | none | JSONL file of every gate decision |

## Adding a rule

- New task: add a template to `TASKS` in `authorizer.py` (`allow` + `pinned` arguments).
- New sensitive tool: add its routing arguments to `control_args`.
- New untrusted source: add the tool name to `untrusted_tools`.

## Limits

- Taint is per session and sticky: after reading one untrusted document, every unpinned
  control argument is refused (over-tainting). The cost shows up as false blocks.
- Harmful actions fully inside a valid grant, and attacks that need no tool call
  (e.g. a misleading summary), are out of scope.
- Trusted components (authorizer, key, gate, agent integration) are assumed intact; a
  sensitive tool not routed through the gate is not protected.
- All runtimes share one HMAC key, so a compromised agent could mint grants. Per-issuer
  keys (e.g. public-key signatures per agent) would close this.
- Replay protection is per process and in memory; it resets when an agent restarts.
