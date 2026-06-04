# RAGShield Threat Model

## Scope

RAGShield focuses on defensive review of LLM, RAG, and agentic AI application artifacts:

- System prompts
- Developer prompts
- Retrieved context
- User prompts
- Tool manifests
- Model responses

## Primary Risks

| Risk | OWASP Mapping | Description |
| --- | --- | --- |
| Prompt Injection | LLM01 | User or retrieved content attempts to override system/developer instructions. |
| Sensitive Data Exposure | LLM02 | Prompts, context, tools, or outputs expose secrets or confidential data. |
| Supply Chain / Tool Risk | LLM03 | External tools, plugins, or dependencies create unsafe execution paths. |
| Unsafe Output Handling | LLM05 | Model output is rendered or executed without proper validation or escaping. |
| Excessive Agency | LLM06 | Agent tools can perform privileged actions without approval or constraints. |
| System Prompt Leakage | LLM07 | Hidden instructions or internal policy text leaks to users. |
| Vector / Embedding Weakness | LLM08 | Retrieved documents inject hostile instructions or poisoned context. |
| Unbounded Consumption | LLM10 | Large or recursive prompts create cost, availability, or abuse risk. |

## Non-Goals

- RAGShield does not attack third-party services.
- RAGShield does not bypass authentication.
- RAGShield does not guarantee complete coverage.
- RAGShield does not replace manual AI red-team testing.

## Defensive Controls

- Use least-privilege tools.
- Require human approval for destructive actions.
- Keep secrets outside prompts and retrieved content.
- Sanitize model output before rendering.
- Add prompt-injection and RAG-poisoning test suites to CI.
- Log and review suspicious prompts and tool calls.
