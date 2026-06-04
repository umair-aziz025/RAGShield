# RAGShield

**Open-source LLM and RAG security scanner for prompt injection, sensitive data exposure, unsafe agent tools, and retrieval poisoning.**

RAGShield is a defensive AI security lab for builders who are shipping chatbots, RAG systems, and tool-using agents. It gives developers a fast way to paste system prompts, retrieved context, user prompts, tool manifests, and model outputs, then generate prioritized findings mapped to the OWASP Top 10 for LLM Applications.

## Why It Matters

LLM applications are being deployed faster than traditional AppSec review cycles can keep up. Prompt injection, poisoned retrieved documents, secret leakage, unsafe tool permissions, and unescaped model output can turn a helpful AI workflow into a real incident.

RAGShield helps teams catch these issues early, document evidence, and create regression tests before production release.

## Features

- Prompt injection detection for user prompts and retrieved documents
- RAG poisoning heuristics for instruction-like retrieved chunks
- Sensitive data exposure checks for prompts, context, output, and tool manifests
- Unsafe agent tool analysis for excessive agency, wildcard network access, and missing approval
- Unsafe output handling checks for script injection patterns
- OWASP LLM Top 10 mapping
- Built-in adversarial payload library
- Risk score and severity breakdown
- Markdown security report export
- Fully static MVP: no backend, no database, no API keys

## Architecture Overview

```text
Browser UI
  |
  v
Local Scanner Engine
  |
  |-- Prompt Injection Rules
  |-- RAG Poisoning Rules
  |-- Secret Exposure Rules
  |-- Tool Abuse Rules
  |-- Unsafe Output Rules
  |
  v
Risk Scoring + OWASP Mapping
  |
  v
Findings Dashboard + Markdown Report
```

## Application Flow

```text
Paste LLM/RAG artifacts
  |
  |-- System Prompt
  |-- Retrieved Context
  |-- User Prompt
  |-- Tool Manifest
  |-- Model Response
  |
  v
Run Scan
  |
  v
Analyze heuristics and evidence
  |
  v
Prioritize findings by severity
  |
  v
Copy or download security report
```

## Quick Start

Open `index.html` in your browser.

No package installation is required.

## Recommended GitHub Topics

```text
ai-security llm-security rag-security prompt-injection owasp-top-10 cybersecurity appsec red-team blue-team agent-security security-scanner
```

## Roadmap

- JSON report export
- Saved scan sessions
- Custom rule packs
- CI mode for automated prompt/security checks
- OpenAI-compatible endpoint testing
- RAG corpus bulk scanner
- SARIF export for GitHub code scanning
- Dockerized API mode

## Responsible Use

RAGShield is for defensive testing, AppSec review, AI red teaming, and secure development. Do not use it to steal secrets, bypass controls, or attack systems you do not own or have permission to test.

## License

MIT License. See `LICENSE.txt`.
