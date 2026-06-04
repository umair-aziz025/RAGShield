# 🛡️ RAGShield

**Open-source LLM and RAG security scanner for prompt injection, sensitive data exposure, unsafe agent tools, and retrieval poisoning.**

RAGShield is a professional AI security console for developers, AppSec teams, and AI red-teamers shipping chatbots, RAG systems, and tool-using agents. Paste your prompts, retrieved context, tool manifest, and model output, then generate prioritized findings mapped to the OWASP Top 10 for LLM Applications.

## 🚨 Why It Matters

LLM applications are moving into production faster than traditional security reviews can keep up. Prompt injection, poisoned retrieved documents, secret leakage, unsafe tool permissions, and unescaped model output can turn a helpful AI workflow into a real incident.

RAGShield helps teams catch those risks early, document evidence, and build regression tests before production release.

## ✨ Features

- React + TypeScript security dashboard built with Vite
- Framer Motion interactions for polished scan, finding, and report states
- Prompt injection detection for user prompts and retrieved documents
- RAG poisoning heuristics for instruction-like retrieved chunks
- Sensitive data exposure checks across prompts, context, output, and tool manifests
- Unsafe agent tool analysis for excessive agency, wildcard network access, and missing approval
- Unsafe output checks for script injection and unsafe browser rendering patterns
- OWASP LLM Top 10 mapping for each finding
- Built-in adversarial payload library for regression testing
- Risk score, severity breakdown, evidence view, and Markdown report export
- Local-first scanning: no backend, no database, no API key required

## 🏗️ Architecture Overview

```text
React + TypeScript UI
  |
  |-- Artifact Workspace
  |     |-- System Prompt
  |     |-- Retrieved Context
  |     |-- User Prompt
  |     |-- Tool Manifest
  |     `-- Model Response
  |
  v
Client-Side Scanner Engine
  |
  |-- Prompt Injection Rules
  |-- RAG Poisoning Rules
  |-- Secret Exposure Rules
  |-- Agent Tool Abuse Rules
  |-- Unsafe Output Rules
  `-- Prompt Budget Rules
  |
  v
Evidence Collector + Severity Tuner
  |
  |-- Profile-aware scoring
  |-- Duplicate evidence cleanup
  `-- OWASP LLM Top 10 mapping
  |
  v
Security Console
  |
  |-- Animated Risk Posture
  |-- Prioritized Findings
  |-- Payload Library
  `-- Markdown Report Export
```

## 🔁 Application Flow

```text
Paste LLM/RAG artifacts
  |
  v
Choose scanner profile
  |
  |-- RAG Application
  |-- Agentic AI
  `-- Chatbot
  |
  v
Run local heuristic scan
  |
  v
Collect evidence and tune severity
  |
  v
Map findings to OWASP LLM Top 10
  |
  v
Review risk posture, payloads, and fixes
  |
  v
Copy or download the security report
```

## ⚡ Quick Start

```bash
npm install
npm run dev
```

Build for production:

```bash
npm run build
```

## 🧪 Recommended GitHub Topics

```text
ai-security llm-security rag-security prompt-injection owasp-top-10 cybersecurity appsec red-team blue-team agent-security security-scanner react typescript
```

## 🗺️ Roadmap

- JSON and SARIF report export
- Saved scan sessions
- Custom rule packs
- CI mode for automated prompt/security checks
- OpenAI-compatible endpoint testing
- RAG corpus bulk scanner
- Browser extension for live LLM app review
- Optional API mode for enterprise pipelines

## 🤝 Responsible Use

RAGShield is built for defensive testing, AppSec review, AI red teaming, and secure development. Do not use it to steal secrets, bypass controls, or attack systems you do not own or have permission to test.

## 📄 License

MIT License. See `LICENSE.txt`.
