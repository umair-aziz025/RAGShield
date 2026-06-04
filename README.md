# 🛡️ RAGShield

**Open-source LLM and RAG red-team console for corpus scanning, live endpoint attack testing, CI/CD prompt security gates, and OWASP LLM risk reporting.**

RAGShield is a professional AI security console for developers, AppSec teams, and AI red-teamers shipping chatbots, RAG systems, and tool-using agents. Upload RAG documents, scan full corpora, attack-test live OpenAI/Claude/Gemini-compatible endpoints, and export build-breaking CI policies mapped to the OWASP Top 10 for LLM Applications.

## 🚨 Why It Matters

LLM applications are moving into production faster than traditional security reviews can keep up. Prompt injection, poisoned retrieved documents, secret leakage, unsafe tool permissions, and unescaped model output can turn a helpful AI workflow into a real incident.

RAGShield helps teams catch those risks early, document evidence, and build regression tests before production release.

## ✨ Features

- React + TypeScript security dashboard built with Vite
- Framer Motion interactions for polished scan, finding, and report states
- Multi-file RAG corpus upload and full-document risk scoring
- Live endpoint attack campaigns for OpenAI Responses, Claude Messages, Gemini generateContent, and custom proxies
- Session-only API key handling with no persistence
- CI/CD scanner command to fail builds on dangerous prompt, tool, or document patterns
- Prompt injection detection for user prompts and retrieved documents
- RAG poisoning heuristics for instruction-like retrieved chunks
- Sensitive data exposure checks across prompts, context, output, and tool manifests
- Unsafe agent tool analysis for excessive agency, wildcard network access, and missing approval
- Unsafe output checks for script injection and unsafe browser rendering patterns
- OWASP LLM Top 10 mapping for each finding
- Built-in adversarial payload library for regression testing
- Risk score, severity breakdown, evidence view, and Markdown report export

## 🏗️ Architecture Overview

```text
React + TypeScript UI
  |
  |-- Corpus Scanner
  |     |-- Markdown / Text / JSON / CSV / HTML
  |     `-- Per-document risk scoring
  |
  |-- Artifact Workspace
  |     |-- System Prompt
  |     |-- Retrieved Context
  |     |-- User Prompt
  |     |-- Tool Manifest
  |     `-- Model Response
  |
  |-- Endpoint Attack Lab
  |     |-- OpenAI Responses API
  |     |-- Claude Messages API
  |     |-- Gemini generateContent API
  |     `-- Custom proxy target
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
  |-- Live response classification
  `-- OWASP LLM Top 10 mapping
  |
  v
Security Console
  |
  |-- Animated Risk Posture
  |-- Prioritized Findings
  |-- Corpus Risk Dashboard
  |-- Live Attack Results
  |-- CI/CD Policy Export
  |-- Payload Library
  `-- Markdown Report Export
```

## 🔁 Application Flow

```text
Upload corpus or paste LLM/RAG artifacts
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
  |-- Optional: run live endpoint attack campaign
  |-- Optional: export CI/CD build gate
  |
  v
Collect evidence and tune severity
  |
  v
Map findings to OWASP LLM Top 10
  |
  v
Review risk posture, payloads, fixes, and CI policy
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

Run the CI security gate locally:

```bash
npm run ci:scan
```

Optional `.ragshieldrc.json`:

```json
{
  "failOnCritical": true,
  "maxRiskScore": 35,
  "allowDemoSecrets": false,
  "scanPaths": ["src/**/*.{ts,tsx,md,json}", "docs/**/*.md", "README.md"]
}
```

## 🧪 Recommended GitHub Topics

```text
ai-security llm-security rag-security prompt-injection owasp-top-10 cybersecurity appsec red-team blue-team agent-security security-scanner react typescript
```

## 🗺️ Roadmap

- SARIF report export
- Saved scan sessions
- Custom rule packs
- Provider-specific score tuning
- Browser extension for live LLM app review
- Optional API mode for enterprise pipelines

## 🤝 Responsible Use

RAGShield is built for defensive testing, AppSec review, AI red teaming, and secure development. Do not use it to steal secrets, bypass controls, or attack systems you do not own or have permission to test.

## 📄 License

MIT License. See `LICENSE.txt`.
