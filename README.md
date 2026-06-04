# 🛡️ RAGShield

<p align="center">
  <img alt="Build" src="https://img.shields.io/badge/build-passing-34d399?style=for-the-badge" />
  <img alt="React" src="https://img.shields.io/badge/React-19-61dafb?style=for-the-badge&logo=react&logoColor=111827" />
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-6-3178c6?style=for-the-badge&logo=typescript&logoColor=white" />
  <img alt="Vite" src="https://img.shields.io/badge/Vite-8-646cff?style=for-the-badge&logo=vite&logoColor=white" />
  <img alt="Framer Motion" src="https://img.shields.io/badge/Framer_Motion-12-f472b6?style=for-the-badge" />
  <img alt="OWASP LLM" src="https://img.shields.io/badge/OWASP_LLM-Top_10-f59e0b?style=for-the-badge" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge" />
</p>

**Open-source LLM and RAG red-team console for corpus scanning, live endpoint attack testing, CI/CD prompt security gates, and OWASP LLM risk reporting.**

RAGShield helps developers, AppSec teams, and AI red-teamers test chatbots, RAG systems, and tool-using agents before production release. Upload documents, scan prompt artifacts, run numbered adversarial prompt campaigns against live model endpoints, and export evidence-ready reports.

## 📸 Screenshots

### 🧭 Security Console
![RAGShield dashboard](docs/screenshots/dashboard.png)

### 🧪 Payload Library
![RAGShield payload library](docs/screenshots/payload-library.png)

## 🚨 Why It Matters

- 🧨 Prompt injection can override assistant behavior and expose hidden instructions.
- 🧬 Poisoned retrieved documents can silently alter RAG responses.
- 🔑 Secrets can leak through prompts, context, logs, tool results, or model output.
- 🛠️ Overpowered tools can turn a helpful agent into an unsafe automation surface.
- 📦 CI/CD gates help teams catch regressions before risky prompts ship.

## ✨ Features

- 🧪 **Expanded Prompt Library**: 22 adversarial prompts mapped to OWASP LLM risks.
- 📤 **Custom Payload Uploads**: Add your own JSON payload packs directly inside the Payload Library.
- 📑 **Paged Payload Lists**: Browse prompts through numbered pages instead of one long messy list.
- 🧭 **Tabbed Workspace**: Each navigation tab renders only its relevant tool surface.
- 🔁 **Prompt Carousel**: Previous, next, shuffle, and direct prompt-number controls.
- 🔢 **Range Campaigns**: Choose a start prompt and run count to test a numbered prompt range.
- ⚡ **Live Endpoint Testing**: OpenAI Responses, Claude Messages, Gemini generateContent, and custom proxy support.
- 🧠 **Local Heuristic Scanner**: Prompt injection, RAG poisoning, secret exposure, unsafe tools, unsafe output, and prompt-budget checks.
- 📂 **Corpus Scanner**: Multi-file RAG document upload with per-document risk scoring.
- 🛡️ **OWASP Mapping**: Findings mapped to OWASP Top 10 for LLM Applications.
- 📊 **Risk Dashboard**: Severity breakdown, animated score ring, evidence cards, and remediation steps.
- 🚦 **CI/CD Gate Export**: Download `.ragshieldrc.json` and a GitHub Actions workflow.
- 📝 **Markdown Reports**: Copy or download evidence-ready security reports.
- 🎛️ **Professional UI**: Dark glass console, animated background, transparent header/footer, and responsive layouts.

## 🏗️ Architecture Overview

```mermaid
flowchart TD
  A[React + TypeScript UI] --> B[Artifact Workspace]
  A --> C[RAG Corpus Scanner]
  A --> D[Live Endpoint Attack Lab]
  A --> E[CI/CD Policy Builder]

  B --> B1[System Prompt]
  B --> B2[Retrieved Context]
  B --> B3[User Prompt]
  B --> B4[Tool Manifest]
  B --> B5[Model Response]

  C --> F[Client-Side Scanner Engine]
  D --> D1[OpenAI Responses]
  D --> D2[Claude Messages]
  D --> D3[Gemini generateContent]
  D --> D4[Custom Proxy]
  D1 --> G[Live Response Classifier]
  D2 --> G
  D3 --> G
  D4 --> G

  F --> H[Evidence Collector]
  G --> H
  H --> I[Severity Tuner]
  I --> J[OWASP LLM Mapper]
  J --> K[Risk Score + Findings]
  K --> L[Markdown Report]
  K --> M[CI Security Gate]
```

## 🔁 Application Flow

```mermaid
flowchart LR
  A[Paste artifacts or upload corpus] --> B[Choose scan profile]
  B --> C[Run local scan]
  C --> D[Review risk score + findings]
  D --> E{Need live validation?}
  E -->|Yes| F[Choose prompt number range]
  F --> G[Run live campaign]
  G --> H[Classify model responses]
  E -->|No| I[Export report]
  H --> I
  I --> J[Download CI gate or Markdown evidence]
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

Run the local CI security gate:

```bash
npm run ci:scan
```

## 🧩 Optional Configuration

Create or edit `.ragshieldrc.json`:

```json
{
  "failOnCritical": true,
  "maxRiskScore": 35,
  "allowDemoSecrets": false,
  "scanPaths": ["src/**/*.{ts,tsx,md,json}", "docs/**/*.md", "README.md"]
}
```

## 🧪 Prompt Campaign Workflow

1. 🔐 Add a session-only API key or custom proxy URL.
2. 🎯 Select the target provider and model.
3. 🔁 Use previous, next, or shuffle to inspect prompts.
4. 🔢 Set **Start No.** and **Run Count** for the campaign range.
5. ▶️ Run the campaign and review blocked, vulnerable, and error states.

Custom payload JSON can be uploaded as either an array or a wrapped object:

```json
{
  "payloads": [
    {
      "category": "Custom Prompt Injection",
      "owasp": "LLM01",
      "payload": "Place your custom model test prompt here."
    }
  ]
}
```

## 🗺️ Roadmap

- 📄 SARIF report export
- 💾 Saved scan sessions
- 🧰 Custom rule packs
- 📈 Provider-specific score tuning
- 🧪 Regression suite import/export
- 🌐 Optional API mode for enterprise pipelines

## 🤝 Responsible Use

RAGShield is built for defensive testing, AppSec review, AI red teaming, and secure development. Use it only on systems you own or have explicit permission to test.

## 📄 License

MIT License. See `LICENSE.txt`.
