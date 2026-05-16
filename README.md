# Bhanu Gupta — AI Security Engineering Portfolio

> Building toward AI Security Engineer · Critical Infrastructure · NZ/AU

[![Prompt Injection Tests](https://github.com/bhanuguptagarg/ai-security-portfolio-bhanu/actions/workflows/tests.yml/badge.svg)](https://github.com/bhanuguptagarg/ai-security-portfolio-bhanu/actions/workflows/tests.yml)
[![Adversarial Attack Tests](https://github.com/bhanuguptagarg/ai-security-portfolio-bhanu/actions/workflows/adversarial-tests.yml/badge.svg)](https://github.com/bhanuguptagarg/ai-security-portfolio-bhanu/actions/workflows/adversarial-tests.yml)
![Focus](https://img.shields.io/badge/focus-AI%20Security%20%7C%20Critical%20Infrastructure-blue)
![Location](https://img.shields.io/badge/location-New%20Zealand-brightgreen)

---

## Live Projects

### PR-01 — Prompt Injection Defense Framework
**🔴 Live:** https://ai-security-portfolio-bhanu-production.up.railway.app/

Detection, sanitization, and middleware for LLM prompt injection attacks. Addresses OWASP LLM01 — the #1 vulnerability in production AI systems.

- 55 hand-crafted attack patterns across 7 categories
- FGSM/PGD attacks implemented from scratch in PyTorch
- Zero external dependencies for the core detection engine
- FastAPI middleware + interactive browser demo + CLI tool + Python library
- 78 tests passing across Python 3.10 / 3.11 / 3.12

→ [`ai-security/prompt-injection-defense/`](./ai-security/prompt-injection-defense/)

---

### PR-02 — Adversarial Attacks on AI in Transport Infrastructure
**🔴 Live:** *(deploying)*

Demonstrates FGSM and PGD adversarial attacks on a 43-class traffic sign classifier. Imperceptible pixel perturbations (ε ≤ 0.03) cause reliable misclassification — STOP signs read as SPEED LIMIT signs. Maps to MITRE ATLAS AML.T0043.

- FGSM and PGD implemented from scratch — no wrapper libraries
- Real-time attack dashboard: epsilon slider, before/after images, live audit log
- Epsilon sweep chart: FGSM vs PGD success rate across perturbation budgets
- 5 MITRE ATLAS technique mappings with full threat scenario and risk assessment
- 52 tests — CPU-only, no downloads, runs in CI

→ [`ai-security/adversarial-transport-attack/`](./ai-security/adversarial-transport-attack/)

---

## What's Being Built

| ID | Project | Stack | Status |
|----|---------|-------|--------|
| PR-01 | Prompt Injection Defense Framework | Python, FastAPI, Regex | ✅ Live |
| PR-02 | Adversarial Attacks on Transport AI | PyTorch, FGSM/PGD, MITRE ATLAS | 🔄 Deploying |
| PR-03 | OT/SCADA Simulation Lab | Python, pymodbus, Modbus TCP | 🔜 Next |
| PR-04 | Nuclei Template — FHIR Health API | YAML, Nuclei | 🔜 Planned |
| PR-05 | CPS 230 Financial Services AI Threat Model | STRIDE, MITRE ATLAS, APRA | 🔜 Planned |
| PR-06 | LLM Red Team Toolkit | Python, Claude API | 🔜 Planned |
| PR-07 | Secure RAG Pipeline | LangChain, ChromaDB, Claude API | 🔜 Planned |

---

## Focus Areas

**Primary — Critical Infrastructure AI Security**
Legally mandated under SICSA 2022 (AU). AI systems embedded in transport, energy, and water infrastructure. Adversarial ML, MITRE ATLAS, threat modelling for physical AI systems.

**Layer — Financial Services AI Security**
APRA CPS 230 compliance. LLM risk in banking and fraud detection AI. OWASP LLM Top 10 applied to production financial systems.

---

## Tech Stack

| Domain | Tools |
|--------|-------|
| Languages | Python 3.10+ |
| ML / AI | PyTorch, torchvision |
| Security frameworks | OWASP LLM Top 10, MITRE ATLAS, STRIDE |
| APIs & deployment | FastAPI, uvicorn, Railway, Render |
| Testing | pytest, pytest-cov |
| CI/CD | GitHub Actions (matrix: Python 3.10 / 3.11 / 3.12) |
| Certifications (in progress) | CompTIA Network+, Security+, Microsoft SC-200 |

---

## Connect

- **GitHub:** [github.com/bhanuguptagarg](https://github.com/bhanuguptagarg)
- **LinkedIn:** [linkedin.com/in/bhanu-gupta-garg](https://linkedin.com/in/bhanu-gupta-garg)
- **Email:** bhanuguptagarg@gmail.com
