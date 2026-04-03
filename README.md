# AI + Security + AI Security Portfolio — Bhanu Gupta

Built during my Bachelor of IT at Otago Polytechnic Auckland. Three deliberate pillars:

**AI** — understanding how models are built, trained, and deployed. You can't secure what you don't understand.

**Security** — web attack surface, detection engineering, penetration testing fundamentals. The foundation that makes me hireable at entry level in NZ.

**AI Security** — prompt injection, adversarial ML, LLM red teaming, OWASP LLM Top 10. The intersection most candidates don't have.

Targeting Security Engineer and AppSec roles in New Zealand. Long-term target: AI Security Engineer / AI Red Teamer.

---

## AI Security Projects

### 1. Prompt Injection Defense Framework
Python toolkit detecting and defending against prompt injection attacks on LLMs. 50+ attack patterns across 7 categories. Rule-based detection with compound risk scoring (0–100). Input sanitization pipeline. Structured JSON logging with alert thresholds. Mapped to OWASP LLM Top 10 (LLM01).

- **Patterns:** Direct override, persona injection, delimiter attacks, encoded attacks, indirect injection, context manipulation, jailbreak templates
- **Detection:** Compound risk scoring — SAFE / SUSPICIOUS / HIGH_RISK / CRITICAL
- **CLI:** `scan`, `scan-file`, `stats` commands with `--sanitize`, `--json`, `--min-severity` flags
- **Tests:** 70+ tests, 0 false positives on clean inputs

**Folder:** [`ai-security/prompt-injection-defense/`](./ai-security/prompt-injection-defense)

---

## Security Testing *(In Progress)*

**HackTheBox** — working through machines, web app and auth-focused. Writeups in progress.

**PortSwigger Web Security Academy** — SQL injection, XSS, authentication, access control, SSRF labs.

**Crucible by Dreadnode** — AI security CTF challenges: prompt injection, model extraction, adversarial inputs.

---

## Certifications *(In Progress)*

Working through a deliberate stack across three pillars:

| Pillar | Certs |
|--------|-------|
| AI | Anthropic Academy → Claude Certified Architect |
| Security | CompTIA Network+ → Security+ → HTB CJCA → CWES |
| AI Security | CompTIA SecAI+ → HTB AI Red Teamer → CAISP |

---

## Tools & Technologies

**AI Security:** Python, OWASP LLM Top 10, MITRE ATLAS, prompt injection patterns, adversarial ML

**Security:** HackTheBox, PortSwigger Web Security Academy, Burp Suite, Wireshark, Splunk/ELK

**AI/ML:** Claude API, Anthropic MCP, LangChain *(learning)*, PyTorch *(learning)*

**Languages:** Python, JavaScript, TypeScript

**CI/CD:** GitHub Actions

---

## About

Bhanu Gupta — final-year Bachelor of IT, Otago Polytechnic Auckland. Pursuing a Master's in Cybersecurity. Building toward Security Engineering roles in NZ with AI security specialization.

Most security people don't understand AI. Most AI people don't understand security. That gap is what I'm positioning in.

- **GitHub:** [github.com/bhanuGupta1](https://github.com/bhanuGupta1)
- **Email:** bhanuguptagarg@gmail.com
