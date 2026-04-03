# AI + Security + AI Security Portfolio — Bhanu Gupta

Portfolio built during my Bachelor of IT at Otago Polytechnic, Auckland. Three deliberate pillars:

**Pillar 1 — AI:** ML fundamentals, model pipelines, Claude API, RAG architecture, LangChain. Understanding how AI systems are built is the prerequisite for knowing how to break and defend them.

**Pillar 2 — Security:** Network+, Security+, web attack surface, SIEM, detection engineering, HackTheBox, PortSwigger. The broad security foundation that makes me hireable at entry level in NZ right now.

**Pillar 3 — AI Security:** Prompt injection defense, LLM red teaming, adversarial ML, OWASP LLM Top 10, MITRE ATLAS. The intersection most candidates don't have — and the long-term target role.

Entry-level target: Junior Security Analyst / Junior AppSec Engineer (NZ priority, AU backup).
Long-term target: AI Security Engineer / AI Red Teamer.

QA automation foundations are reframed as security testing evidence — adversarial edge-case thinking, auth flow analysis, systematic coverage, CI/CD automation. The same skills that make a good test engineer make a good security engineer.

---

## AI Security Projects *(In Progress)*

### 1. Prompt Injection Defense Framework
Python toolkit detecting and defending against prompt injection attacks on LLMs. 50+ attack patterns catalogued (direct, indirect, jailbreaks). Rule-based + embedding similarity detection. Input sanitization layer. Mapped to OWASP LLM Top 10 (LLM01).

*Building now.*

### 2. LLM Red Team Toolkit
Automated red teaming tool that probes LLMs for vulnerabilities — prompt injection, data leakage, jailbreak patterns, output manipulation. Scoring system, PDF/Markdown report generation, evidence collection.

*Planned: after Project 1.*

### 3. Secure RAG Pipeline
Retrieval-Augmented Generation system with security hardening at every layer. Document-level access control, query sanitization, data poisoning detection, PII filtering, audit logging.

*Planned: during Master's.*

### 4. Adversarial ML Attack Detection
FGSM and PGD attacks on a trained image classifier. Defense comparisons (adversarial training, input preprocessing). Full writeup with math explanations.

*Planned: during Master's.*

### 5. AI Security Audit Framework
Reusable audit checklist and automated scanning toolkit mapped to OWASP LLM Top 10 and MITRE ATLAS. Risk scoring matrix, professional report template, remediation database.

*Planned: after Project 2.*

---

## Security Testing *(In Progress)*

**HackTheBox writeups** — working through machines, starting with Easy (web app and auth-focused), progressing to Medium.

**OWASP Juice Shop lab** — 3-star+ challenges documented as a professional vulnerability assessment report, mapped to OWASP Top 10 and CWE IDs.

**PortSwigger Web Security Academy** — SQL injection, XSS, authentication, access control, SSRF labs.

---

## QA Foundations *(Completed — Reframed for Security)*

These sections demonstrate the systematic, adversarial thinking that feeds directly into security engineering work.

### Manual Security Testing — SEEK NZ

Security-focused exploratory testing of SEEK New Zealand as a guest user. Evaluated authentication gating, access control boundaries, authorization bypass attempts, and session management behavior.

14 executed test cases, 6 bug reports (severity/impact/evidence), Risk Matrix, RTM, Accessibility Checks, Test Summary Report.

**Folder:** [`manual/`](./manual)

---

### API Security Testing — DummyJSON (Postman + Newman)

API security test suite covering authentication bypass vectors, JWT token security, unauthorized access attempts, and data validation against the DummyJSON REST API.

**18 requests, 47 assertions** across 5 categories:

| Category | Requests | What's Tested |
|----------|----------|---------------|
| Pre-Auth Checks | 2 | Unauthenticated access: no token (401), fake token (401) |
| Auth | 3 | Valid login (token stored), invalid creds, empty body |
| Users | 4 | List, get by ID, invalid ID (404), pagination |
| Products (CRUD) | 8 | GET, POST, PUT, DELETE, search, sort, schema validation |
| Authenticated Access | 1 | Chained auth: login token reused on /auth/me |

Chained auth flows, full CRUD coverage, schema validation, negative testing, Newman CI pipeline.

**Folder:** [`api/`](./api)

---

### Security Regression Automation — Cypress (JavaScript)

Automated security regression framework validating authentication controls, session management, and data integrity across Sauce Demo's critical security boundaries.

**24 test cases** across 5 spec files — valid login, locked user detection, invalid credential handling, session state persistence, cart data integrity, checkout flow validation.

Page Object Model, custom commands, data-driven fixtures, screenshot on failure, GitHub Actions CI/CD.

**Folder:** [`automation/cypress-framework/`](./automation/cypress-framework)

---

### Cross-Browser Security Validation — Playwright (TypeScript)

Multi-browser security validation framework. Same application, different stack. Proves the security test coverage isn't tool-dependent.

**29 test cases** — Chromium, Firefox, WebKit. Auth flow verification, session management, direct-access protection, checkout data integrity. Trace viewer for failure analysis.

**Folder:** [`automation/playwright-framework/`](./automation/playwright-framework)

---

## How to Run Tests

### Cypress
```bash
cd automation/cypress-framework
npm install
npm test                    # headless
npm run cy:open             # interactive
```

### Playwright
```bash
cd automation/playwright-framework
npm install
npx playwright install
npm test                    # all browsers
npm run test:chromium       # chromium only
npm run report              # HTML report
```

---

## Certifications

Working through a deliberate certification stack across CompTIA, ISTQB, HackTheBox, and Anthropic. Full tracker in `certifications/README.md` *(coming soon)*.

Target certs: CompTIA Network+ → Security+ → SecAI+, ISTQB CTFL → CT-AI, HTB CJCA → CWES → AI Red Teamer, Claude Certified Architect, CAISP.

---

## Tools & Technologies

Security: Python, OWASP LLM Top 10, MITRE ATLAS, prompt injection patterns, adversarial ML, HackTheBox, PortSwigger Web Security Academy

Testing & Automation: Cypress 15.x (JavaScript), Playwright (TypeScript), Postman, Newman, Page Object Model, data-driven fixtures

AI/ML: Claude API, Anthropic MCP, LangChain *(learning)*, PyTorch *(learning)*

CI/CD: GitHub Actions, headless test runs, Newman HTML reports

---

## About

Bhanu Gupta — final-year Bachelor of IT, Otago Polytechnic Auckland. Pursuing a Master's in Cybersecurity after graduation (Dec 2026). Building toward Security Engineering roles with AI security specialization. Target market: New Zealand (priority), Australia.

Security engineering is where I'm entering. AI security is where I'm heading. The two don't conflict — they compound.

- **GitHub:** [github.com/bhanuGupta1](https://github.com/bhanuGupta1)
- **Email:** bhanugupta2001@gmail.com
