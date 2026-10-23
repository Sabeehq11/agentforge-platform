# Build versus configure record

Required by the Week 3 PRD before any agent role is implemented, and an Architecture Defense deliverable.

**Evidence status.** Coverage claims were checked against each vendor's own documentation on 2026-10-23. The page
and the date are in the table. No tool was installed or run. A checked page is not a scan of the Co-Pilot, and it
is not a measurement of how the tool would behave against this target.

## What we need

| Role | Job |
|---|---|
| Red Team | Generate novel attacks, mutate partial successes, run multi-turn sequences against the Co-Pilot |
| Judge | Decide whether an attack succeeded, a defense held, or a regression appeared, independently of the attacker |
| Orchestrator | Read coverage gaps, open findings and regressions, then choose the next campaign |
| Documentation | Turn a confirmed exploit into a reproducible report after validating required fields and uniqueness |
| Deterministic layer | Replay, canary and PHI checks, boundary and fuzz inputs, regression store |

The target is an LLM application behind a session-authenticated web module (ADR-002). The attack content is mostly
natural language and uploaded documents, and the verdict depends on this platform's own invariants: patient IDs,
canaries, PHI patterns, and the tool allowlist.

## Tools evaluated

| Tool | What the official page says it covers | Where that falls short here | Decision |
|---|---|---|---|
| Burp Suite | Burp Proxy intercepts, inspects, and modifies browser traffic, including HTTPS ([Burp Proxy](https://portswigger.net/burp/documentation/desktop/tools/proxy), updated 2026-10-22). Burp Scanner is a DAST scanner that crawls an application and audits requests for vulnerabilities. It is available in Professional and DAST, not Community Edition ([Burp Scanner](https://portswigger.net/burp/documentation/scanner); [first scan](https://portswigger.net/burp/documentation/desktop/getting-started/running-your-first-scan)). Burp AT is a prompted agent that uses those tools and records findings for a person to verify ([Burp AT](https://portswigger.net/burp/documentation/desktop/burp-at)). | The documented scanner finds web vulnerabilities in traffic. It does not implement this platform's patient, canary, or PHI verdicts. Burp AT sends prompts to PortSwigger, which selects the model, and the operator must verify each finding. That does not provide the independent Judge, the versioned contracts, or the regression store. | Not adopted. Not run. |
| OWASP ZAP | An intercepting proxy with a spider and an active scanner. The active scanner sends known attacks. Its own page says it cannot find logical vulnerabilities such as broken access control, and that manual testing is still required ([Active Scan](https://www.zaproxy.org/docs/desktop/start/features/ascan/), read 2026-10-23). | The same limit as Burp Scanner. It does not grade model behavior against this platform's invariants, and it has no regression harness for a changed target version. | Not adopted. Not run. An earlier line that said to configure ZAP for the web Top 10 is withdrawn. |
| Semgrep | Static analysis of source code with rules. Official docs describe scanning a repository for patterns in first-party code ([Semgrep Code](https://docs.semgrep.dev/semgrep-code/overview), read 2026-10-23). | It needs source. This platform reaches the Co-Pilot over HTTP only (ADR-001), so Semgrep cannot observe the running target. | Not adopted. The platform self-scan is pytest, mypy, Bandit, and pip-audit (`scripts/self_scan.py`), not Semgrep. |
| Garak | An LLM vulnerability scanner. Probes send prompts to a generator and detectors score the text that comes back. Official docs describe generators as things that take text in and return text out, including HTTP APIs ([generators](https://docs.garak.ai/garak/garak-components/using-generators), read 2026-10-23). | A generator does not own this target's login, patient context, or tool gateway. Detectors look for keywords or classifier hits in generated text. They do not apply this platform's patient-boundary or canary invariants, and they do not write this store's regression cases. | Not adopted. Not wrapped. |
| promptfoo | Config-driven red-team generation and evaluation. Plugins generate adversarial inputs and strategies deliver them. The red-team grader is a model, `gpt-5` by default ([About the Grader](https://www.promptfoo.dev/docs/red-team/troubleshooting/grading-results/), read 2026-10-23). | The default grader is another model. That conflicts with a Judge whose decisive checks are deterministic and independent of the attacker. It also does not write this platform's versioned exploit store. | Not adopted. |
| PyRIT | A Python framework for AI red teaming. Official docs describe single-turn and multi-turn attacks, targets that include custom HTTP endpoints, and scorers that return a boolean or a score ([PyRIT](https://microsoft.github.io/PyRIT/latest/), read 2026-10-23). | It brings its own attack, memory, and scoring abstractions. ADR-003 chose a small persisted state machine so that trust boundaries and typed messages stay explicit. Wrapping PyRIT would put a second coordinator behind that machine. | Not adopted. The earlier "evaluate in P4" line is closed. |
| Commercial red-team platforms | Palo Alto Prisma AIRS AI Red Teaming documents a hosted attack library of 500 or more scenarios, campaign reports, and a required license ([Prisma AIRS](https://docs.paloaltonetworks.com/ai-runtime-security/ai-red-teaming/identify-ai-system-risks-with-ai-red-teaming), updated 2026-10-08). | The documented product sends the campaign to the vendor service and returns the vendor's report. It does not implement this platform's contracts, approval gate, or regression store. Healthcare transcripts would leave this repository. | Not adopted. Not licensed. Not run. This is one documented product in the class, not a survey of every vendor. |
| Plain deterministic tooling | Not a vendor product. Replay, canary strings, PHI checks, and the SQL store are code in this repository. | This layer cannot invent a new attack or judge an ambiguous transcript. Those remain the Red Team and the ambiguous-only Judge model. | Adopted. Already built. |

## Decision per role

| Role | Decision | Justification |
|---|---|---|
| Red Team | Build custom | The session, patient context, budget, and novelty check are this platform's. None of the evaluated tools implements that boundary without adopting its own coordinator. |
| Judge | Build custom, deterministic rules first | Verdicts depend on this platform's invariants. A model grades only an ambiguous transcript, and it is a different family from the Red Team. |
| Orchestrator | Build custom, no model | It ranks stored coverage, findings, and regressions (`src/agentforge/orchestrator/priority.py`). No evaluated tool reads that store. |
| Documentation | Build custom, no model | The report copies the confirmed exploit after the required-field and uniqueness checks. A template is reproducible. Generated prose is not required. |
| Deterministic layer | Build, small | Replay, canary, PHI, and boundary checks must be exact. They are already in this repository. |
| Web scanning | Do not configure a scanner as a platform component | Burp Scanner and ZAP cover generic web attacks. They do not grade the clinical invariants, and neither has been run. |

## Closed items

- The coverage claims above were checked against the linked pages on 2026-10-23. Anything those pages do not say is
  not claimed.
- No evaluated tool is adopted, so none is wrapped by the allowlist chokepoint. A later adoption would still have to
  pass that chokepoint or be refused.
- Burp Scanner's Professional or DAST license requirement is documented by PortSwigger. No price was checked, and
  none is needed, because the scanner is not adopted.
