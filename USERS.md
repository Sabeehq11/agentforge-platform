# Users

Who this platform is for, what they do with it, and why a person prompting by hand is not enough. The root-level
`USERS.md` is a PRD deliverable whose checkpoint is **(unconfirmed)** (ROADMAP section 5, Q5). It is written now, at
P1, so the work exists whichever checkpoint it is graded at.

The platform tests one system: the Clinical Co-Pilot inside OpenEMR, reached over HTTP as a synthetic fixture user
([ADR-002](Docs/adr/002-target-access.md)). It does not replace a human reviewer. It finds, grades, and files. A
person decides what gets published and what gets fixed.

## Users

### Security engineer

Owns the question of whether the Co-Pilot can be made to do something it should not.

- **Workflow.** Reads [THREAT_MODEL.md](THREAT_MODEL.md), approves a campaign against the categories ranked there,
  reviews the findings the Judge confirms, and reproduces one before accepting it.
- **Use cases.**
  - "Has anyone tested indirect injection through an uploaded PDF (TM-PI-2) since the last change to the verifier?"
  - "Show me the open high-severity findings and which of them regressed after the last deploy."
  - "Give me a report I can hand to the engineer who will fix it, with the exact sequence and the expected behavior."
- **Why automation.** The categories mutate. A list of prompts written once does not catch the variant that appears
  after a fix, and re-running it by hand does not scale past a handful of cases. The engineer still approves what is
  published. The platform does the repetition.

### Platform and ML engineer

Owns the Co-Pilot and is the person who changes it.

- **Workflow.** Before merging a change to the agent, runs the regression suite against the pinned build and reads
  the pass and fail rate by category.
- **Use cases.**
  - "Does the fix for cross-patient access (TM-EX-2) still hold, and did it break anything in another category?"
  - "A case failed yesterday and passes today. Is the vulnerability fixed, or did the model just answer differently?"
- **Why automation.** A fix validated once, by hand, against one prompt, is how regressions ship. The harness reruns
  the confirmed cases on every version and asserts on side effects rather than on wording, which a person skimming an
  answer cannot do reliably.

### Clinical safety and compliance reviewer

Owns the decision that a finding is real, serious, and safe to circulate. Does not run attacks.

- **Workflow.** Reads the filed reports, checks that each one has the required fields and a clinical impact, and
  approves or sends back the critical and high ones.
- **Use cases.**
  - "Which open findings could expose one patient's chart to another clinician, and what is the evidence?"
  - "Was any real patient data involved in producing this report?"
- **Why automation.** The reviewer needs coverage they can query, not a chat log. Automation produces the structured
  record and the guarantee that the underlying data is synthetic. It does not make the approval decision, because a
  wrong one wastes engineering time or, worse, clears a real exposure.

### Operator

Owns the keys, the allowlist, and the spend. In this project that is the repository owner.

- **Workflow.** Sets the provider-side spending limit, attests it, approves a run that exceeds the default cap, and
  edits the allowlist when the tunnel URL changes.
- **Use cases.**
  - "Stop everything before the next call."
  - "Add the new tunnel hostname, and show me that nothing else was added."
- **Why automation, and where it stops.** Automation is the wrong tool for these decisions, and the platform is built
  so it cannot make them. An allowlist entry, an over-cap run, and a load test each require a person. Automation
  handles the part that must be tireless: enforcing the cap on every single call, including the ones at 3am.

## Where a human decides

| Decision | Who | Why it is not automated |
|---|---|---|
| Publishing a critical or high finding | Clinical safety reviewer | A false positive wastes the fixing engineer's time |
| Applying a remediation | Platform engineer | An agent that pushes a fix can introduce a new vulnerability. Agents may propose a patch and never apply one |
| Adding an allowlist host, raising a cap, running a load test | Operator | These authorize the platform to act on something new, or to spend more |

## Why automation is the right tool overall

The failure this platform exists to fix is not a missing jailbreak. It is that the current process is a person typing
prompts and keeping notes. That fails in four ways, each visible in the scenario this work responds to:

- A static list goes stale the moment an attacker rephrases.
- A finding that is not reproducible is not fixable by someone who was not there.
- A fix checked once is not a fix checked against the next variant.
- Without a record of which categories were exercised, nobody can say what was not tested.

Each of those is a volume and consistency problem. A person is the right judge of whether a finding matters. A person
is not the right mechanism for running the same case, and its variants, against every new version, forever.
