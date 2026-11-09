# Learning Guide — Four Security Engineering Projects

This guide explains the **ideas** behind the four projects: the real-world
problem each one attacks, the security concepts and vocabulary you need to
understand it, and what skills it demonstrates. Read this first to understand
*why* the projects are built the way they are. For the hands-on "how do I run it
and read the output" side, see **PROJECT_WALKTHROUGH.md**.

## The one idea that ties them together

All four projects share a single principle:

> **Security claims should be measured, not asserted.**

A detection you never scored is a guess. A scanner you only ran against a broken
target has an unknown false-positive rate. A "secure build" you never tried to
tamper with proves nothing. Each project therefore pairs a *mechanism* (a
detector, a test suite, a pipeline, a model) with a *measurement harness* that
produces honest numbers: coverage, recall, precision, detection rate, false-alarm
rate, latency, communication cost.

That pairing — build the thing **and** the thing that grades it — is the skill
these projects are really teaching.

---

## Project 1 — Cloud Attack Detection & Response Lab

### The problem
Cloud environments (AWS, Azure, GCP) emit huge audit logs. Buried in the noise
are the few events that signal an attack: a password being guessed, a stolen
credential used from a new country, someone quietly turning off logging. The job
of **detection engineering** is to write rules that find those events — and to
know how good those rules actually are.

### Key concepts
- **Audit log / audit trail** — the record of who did what (e.g. AWS CloudTrail).
  Every event has an actor, a source IP, an action, a resource, and an outcome.
- **MITRE ATT&CK** — a public, numbered catalog of attacker techniques
  (e.g. `T1110.001` = password guessing). It gives defenders a shared vocabulary:
  instead of "someone tried a lot of passwords," you say "we detected T1110.001."
  Reference: https://attack.mitre.org/
- **Tactic vs. technique** — a *tactic* is the attacker's goal (Credential
  Access, Persistence, Defense Evasion); a *technique* is a specific way to
  achieve it. ATT&CK organizes techniques under tactics.
- **Detection rule** — logic that fires an **alert** when a pattern appears.
  Rules are often *stateful and windowed*: "≥10 failed logins for one account
  within 2 minutes," not just "a failed login."
- **True positive / false positive** — a *true* alert matches a real attack; a
  *false* alert fires on benign activity. Too many false alerts and analysts stop
  trusting the system ("alert fatigue").
- **Alert latency** — how long between the first attack event and the alert.
  Fast detection shrinks the window an attacker has to do damage.
- **Response playbook** — the step-by-step containment/eradication/recovery
  procedure you run *after* an alert (Contain → Scope → Eradicate → Recover →
  Harden).

### What this project demonstrates
You can model attacker behavior, write detections mapped to a recognized
framework, and — crucially — **score** them for coverage, false positives, and
latency instead of just claiming they work.

---

## Project 2 — API Authorization Testing Framework

### The problem
The most common serious API bugs aren't exotic — they're **broken
authorization**: the API checks *who you are* (authentication) but forgets to
check *whether you're allowed to touch this specific thing* (authorization). The
result is users reading each other's data or calling admin-only functions.

### Key concepts
- **Authentication vs. authorization** — authentication = "are you a valid
  user?" (login, tokens). Authorization = "are you allowed to do *this*?". Most
  of these bugs pass authentication and fail authorization.
- **OWASP API Security Top 10 (2023)** — the industry reference list of the worst
  API risks. Reference: https://owasp.org/API-Security/editions/2023/en/0x00-header/
  This project covers three of them:
  - **BOLA — Broken Object Level Authorization (API1)** — you can access an
    *object* (a record) that isn't yours by changing an ID in the URL, e.g.
    `GET /users/2` when you are user 1. The #1 API risk.
  - **BOPLA / Mass Assignment (API3)** — the API blindly accepts whatever fields
    you send, so you set a field you shouldn't control (like `role: admin`) and
    escalate your own privileges.
  - **BFLA — Broken Function Level Authorization (API5)** — you can call a
    *function/endpoint* meant for a higher role, e.g. a normal user hitting
    `DELETE /admin/users/1`, because the role check is missing.
- **IDOR** — "Insecure Direct Object Reference," the older name for the bug class
  BOLA formalizes.
- **Seeded flaw** — a vulnerability you deliberately plant so you can prove your
  test finds it. Testing only against seeded flaws measures **recall**.
- **Recall vs. precision (and why you need legitimate tests too)** — treat "the
  app blocked the action" as a prediction. *Recall* = of the attacks, how many did
  it block? *Precision* = of its blocks, how many were justified? If you only test
  forbidden actions, an API that **denies everything** gets perfect recall and
  looks secure — but it's useless. So the project also runs **legitimate** probes
  (actions that *should* succeed); blocking those counts as false positives and
  collapses precision. An app is judged secure only if it stops every attack
  **and** denies no legitimate request. (A bundled deny-all control demonstrates
  this: recall 1.0 but precision 0.5, specificity 0.0.)

### What this project demonstrates
You understand the dominant class of real-world API vulnerabilities, can write
probes that exercise them, and can validate a security tool in **both**
directions — it must fire on the bug *and* stay quiet on the fix.

---

## Project 3 — Software Supply-Chain Security Pipeline

### The problem
Modern software is assembled from hundreds of third-party pieces and built by
automated systems. Attackers have learned to poison that process: swap a
dependency, tamper with a build, or forge the record of how something was made
(SolarWinds, Codecov, and the `event-stream` npm incident are famous examples).
**Supply-chain security** is about being able to *prove* an artifact came from an
approved process with unchanged inputs.

### Key concepts
- **Artifact** — the thing you ship (a binary, a package, a container image). Its
  identity is its cryptographic **digest** (a SHA-256 hash); change one byte and
  the digest changes.
- **SBOM — Software Bill of Materials** — a machine-readable inventory of every
  component that went into a build, with versions. Think "ingredients label."
  **CycloneDX** is a common SBOM format. If a new vulnerability drops, your SBOM
  tells you instantly whether you ship the affected version.
- **Provenance** — a signed statement describing *how* an artifact was built:
  what source it came from, which builder produced it, and what materials
  (dependencies) went in. **in-toto** defines the envelope; **SLSA**
  (Supply-chain Levels for Software Artifacts) defines the provenance content.
  Reference: https://slsa.dev/spec/v1.0/provenance
- **Attestation / signing** — provenance and SBOM are only trustworthy if they're
  **signed** so they can't be altered undetected. This project uses **Ed25519**
  (a modern public-key signature). Real pipelines often use **Sigstore/cosign**.
- **Canonical serialization** — to sign/verify reliably you must hash the *exact
  same bytes* every time, so the data is encoded deterministically (sorted keys,
  no incidental whitespace) before signing.
- **Trust anchor / key pinning** — a signature is only meaningful if you verify it
  against a key you *already* trust. The subtle, critical rule: a bundle must
  never name the key that verifies it, or an attacker just signs with their own
  key and points at it. Trusted keys are **pinned out-of-band**, bound to a
  builder identity, and looked up by that identity at verify time.
- **Admission policy** — the gate that decides whether a release may ship. Here it
  enforces five checks: valid signatures *against the pinned key for the claimed
  builder*, the builder being a **known/approved identity**, the release digest
  matching what provenance claims, SBOM/provenance agreement, and fully **pinned**
  (version-locked) dependencies.
- **Pinning** — requiring exact versions (`left-pad==1.3.0`, not `left-pad`) so a
  build is reproducible and can't silently pull a malicious newer version.

### What this project demonstrates
You understand how builds get attacked and how to defend them: generating an
SBOM, recording signed SLSA-style provenance, and enforcing a policy that
*rejects* tampered releases — then proving it with controlled tamper experiments
that each trip a specific check.

---

## Project 4 — IoT Intrusion Detection Under Changing Conditions

### The problem
You can train a machine-learning model to spot malicious network traffic. But IoT
fleets break the usual assumptions: every device type behaves differently, their
"normal" shifts over time, and you often can't (or shouldn't) ship all their raw
traffic to one server. This project studies how a detector holds up when the
world stops being tidy.

### Key concepts
- **Intrusion Detection System (IDS)** — software that flags malicious network
  activity. A *machine-learning* IDS learns the boundary between benign and
  attack traffic from labeled examples.
- **Features** — the numeric summary of a traffic window the model reasons over
  (packet rate, payload size, unique destination ports, failed-connection ratio,
  etc.). Good features make classes separable; overlapping features make the job
  realistically hard.
- **Attack families** — here, *flood* (volumetric / DDoS-style bursts) and *scan*
  (probing many ports/hosts). A **DDoS** (Distributed Denial of Service) tries to
  overwhelm a target with traffic; a **port scan** maps what's reachable.
- **Non-IID data** — "not independent and identically distributed." A camera and
  a door lock have totally different normal traffic, so data split by device is
  *non-IID*. This is the hard case for learning: a model that fits one device may
  misjudge another.
- **Concept drift** — when the underlying "normal" changes over time (a firmware
  update, new usage patterns). A model trained before the drift starts raising
  **false alarms**, because yesterday's normal now looks suspicious.
- **Centralized training** — pool all devices' raw data on a server and train one
  model. Simple and usually accurate, but you must *move all the raw data*.
- **Federated learning / FedAvg** — instead of moving data, each device trains
  locally and only shares **model parameters**; a server averages them (Federated
  Averaging) into a global model. You move kilobytes of weights instead of
  gigabytes of traffic.
- **Communication cost** — a first-class metric here: how much data had to move to
  train. Federated's whole pitch is trading a little accuracy for a lot less data
  movement.
- **Detection rate vs. false-alarm rate** — *detection rate* (recall / true
  positive rate) = fraction of attacks caught; *false-alarm rate* (false positive
  rate) = fraction of benign traffic wrongly flagged. You always trade one against
  the other.
- **An honest caveat** — federated learning reduces data movement, but sharing
  model updates can still leak information. It is studied here as a
  robustness/cost experiment, **not** as a privacy guarantee. Stating limits like
  this is itself a mark of security maturity.

### What this project demonstrates
You can build and *evaluate* an ML security model under realistic stress —
heterogeneous data and drift — and reason quantitatively about the
accuracy-vs-communication trade-off between centralized and federated approaches.

---

## Cross-cutting glossary

| Term | Plain meaning |
|------|---------------|
| True positive (TP) | correctly flagged a real bad thing |
| False positive (FP) | flagged a benign thing (false alarm) |
| False negative (FN) | missed a real bad thing |
| Recall / detection rate / TPR | TP ÷ (TP + FN) — of the bad things, how many caught |
| Precision | TP ÷ (TP + FP) — of your alerts, how many were real |
| False-alarm rate / FPR | FP ÷ (FP + TN) — of benign things, how many wrongly flagged |
| F1 score | harmonic mean of precision and recall (one combined number) |
| Coverage | fraction of scenarios where you detected *something* real |
| Latency | time from first attack event to the alert |
| Digest / hash | a fixed-length fingerprint of data (SHA-256); any change alters it |
| Signature | cryptographic proof that data wasn't altered and came from a key holder |
| Non-IID | data whose distribution differs across sources (per device, per user) |
| Concept drift | the "normal" distribution changing over time |

## Suggested learning order

1. **Project 2 (API authorization)** — most intuitive; you can *see* the bug in an
   HTTP request. Great mental model for authz vs. authn.
2. **Project 1 (detection lab)** — introduces events, rules, and scoring; the
   "measure it" mindset.
3. **Project 3 (supply chain)** — adds cryptography (hashing, signing) and policy
   thinking; a bit more abstract.
4. **Project 4 (IoT IDS)** — brings in machine learning; most math, most moving
   parts.

## How to talk about these (interview / README framing)

For each project, be ready to answer four questions:
1. **What real attack does it model?** (name the technique / OWASP item / incident)
2. **What did you build to catch or prevent it?**
3. **How did you measure success?** (name the metric and your result)
4. **What are its limits?** (synthetic data, simplified crypto, drift only
   modeled one way, etc. — naming limits builds credibility)

If you can answer those four for all four projects, you understand them.

## Where to go next

- Swap synthetic data for a public dataset (e.g. a labeled network-traffic or
  cloud-audit dataset) and re-run the same harnesses.
- Replace the hand-written crypto/SBOM in Project 3 with real tools (`cosign`,
  `syft`) and compare.
- Add a new ATT&CK technique (Project 1) or a new OWASP category such as
  rate-limiting/API4 (Project 2) and extend the test suite.
- Each project's README has an "Extending it" section with concrete next steps.
