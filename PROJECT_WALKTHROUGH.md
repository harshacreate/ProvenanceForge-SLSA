# Project Walkthrough — Setup, Running, and Reading the Code

This is the hands-on companion to **LEARNING_GUIDE.md**. The guide explains the
*ideas*; this file shows you how to **set up, run, and understand the code** of
each project, file by file, and how to interpret every number the tools print.

All four projects were built and verified on **macOS with Python 3.9**. Commands
below assume you are inside each project's folder.

---

## 0. One-time setup (recommended: a virtual environment)

A virtual environment keeps each project's dependencies isolated from your system
Python. Do this once per project:

```bash
cd ~/security-projects/<project-folder>
python3 -m venv .venv            # create the environment (the .gitignore excludes it)
source .venv/bin/activate        # activate it (prompt shows (.venv))
pip install -r requirements.txt  # install that project's dependencies
```

When you're done: `deactivate`. Next time, just `source .venv/bin/activate`
again. Every project also has a `Makefile`; run `make help` in any folder to see
its commands. The common ones are `make setup`, `make test`, and a run/eval
target.

> If you skip the venv, `make setup` still works — it just installs into your
> user Python. The venv is cleaner and is the normal professional habit.

---

## 1. Cloud Attack Detection & Response Lab

### What you run
```bash
make setup     # installs pytest (the lab core is standard-library only)
make test      # runs the unit tests for every detection rule
make eval      # the scored evaluation report
make eval-json # same report as JSON (for piping into other tools)
```

### How the pieces fit together
```
attack_sim/scenarios.py   makes fake audit events (benign + labeled attacks)
        │
        ▼
detections/rules.py       rules scan the event stream and emit Alerts
   + detections/engine.py  (the engine feeds each event to each rule, in time order)
        │
        ▼
harness/evaluate.py       compares Alerts to the hidden labels → metrics
```

### File-by-file
- **`attack_sim/scenarios.py`** — defines the `Event` dataclass (timestamp,
  actor, source_ip, action, resource, outcome, plus hidden `is_attack` /
  `technique` labels). `background_noise()` makes routine benign traffic. Five
  `scenario_*` functions each emit a labeled attack:
  - `password_guessing` → 25 failed logins then a success (**T1110.001**)
  - `impossible_travel` → one normal login, then one from a foreign IP (**T1078**)
  - `bucket_enumeration` → list then mass-download storage objects (**T1619/T1530**)
  - `new_access_key` → `CreateAccessKey` (**T1098**)
  - `disable_logging` → `StopLogging` (**T1562.008**)
  `build_timeline()` interleaves noise with attacks and sorts by time.
- **`attack_sim/mitre_map.py`** — loads `data/attack_techniques.json` and lets you
  look up a technique's name/tactic by ID.
- **`detections/engine.py`** — the `Alert` dataclass, the `Rule` interface, and
  the `Engine` that pushes every event through every rule.
- **`detections/rules.py`** — the four detections. Note they're **stateful**:
  `BruteForceLogin` keeps a sliding window (a `deque`) of recent failures per
  account; `ImpossibleTravel` remembers each account's last login IP+time;
  `BulkObjectAccess` counts reads in a window; `SensitiveApiCall` fires on single
  high-signal actions. Each rule's threshold is a knob you can tune.
- **`harness/evaluate.py`** — the scorer. It groups the hidden attack labels into
  per-technique time windows, runs the engine, then splits the alerts into
  **true** (technique was really present) and **false** (it wasn't), and computes
  latency as "first true alert time − first attack event time."
- **`response/playbooks.md`** — the human side: what to do after each alert.
- **`docker-compose.yml`** — *optional*. Brings up a sealed OpenSearch + Dashboards
  stack (`internal: true` network, loopback-only port) if you want to ship events
  into a mini-SIEM. Not needed for detection or scoring.

### Reading the output
The evaluation runs over many random seeds (`--seeds`, default 20):
```
Synthetic-scenario coverage : mean 100%  (worst seed 100%)   → of the GENERATED scenarios
False alerts                : 0.00 per run  (0 total over 20 runs)
Mean alert latency          : ~5 s         → avg time from attack start to detection
```
"Synthetic-scenario coverage" is the fraction of the lab's *generated* scenarios
detected — a signal about the rules against this synthetic family, **not** a
measure of real-world performance. The per-scenario breakdown (from the base
seed) shows `detected`, `true`/`false` alert counts, latency, and the ATT&CK
technique that fired.

### Try an experiment
Open `detections/rules.py` and lower `BruteForceLogin`'s `threshold` from 10 to 3,
then re-run `make eval`. Watch how a looser rule can start producing false alerts
on noise — the harness makes the precision/recall trade-off visible.

---

## 2. API Authorization Testing Framework

### What you run
```bash
make setup         # fastapi, uvicorn, httpx, pytest
make run           # the probe report against BOTH apps
make test          # pytest assertions (full recall, zero false positives)
make serve-vuln    # (optional) serve the vulnerable API on 127.0.0.1:8000
make serve-secure  # (optional) serve the fixed API on 127.0.0.1:8001
```

### How the pieces fit together
```
sample_api/vulnerable.py   the API WITH seeded authorization bugs
sample_api/secure.py       the SAME API, bugs fixed
        │                           │
        └──────────┬────────────────┘
                   ▼
authz_tests/catalog.py     probes act as low-privilege "bob" and try forbidden actions
        │
        ▼
authz_tests/runner.py      vuln app → recall; secure app → precision
```

### File-by-file
- **`sample_api/data.py`** — in-memory users (`alice` id 1, `bob` id 2, `admin`
  id 9), their orders, and a deliberately-trivial token scheme (`make_token` =
  base64 of the username). The simplicity is on purpose: the focus is
  *authorization*, not crypto.
- **`sample_api/vulnerable.py`** — the flawed API. Every bug is tagged with a
  `SEEDED FLAW <id>` comment:
  - **SF-01** `GET /users/{id}` returns *anyone's* record incl. SSN (**BOLA**)
  - **SF-02** `GET /users/{id}/orders` lists *anyone's* orders (**BOLA**)
  - **SF-03** `PATCH /users/{id}` accepts a client-set `role` → self-promote (**mass assignment**)
  - **SF-04** `DELETE /admin/users/{id}` has no role check (**BFLA**)
  - **SF-05** `GET /admin/metrics` has no role check (**BFLA**)
- **`sample_api/secure.py`** — the same routes with the fixes, tagged
  `FIX <id>`: a `require_owner_or_admin()` object check, a `require_admin()`
  function check, and a `PatchUser` model that simply doesn't accept `role`.
- **`sample_api/deny_all.py`** — the over-restrictive control that denies every
  protected request. The scoring must *not* mistake it for secure.
- **`authz_tests/catalog.py`** — two kinds of probe: **forbidden** (a low-privilege
  caller attempts something it must not do — these target the seeded flaws) and
  **legitimate** (a caller does what it *should* be allowed to). Each returns a
  `ProbeResult` with `action_allowed` and builds its own fresh client.
- **`authz_tests/runner.py`** — drives each app *in-process* with Starlette's
  `TestClient` (no network listener). It computes the suite's seeded-flaw recall
  on the vulnerable app, and scores each app as an access-control classifier over
  *both* probe sets (block = positive prediction, should-block = positive label):
  **recall** (attacks stopped), **precision** (blocks that were justified), and
  **specificity** (legitimate use allowed). An app is "secure" only if it stops
  every attack **and** denies no legitimate request.

### Reading the output
```
secure app:   recall=1.0 precision=1.0 specificity=1.0 -> PASS
deny_all app: recall=1.0 precision=0.5 specificity=0.0 -> correctly NOT secure
```
Per-probe rows tag each result: `VULN`/`block` for forbidden probes, `allow`/`DENY!`
for legitimate ones, with HTTP evidence (`GET /users/1 as bob -> 200 (ssn leaked)`
vs `-> 403`). The `deny_all` line is the lesson: blocking everything gives recall
1.0 but tanks precision and specificity, so it can't look secure.

### Try an experiment
Open `sample_api/secure.py`, comment out one `require_owner_or_admin(...)` call to
re-introduce a bug, and run `make run`. That forbidden probe flips to `VULN` and
the secure app's recall drops below 1.0 — showing how the framework catches
regressions.

You can also `make serve-vuln` and poke it by hand:
```bash
TOKEN=$(curl -s localhost:8000/login -H 'content-type: application/json' -d '{"username":"bob"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s localhost:8000/users/1 -H "Authorization: Bearer $TOKEN"   # bob reads alice → leaks
```

---

## 3. Software Supply-Chain Security Pipeline

### What you run
```bash
make setup    # cryptography, pytest
make build    # run the pipeline → out/release.json (signed bundle) + timings
make verify   # build, then run the admission policy and print PASS/FAIL per check
make tamper   # the controlled tamper experiments (the headline demo)
make test     # pytest
```

### How the pieces fit together
```
sample_project/app.py + manifest.txt   the "product" and its declared deps
        │
pipeline/build.py  ── hashes the WHOLE release tree, registers the builder key
        │            in the trust store, then calls:
        ├─ sbom.py        → CycloneDX inventory of dependencies
        ├─ provenance.py  → SLSA/in-toto record of how it was built
        └─ signing.py     → Ed25519 signatures over both
        │
        ▼
pipeline/verify.py   admission policy: C1..C5 must all pass to ship
   + pipeline/trust.py   pinned trusted keys (builder identity → key), OUTSIDE the bundle
        ▲
tamper/experiments.py   mutate one thing, confirm the right check fires
```

### File-by-file
- **`sample_project/app.py` / `manifest.txt`** — the product and its pinned
  dependency list (`name==version`).
- **`pipeline/signing.py`** — `canonical_bytes()` (deterministic JSON so signing
  is stable), `generate_keypair()` (Ed25519 PEM keys, private key chmod 600),
  and `sign()` / `verify()`.
- **`pipeline/trust.py`** — the **trust store**: a map of builder identity → trusted
  public key, kept *outside* the bundle. This is the root of trust; the verifier
  resolves keys from here by builder identity, never from the bundle.
- **`pipeline/sbom.py`** — parses the manifest and emits a **CycloneDX 1.5** SBOM.
- **`pipeline/provenance.py`** — emits an **in-toto Statement v1** wrapping a
  **SLSA provenance v1** predicate: the release digest (subject), the builder ID,
  the invocation, and the resolved dependencies (materials).
- **`pipeline/build.py`** — orchestrates build → sbom → provenance → sign, times
  each stage, and writes `out/release.json`. The artifact digest is a hash over
  **every file in the release tree** (not just `app.py`), and the build registers
  the builder's public key in the trust store (out-of-band onboarding).
- **`pipeline/verify.py`** — the **admission policy**. Five checks:
  - **C1** signatures valid *against the pinned key for the claimed builder* ·
    **C2** claimed builder is in the trust store · **C3** release digest matches
    provenance · **C4** SBOM == provenance materials · **C5** every dependency
    pinned. A release ships only if *all* pass.
- **`tamper/experiments.py`** — a clean **control** (must be admitted) plus six
  attacks, each designed to trip a specific check:
  | Experiment | Models | Caught by |
  |-----------|--------|-----------|
  | dependency swapped in SBOM | altered version | C4 (+C1: editing breaks the signature) |
  | artifact altered post-build | a release file replaced after signing | C3 |
  | unapproved builder (re-signed) | build from an untrusted identity | C2 |
  | **forged key, approved builder** | **signs with own key, claims approved builder** | **C1 (vs the pinned key)** |
  | provenance forged, stale signature | record edited in transit | C1 |
  | hidden component in SBOM | inventory/materials disagree | C4 |

### Reading the output
```
make tamper:
  OK      control (untampered)         checks fired: -       → clean build still ships
  CAUGHT  artifact altered post-build  checks fired: C3      → tamper tripped the digest check
  CAUGHT  forged key, approved builder checks fired: C1      → bad signature vs the PINNED key
  ...
  Attacks caught   : 6/6 (100%)       → every tampering was detected
  Control admitted : True             → the policy isn't just rejecting everything
  Avg pipeline time: ~0.3 ms/build    → the security overhead added to a build
```
"Checks fired" tells you *which guarantee* each attack violated — that mapping is
the real lesson.

### A note on fidelity
To stay dependency-light and run fully offline, dependency hashes and the signing
keys are generated locally rather than pulled from a real registry or KMS, and
the trust store is onboarded by the build step rather than a separate admin tool.
The *structure* (CycloneDX, in-toto/SLSA, detached signatures, **keys pinned by
builder identity outside the bundle**, a full-release digest as the signed
subject) mirrors a production pipeline built with real tools like `syft` (SBOM)
and `cosign`/Sigstore (signing).

---

## 4. IoT Intrusion Detection Under Changing Conditions

### What you run
```bash
make setup   # numpy, matplotlib, pytest
make run     # the centralized-vs-federated comparison report
make plot    # same, plus writes out/comparison.png (bar charts)
make test    # pytest
```

### How the pieces fit together
```
ids/dataset.py     synthetic per-device traffic (benign + flood/scan attacks),
                   non-IID shards, and an optional concept-drift shift
        │
        ├─ ids/centralized.py → pool all data, train one model
        └─ ids/federated.py   → each device trains locally, server averages (FedAvg)
        │
ids/model.py       a numpy logistic-regression detector (params = flat vector,
                   which is what makes averaging trivial)
        │
ids/evaluate.py    detection rate, false-alarm rate, precision, F1
        │
experiments/run.py  runs both, in-distribution and under drift, and reports
```

### File-by-file
- **`ids/dataset.py`** — the data generator. `DEVICE_PROFILES` gives each device
  (camera, thermostat, lock, hub) its own benign baseline (that's what makes the
  data **non-IID**). `_sample_attack()` makes *flood* and *scan* traffic whose
  feature ranges deliberately **overlap** benign traffic, so detection is a real
  multi-feature decision. The `drift` parameter shifts benign baselines toward the
  attack region to simulate **concept drift**. `partition_by_device()` creates the
  per-device shards federated learning trains on.
- **`ids/model.py`** — a small logistic-regression classifier in numpy. Its
  parameters are exposed as one flat vector (`params` / `set_params`) so federated
  averaging is a one-liner. `_linear()` wraps the matmul in `np.errstate(...)` to
  silence a *spurious* FP-flag warning from numpy 2.x on macOS BLAS (it's a
  hardware-flag artifact, not a real numeric error — explained in a code comment).
- **`ids/centralized.py`** — trains one model on pooled data (the baseline).
- **`ids/federated.py`** — **FedAvg**: each round, every device trains locally
  from the current global weights, the server averages the returned weights
  (weighted by sample count), and it **counts the floats transferred** as the
  communication cost. Normalization uses `agreed_scaler()` — a **pre-agreed**
  scaler (`AGREED_SCALER_MEAN/STD`), so no raw rows are pooled on a server just to
  fit a scaler, which keeps the model-updates-only comm cost honest.
  `centralized_comm_cost()` is the cost of shipping all raw samples, for
  comparison.
- **`ids/evaluate.py`** — turns predictions into metrics: `detection_rate`
  (recall), `false_alarm_rate` (FPR), `precision`, `f1`.
- **`experiments/run.py`** — builds an in-distribution split and a separate
  **drifted** test set, trains both approaches, and prints the comparison. With
  `--plot` it renders grouped bar charts to `out/comparison.png`.

### Reading the output
```
[centralized]
  in-distribution       DR=0.979  FAR=0.000  F1=0.989
  under concept drift   DR=0.993  FAR=0.060  F1=0.931   ← drift pushes false alarms UP
  communication (floats): 9000    ← cost of shipping all raw samples
[federated: 25 rounds]
  in-distribution       DR=0.979  FAR=0.000  F1=0.989
  under concept drift   DR=0.993  FAR=0.067  F1=0.924   ← slightly behind centralized
  communication (floats): 1400    ← only model params moved
federated / centralized comm cost: 0.156x               ← ~16% of the data movement
```
The story in three numbers: both detect well in-distribution; **drift raises the
false-alarm rate** (the "changing conditions" effect); federated gives up a sliver
of accuracy to move a fraction of the data.

### Try an experiment
In `experiments/run.py`, change the drifted test set's `drift=0.6` to `drift=1.2`
and re-run `make run`: a bigger behavioral shift should push the false-alarm rate
higher. Or lower `train_federated(rounds=25, ...)` to `rounds=5` to see accuracy
drop as the federated model gets less time to converge — the
accuracy-vs-communication knob in action.

---

## Troubleshooting

- **`ModuleNotFoundError`** — activate the venv (`source .venv/bin/activate`) and
  `pip install -r requirements.txt`, or run `make setup`.
- **`make` not found** — macOS ships `make` with the Xcode command-line tools:
  `xcode-select --install`. Or run the underlying `python3 -m ...` command the
  Makefile shows.
- **numpy warnings in Project 4** — already handled in code; if you see any,
  they're the harmless macOS BLAS FP-flag artifacts noted above, not real errors.
- **FastAPI/uvicorn install (Project 2)** — needs network access the first time to
  download the packages; after that it runs fully offline.
- **Generated folders** (`out/`, `.venv/`, `__pycache__/`, `.pytest_cache/`) are
  all in each project's `.gitignore`, so they won't end up in your repo.

## A good way to study each project

1. Run `make test` — confirm it's green.
2. Run the main demo (`make eval` / `make run` / `make tamper`) and read the output
   against the "Reading the output" section above.
3. Open the one file that *scores* the project (`harness/evaluate.py`,
   `authz_tests/runner.py`, `tamper/experiments.py`, `experiments/run.py`) — that's
   where the "how do we know it works" logic lives.
4. Do the "Try an experiment" tweak and re-run to see a number move.
5. Read that project's `README.md` "Extending it" section for next steps.
