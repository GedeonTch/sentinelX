# SentinelX — Kiro Steering Document v1.1

> **Rule #0 for Kiro and Cursor**: Do not try to impress the project owner.
> Build exactly what is specified, in a testable, understandable and verifiable way.
> If an implementation requires changing the architecture, data model, pipeline,
> scope, or any mandatory rule — STOP and request explicit approval before proceeding.

---

## A. Vision SentinelX

SentinelX is an open-source educational cybersecurity platform built in Python. It teaches offensive and defensive network security techniques through a real tool running on a controlled lab environment.

**Core principle**: understanding how an attack works is the prerequisite for knowing how to defend against it. Every offensive feature is paired with its defensive counterpart — attack command, detection technique, remediation method.

**LEGAL NOTICE**: SentinelX is designed exclusively for networks and systems you own or have explicit written authorization to test. Any other use is illegal.

### The Four Products

| Product | Version | Keyword | CLI Command | Status |
|---|---|---|---|---|
| NetLab | V1 | Audit | `netlab scan` / `netlab sentinel` | In development |
| Insight | V2 | Understand | `insight scan` / `insight learn` | Planned after V1 |
| Nexus | V3 | Centralize | `nexus gui` / `nexus api start` | Planned after V2 |
| Enterprise | V4 | Distribute | Agent Windows / Agent Linux / Probe | Future vision |

V4 Enterprise = central Manager + lightweight agents on each machine + network probes. Distributed SOC architecture. **Not part of current development.**

---

## B. Non-Negotiable Project Principles

These principles are above all implementation details. If any decision conflicts with them, implementation must change — not the principles.

1. **NetLab V1 is deterministic.** No AI decides that a vulnerability exists.
2. **A Finding must be justifiable by evidence.** No finding without proof.
3. **AI explains — it never detects or scores.** Detection is rules-based. AI comes after.
4. **A feature is not done until the developer understands it.** Code + tests + README read + can explain.
5. **Kiro never expands scope without explicit approval.** Ask before changing architecture.
6. **Security over convenience.** Never skip a confirmation prompt for speed.
7. **Implementation details may evolve** if they preserve architectural principles and are explicitly approved.

---

## C. The Central Pipeline

```text
DISCOVER → DETECT → ASSESS → EXPLAIN → LEARN → REMEDIATE → VERIFY
```

| Step | Role | Main V1 Modules |
|---|---|---|
| DISCOVER | Identify assets and exposed services | `device_fingerprint`, `dns_enum`, `passive_recon` |
| DETECT | Find weaknesses and misconfigurations | `tcp_scan`, `udp_scan`, `smb_enum`, `misconfig_detection`, `default_creds` |
| ASSESS | Calculate risk score for each Finding | `risk_scorer` (documented CVSS-based formula) |
| EXPLAIN | Produce 3-angle explanation | Local knowledge base (AI in V2 only) |
| LEARN | Train the user interactively | AI-guided Learning Zone — V2 only |
| REMEDIATE | Apply corrections | Manual (V1) / Auto-fix bash scripts (V2+) |
| VERIFY | Rescan and confirm the fix | `netlab rescan --session <id>` |

---

## D. V1 Scope — Explicit Boundaries

### What V1 IS

- CLI audit tool, cross-platform Windows + Linux
- Network discovery + port scanning + service detection
- CVE lookup from local knowledge base
- Risk scoring with documented formula
- Basic Sentinel: baseline learning + simple network change detection (new port, ARP change)
- PDF / HTML / JSON report generation
- Lab cleanup (artifact detection + restore)
- `netlab doctor` environment verification

> **V1 Sentinel clarification**: Sentinel Core = baseline + detection of simple network changes (new port, MAC change, new host). NOT behavioral analysis. NOT EDR. NOT CrowdStrike. Simple, deterministic, rule-based only.

### What V1 is NOT — Explicitly Out of Scope

- No AI imports (`openai`, `groq`, `anthropic`, `google.generativeai`) — V2
- No REST API — V2
- No auto-fix / port closing — V2 (requires bash integration)
- No GUI — V3
- No user accounts — V3
- No distributed agents — V4 Enterprise
- No SIEM, no EDR, no machine learning, no cloud

> **Rule**: No new feature can be added while the current ticket is not finished, tested, README read, and understood by the developer.

---

## E. Tech Stack

- **Language**: Python 3.10+, cross-platform Windows + Linux
- **Low-level Linux tasks**: Bash scripts in `scripts/` only — called via subprocess
- **CLI**: Typer — never argparse, never click
- **Terminal display**: Rich — never `print()` directly in a module
- **Persistence**: SQLite via stdlib `sqlite3` — `~/.netlab/sessions/<session_id>.db`
- **External tools**: nmap, enum4linux — checked by `netlab doctor` at startup
- **Code language**: English (all code, variables, functions, comments, commits)
- **Pedagogical READMEs**: French (for the developer's learning)

---

## F. Absolute Architectural Rules

> ⛔ These rules cannot be bypassed.
> If a ticket seems to violate them, Kiro must STOP and request approval.

### Layer Separation

| Layer | What it does | What it NEVER does |
|---|---|---|
| Modules (scanners) | Produce Finding objects | Touch SQLite, calculate score, `print()` |
| `core/risk_scorer` | Calculate `risk_score` | Scan, write to DB, display |
| `core/database` | Read / write SQLite | Business logic, calculation, display |
| `cli.py` | Format user input/output | Contain any business logic |
| `reports/` | Generate PDF / HTML / JSON | Scan, calculate, modify the database |
| `scripts/*.sh` | Low-level Linux tasks only | Business logic, data manipulation |

### Mandatory Code Rules

- NEVER `print()` in a module — use Rich via `core/logger.py`
- NEVER `import sqlite3` outside `core/database.py`
- NEVER calculate `risk_score` outside `core/risk_scorer.py`
- NEVER run an active network action without explicit `(y/n)` confirmation
- NEVER delete a file in `restore.py` without verifying `session_id` ownership
- ALWAYS type Python functions — parameters and return value
- ALWAYS return `List[Finding]` or `Finding` from scan functions
- ALWAYS produce a pedagogical `README.md` with every module

---

## G. The Finding Model (Central Contract)

Every scan module MUST return `Finding` objects. This is the only format accepted by Core. No exceptions.

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
import uuid, datetime


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    CONFIG = "config"
    SERVICE = "service"
    NETWORK = "network"
    CREDENTIAL = "credential"
    TRACE = "trace"


class Confidence(float, Enum):
    """Hérite de float — reste directement utilisable comme facteur
    dans risk_scorer.py (Confidence.CONFIRMED * base_severity marche
    tel quel), tout en empêchant une valeur invalide comme 0.9."""
    CONFIRMED = 1.00
    PROBABLE = 0.85
    POSSIBLE = 0.60


class Exposure(str, Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"


class FindingStatus(str, Enum):
    OPEN = "open"
    VERIFIED = "verified"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"


@dataclass
class Evidence:
    raw: str = ""              # sortie brute de la commande — jamais interprétée ici
    command: str = ""          # commande exécutée pour l'obtenir


@dataclass
class Explanation:
    what: str = ""
    attack: str = ""
    defense: str = ""


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    module: str = ""           # e.g. "smb_enum", "tcp_scan", "default_creds"
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    target_ip: str = ""
    target_port: Optional[int] = None
    target_service: str = ""
    service_version: str = ""
    category: Category = Category.CONFIG
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.PROBABLE
    exposure: Exposure = Exposure.INTERNAL
    evidence: Evidence = field(default_factory=Evidence)
    explanation: Optional[Explanation] = None   # None = pas encore documenté (voir base de connaissances)
    cve_refs: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    risk_score: Optional[float] = None  # set by risk_scorer only — never manually
    status: FindingStatus = FindingStatus.OPEN
    remediation_cmd: str = ""   # V2: bash command for auto-fix
```

### Evidence → Confidence → Finding Chain

```text
Discovery
    ↓
Identification (banner, version, behavior)
    ↓
Evidence (raw proof stored in evidence field)
    ↓
Vulnerability matching (CVE lookup from local DB)
    ↓
Confidence assignment (1.0 / 0.85 / 0.60)
    ↓
Finding created
```

> **Critical rule**: `banner says Apache 2.4.x` ≠ `Apache vulnerability confirmed`
> A Finding requires evidence. A CVE ref requires version confirmation.
> No vulnerability claim without sufficient evidence.

### Confidence Rules

| Value | When to use | Example |
|---|---|---|
| 1.0 Confirmed | Direct observation, tangible proof | Open port confirmed, TCP handshake |
| 0.85 Probable | Strong deduction, banner grabbing | Version inferred from HTTP/SSH banner |
| 0.60 Possible | Estimation, behavioral fingerprint | OS estimated by TTL and TCP behavior |

If `confidence < 0.7` → Finding displayed in grey, marked "unconfirmed", excluded from global score calculation.

---

## H. Scoring Formula — Never a Black Box

```text
risk_score = min(100, base_severity × confidence_factor × exposure_factor)
```

- **Base**: CVSS × 10 if known — otherwise Critical=90, High=70, Medium=45, Low=20, Info=5
- **Confidence**: Confirmed ×1.00 · Probable ×0.85 · Possible ×0.60
- **Exposure**: External ×1.15 · Internal ×1.00
- **Global network score** = worst open Finding — never an average
- **Coefficients** stored in `config.yaml` — modifiable, tested on 5+ real cases before release
- **Formula** always appears in every generated report

---

## I. SQLite Schema

One file per session: `~/.netlab/sessions/<session_id>.db`
Only `core/database.py` is authorized to import `sqlite3`.

| Table | Key Fields | Role |
|---|---|---|
| `assets` | id, ip, mac, hostname, os, first_seen, active | Network device inventory |
| `sessions` | id, start_time, end_time, target, profile, status, notes | One session = one full audit |
| `findings` | id, session_id, asset_id, module, category, severity, cvss, confidence, exposure, score, status, evidence, explanation, remediation_cmd, cve_refs | Core of the system |
| `baseline` | id, asset_id, ports, services, mac, gateway, dns, last_scan | Sentinel normal state |
| `events` | id, timestamp, type, asset_id, details, resolved | Sentinel detected events |

---

## J. Lab Cleanup — `restore.py` Functional Definition

```text
Name        : Lab State Cleanup
File        : 06_cleanup/restore.py

Input       : session_id (current session only)

Step 1 — Detect
    Find all artifacts created or modified by NetLab
    during the current session (from session log)

Step 2 — Validate ownership
    Every artifact must belong to session_id
    Any artifact outside session scope → skip, log warning

Step 3 — Preview
    Display complete list of artifacts to be removed
    User must type "yes" in full to confirm

Step 4 — Action
    Remove / revert only NetLab-owned artifacts

Step 5 — Verify
    Confirm artifact no longer exists

Constraints:
    NEVER revert a security fix applied by the user
    NEVER touch files outside ~/.netlab/ and /tmp/netlab-<session_id>/
    Unit tests MANDATORY before integration
    Uses "yes" typed in full — never just "y"
```

---

## K. Sentinel Baseline Whitelist

```yaml
# ~/.netlab/baseline_whitelist.yaml
allowed_new_macs: []
allowed_port_changes:
  - host: 192.168.1.10
    ports: [8080]
allowed_new_hosts: []
sentinel_max_alerts_per_hour: 3   # beyond this → silent mode
```

---

## L. CLI Commands — V1 NetLab

```bash
netlab doctor
netlab scan --target 192.168.1.0/24 --profile normal
netlab scan --target 192.168.1.45 --profile stealth
netlab scan --target 192.168.1.45 --profile aggressive
netlab findings list --session S001
netlab findings show 1
netlab findings explain 1
netlab findings rescan --session S001
netlab sentinel start
netlab sentinel status
netlab sentinel stop
netlab report generate --session S001 --format pdf
netlab report generate --session S001 --format html
netlab report generate --session S001 --format json
netlab cleanup --session S001
netlab cleanup --sessions --older-than 30d
netlab config set lab.scope 192.168.1.0/24
netlab config show
netlab --version
```

---

## M. Development Order — 20 Tickets

| Ticket | File | Why This Priority |
|---|---|---|
| #001 | `core/finding.py` | Central contract — everything depends on it ✅ |
| #002 | `core/database.py` | SQLite persistence — pipeline needs it between calls |
| #003 | `core/dependencies.py` + `netlab doctor` | Environment check before first real scan |
| #004 | `core/risk_scorer.py` | ASSESS — tested on 5+ real cases before use |
| #005 | `cli.py` | Typer structure — connects all modules |
| #006 | `01_recon/device_fingerprint.py` | DISCOVER — first pipeline step |
| #007 | `01_recon/dns_enum.py` | DISCOVER — WHOIS + DNS records |
| #008 | `01_recon/passive_recon.py` | DISCOVER — no active traffic |
| #009 | `02_detect/tcp_scan.py` + `udp_scan.py` | DETECT — core value |
| #010 | `02_detect/service_detection.py` | DETECT — versions for CVE matching |
| #011 | `02_detect/smb_enum.py` | DETECT — Windows shares (use Grok in Cursor) |
| #012 | `02_detect/misconfig_detection.py` | DETECT — misconfigured services |
| #013 | `02_detect/default_creds.py` | DETECT — default credentials |
| #014 | `knowledge/ports.json` | Fingerprinting — identify service/version (Cursor) |
| #015 | `knowledge/vulnerabilities.json` | Explanation rules — {what, attack, defense} per detection rule |
| #016 | `04_sentinel/` (5 files) | Sentinel Core — baseline + monitoring |
| #017 | `reports/generator.py` | PDF/HTML/JSON export |
| #018 | `06_cleanup/artifact_detector.py` | Lab hygiene |
| #019 | `06_cleanup/restore.py` | Unit tests MANDATORY before integration |
| #020 | V1 unit tests (complete) | V1 completion criterion |

> **Responsibility split for #014 vs #015**:
> `ports.json` (#014) = identification — which service, which version. Cursor, no Kiro spec.
> `vulnerabilities.json` (#015) = interpretation — which explanation for which detected rule. Kiro spec required.

---

## N. Module Responsibilities

| Module | Model (Auto recommended) | Specific Constraint |
|---|---|---|
| `core/finding.py` | Most powerful | Zero external dependency |
| `core/database.py` | Most powerful | Only file authorized to import sqlite3 |
| `core/risk_scorer.py` | Most powerful | Only file that calculates risk_score |
| `core/dependencies.py` | Fast | Simple checks — no business logic |
| `cli.py` | Most powerful | Typer only — zero business logic |
| `01_recon/*.py` | Most powerful | Return `List[Finding]` — never `print()` |
| `smb_enum.py` | Grok in Cursor | Test on Windows VM mandatory |
| `default_creds.py` | Fast | Dictionary lookup — y/n confirmation mandatory |
| `04_sentinel/*.py` | Most powerful | Never modifies system configuration |
| `restore.py` | Most powerful | Unit tests MANDATORY — waits for "yes" in full |
| `reports/generator.py` | Most powerful | Always includes scoring formula |
| MITM Lab (V2) | Grok in Cursor | Wireshark capture mandatory for validation |

> ⛔ NEVER use a lightweight model on:
> `restore.py`, `risk_scorer.py`, `core/finding.py`, `core/database.py`

---

## O. Workflow — Kiro + Cursor

### Kiro — Spec Before Code

Use Kiro for complex modules: Sentinel, MITM Lab (V2), `smb_enum`, Learning Zone (V2), `restore.py`.

For each complex module, Kiro must produce:

1. `requirements.md`
2. `design.md`
3. `tasks.md`
4. `README.md` (pedagogical — explains concepts, not just code)

**Always read and validate the spec before approving code.**

### Cursor — Code and Integration

Use Cursor directly (without Kiro spec) for:

- `default_creds.py`
- `knowledge/ports.json`
- `netlab doctor`
- bug fixes
- refactoring

### Claude — Architecture and Review

Use Claude (chat) for:

- Architectural decisions when in doubt
- Code review when something feels wrong
- Explaining concepts from the pedagogical README

---

## P. Ticket Format

### Structure

```text
Ticket #XXX — <filename>
─────────────────────────────────────────
Objective    : One sentence — what this file/function must do
Input        : Parameters (typed)
Output       : Return value (typed — e.g. List[Finding])
Test nominal : Normal case verification
Test edge    : Limit case + error case
Constraints  : What is forbidden in this file
README       : Concepts to explain in the pedagogical README
```

### Example — TICKET #001

```text
Ticket #001 — core/finding.py
─────────────────────────────────────────
Objective    : Create the Finding dataclass with all fields
               from Section G + to_dict() method
Input        : none (class definition)
Output       : Finding class importable from any module
Test nominal : Finding(module="tcp_scan", target_ip="192.168.1.1",
               severity=Severity.HIGH, confidence=Confidence.PROBABLE)
               → to_dict() returns a valid JSON-serializable dict
Test edge   : confidence=Confidence.POSSIBLE (0.60) → risk_score must remain None
               (not calculated here)
Constraints  : ZERO import sqlite3 / ZERO import cli / ZERO print()
README       : Explain vulnerability vs exposure, CVE, CVSS,
               confidence, finding lifecycle
```

---

## Q. Testing Strategy

### Test Types Required

| Type | What it covers |
|---|---|
| Unit | Single function, mocked dependencies |
| Integration | Module + database + real Finding flow |
| CLI | Command output and exit codes |
| Lab | Real scan on authorized lab network |
| Negative | Closed port not reported, low confidence excluded |
| Regression | Previous behavior preserved after changes |

> **Important**: A security detection feature cannot be validated only because its unit tests pass. Lab tests on real targets are mandatory.

### Example — `tcp_scan.py` Tests

```text
Unit        → parser correctly builds Finding from raw scan output
Integration → nmap subprocess called correctly, Finding stored in DB
Lab         → known open port detected on lab VM
Negative    → closed port not reported as open
Regression  → adding udp_scan doesn't break tcp_scan results
```

---

## R. Definition of Done — Per Ticket

A ticket is DONE only when ALL of these are checked:

```text
[ ] Code implemented and runs without error
[ ] Unit tests pass
[ ] Edge case tested
[ ] Error case tested
[ ] No architectural rule violated (grep check: no print(), no sqlite3 outside DB)
[ ] README.md generated by Kiro/Cursor
[ ] README read by developer
[ ] Developer can explain the implementation without looking at the code
[ ] Git diff reviewed by developer
[ ] Kiro approved to move to next ticket
```

**Additional rule for detection modules** (#009 to #013, #016):
A detection module cannot be marked DONE until every detection rule it introduces
has a corresponding entry in `knowledge/vulnerabilities.json` with its `{what, attack, defense}` triplet.
No orphan Finding without a matching explanation rule.

---

## S. Integration Checklist for External Code

Before integrating any module from Grok or external source:

```text
[ ] No direct print()
[ ] No import sqlite3
[ ] Returns List[Finding] or Finding
[ ] Confirmation (y/n) before any active network action
[ ] Pedagogical README present
[ ] Evidence field populated — not empty
[ ] confidence value set and justified
```

---

## T. V1 Completion Criteria

V1 is done when AND ONLY WHEN all of these pass:

**Functional**

- [ ] NetLab detects something → proves why (non-empty evidence)
- [ ] Confidence level documented and justified
- [ ] Risk calculated by transparent formula (`risk_score` by `risk_scorer`)
- [ ] Results persist between commands (SQLite `session_id`)
- [ ] Rescan shows what changed (status `VERIFIED`)
- [ ] PDF/HTML report generated, JSON export working
- [ ] Sentinel detects ARP change and new port without false positive on lab network

**Technical**

- [ ] `restore.py` passes all unit tests
- [ ] No module contains direct `print()` — verified by grep
- [ ] No module outside `core/database.py` imports `sqlite3` — verified by grep
- [ ] Every module has its README read and understood by developer
- [ ] `netlab doctor` passes without error on Linux AND Windows
- [ ] Scoring coefficients tested on minimum 5 real cases

---

## U. The Completion Rule

> A feature is not done when the AI has finished coding.
> It is done when:
> - the code is tested
> - the README is read
> - the developer understands what was built and can explain it

---

*SentinelX Steering Document v1.1 — August 2026*  
*NetLab → Insight → Nexus → Enterprise*  
*First a tool. Then intelligence. Then a platform. One day, a SOC.*
