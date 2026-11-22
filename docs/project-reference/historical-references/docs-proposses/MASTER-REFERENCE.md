# SENTINELX — Document de référence maître

**Révision : 2026-11-10 — Synchronisé avec ARENA.md révision 13.**
**Autorité : ce document est la référence officielle du produit pour tous les agents.**
**Pour les décisions de conception détaillées et spécifications complètes de T23-B : voir `ARENA.md` (révision 13) disponible dans les téléchargements du propriétaire.**

---

## 1. Contexte produit

**SentinelX** est une plateforme open-source d'audit cybersécurité en Python. Le produit V1, **NetLab**, est un outil CLI d'audit réseau cross-platform (Windows + Linux).

**Principe fondateur :** comprendre une attaque est le prérequis pour s'en défendre. Chaque fonctionnalité offensive est associée à sa contrepartie défensive — commande d'attaque, technique de détection, méthode de remédiation.

**Pipeline central :** `DISCOVER → DETECT → ASSESS → EXPLAIN → LEARN → REMEDIATE → VERIFY`

**Stack technique :** Python 3.11+, Typer (CLI), Rich (affichage), SQLite (stdlib `sqlite3`), nmap + enum4linux-ng (outils externes, venv séparé), Jinja2 (rapports).

**Avis légal :** SentinelX est conçu exclusivement pour les réseaux et systèmes que vous possédez ou avez autorisation écrite explicite de tester.

---

## 2. État réel du dépôt

```
Dépôt    : /home/anonymous/sentinelX
Branche  : a4-arena
HEAD     : 365749878aa3e886da9cd33c2322fb75277c16ce  (T23-B, commit Arena)
Tests    : 2024–2026 passed à HEAD 3657498 (2 tests lifecycle flaky sous forte charge CPU — passent en isolation)
Deps     : paramiko 5.1.0, smbprotocol 1.17.0 (installés dans venv principal)
```

**Modifications locales non commitées :**
- `cli.py` — colonne Confidence dans les tables Security Findings (Confidence CLI, 14/14 tests ✓)
- `tests/test_cli.py` — tests correspondants

**Fichiers non suivis (préservés) :** `.vscode/`, `cli.py.rej`

**Sauvegardes Git conservées :**
```
refs/tags/backup/pre-centralisation-verified         → d2aa8a2
refs/tags/backup/pre-centralisation-20261031-121431  → d2aa8a2
refs/heads/backup-a4-arena-d2aa8a2                   → d2aa8a2
```

**Note SSH :** les tests `test_ssh_creds.py` nécessitent `umask 022`. L'umask système `002` provoque 4 échecs de permissions du trust store. Comportement connu, non bloquant.

---

## 3. Bases SQLite — distinction critique

| Base | Chemin | Identifiant | Rôle |
|---|---|---|---|
| Sessions NetLab | `~/.netlab/sessions/<session_id>.db` | `session_id` (ex. `session-79adb9b2`) | Findings d'audit, assets, session d'audit |
| Sentinel | `~/.netlab/sentinel/<network_id>.db` | `network_id` (hash 12 chars, ex. `4e62187d8d56`) | Baseline, events, sentinel_state, control |

🔒 `session_id` ≠ `network_id`. Les fonctions `sentinel_*` dans `core/database.py` utilisent `network_id` ; les autres utilisent `session_id`. Ne jamais confondre.

---

## 4. Règles architecturales non négociables

1. `ZERO print()` dans les modules → `core/logger.py::display()`
2. `ZERO import sqlite3` hors `core/database.py`
3. `ZERO calcul risk_score` hors `core/risk_scorer.py`
4. Confirmation `(y/n)` avant toute action réseau active
5. `List[Finding]` en retour des modules scanners
6. Toujours typer les fonctions (paramètres + retour)
7. README pédagogique par module (français)
8. `Finding` est le contrat central — tout module produit des `Finding`

---

## 5. Décisions verrouillées

Ces décisions sont closes et ne peuvent être remises en question sans autorisation explicite du propriétaire.

| Décision | Statut |
|---|---|
| DQ-01 : VERIFIED exclu du score courant | Fermée (steering §H, aucun code) |
| DQ-02 : `device_fingerprint` hors VERIFY/scoring | Implémentée (T09) |
| DQ-SMB : enum4linux-ng venv séparé | Implémentée (T14) |
| DQ-SMB-share : writable HIGH/PROBABLE (anon), MEDIUM/PROBABLE (auth) | Implémentée (T19) |
| T23-B : 5 nouveaux types sans Finding (4 observations + 1 interne) | Verrouillée |
| T23-B : ICMP seul jamais preuve d'absence | Verrouillée |
| T23-B : `SERVICE_CHANGED` exclu | Verrouillée |
| T23-B : `new_port` HIGH provisoire | Verrouillée |
| T22 scope V1 : FTP, SNMP, SSH-password, SMB | Verrouillée |
| T21 critère 7 : colonne `Target` → `Port`, IP portée par l'en-tête de groupe | Déviation acceptée (2026-11-08) |

---

## 6. Feuille de route — statuts

### 6.1 Tickets livrés

Les statuts ci-dessous sont établis à partir de `git log`, `git show --stat`, et tests exécutés. Une validation indépendante critère par critère n'a pas été effectuée par un tiers sauf mention contraire.

| Ticket | Commit(s) | Contenu | Preuves |
|---|---|---|---|
| T17 | `1bcb25e` | README `netlab findings rescan` | git show --stat |
| T16 | `97f644b` | KB lookup CVE-specific | git show --stat |
| P2-3 + T12 | `3a5ef3a` | CLI standalone + suggestions | git show --stat |
| T14 | `e6ff855` | Migration smb_enum → enum4linux-ng | git show --stat |
| T18 | `545708d` | OS device_fingerprint → CVE matching | git show --stat |
| T19 | `9a5dbbf` | SMB enrichment (writable/users/policy) | git show --stat |
| fix | `1de5cd7` | CLI "Global score" → "Worst Current Threat" | git show --stat |
| logo | `fb42dae` | Rapport logo SentinelleX.png | git show --stat |
| T23-A | `d5459d3`, `a4ee6a6`, `016df75` | Monitor UX plain-log + progress line | git show --stat |
| D1–D4 | `d2aa8a2` | Event persistence reliable | git show --stat |
| B1–B7/C1 | `c80acf6`, `4bc4d5a`, `1ee02c9` | Baseline learning/relearn reliable | git show --stat |
| T26 | `ec1d6a2`, `8288cee` | python-whois 0.9.6 + WHOIS/RDAP structuré | git show --stat |
| T21 | `5e2be6b` | `findings list` groupé par machine (déviation critère 7 acceptée, voir §5) | git show --stat, tests `test_cli.py` section T21 |
| T23-B | `3657498` | Extension détections Sentinel (spec ARENA.md §9, révision 12) | Commit + push + revue Kiro. Tests : 2024–2026 passed. Non re-vérifié par tiers. |

### 6.2 Tickets partiellement livrés — validation critère par critère nécessaire

#### T24 — `dns_enum` + `passive_recon` corrections

**Code livré par `cf5d821` :** corrections evidence.command, RDAP, `rdap.py`, `registration.py`, CLI, `dependencies.py`, `vulnerabilities.json`. Tests : `test_dns_enum.py`, `test_passive_recon.py`, `test_rdap.py`, `test_registration.py`, `test_t24_recon_cli.py`.

**Critères d'acceptation non encore vérifiés indépendamment :**
- `evidence.command` reflète le mécanisme réel (dnspython, pas `dig`)
- WHOIS structuré orienté SOC/pentest — dump brut dans `evidence.raw`
- `Confidence` → `PROBABLE` si résultat non autoritaire
- `Exposure` données DNS publiques → `EXTERNAL`
- `passive_recon` : filtrage réseau rigoureux, IPv6 système exclue, ARP stale → `PROBABLE`
- `avahi-browse` documenté comme émettant du trafic mDNS

#### T25 — Multi-host : 1 confirmation par opération

**Code livré par `f87b140` :** `_confirm_batch_scan(module, ips, ports, profile)` — 1 consentement par module scanner. `--yes` court-circuite tout. Tests : `test_scan_confirmations.py` (238 lignes).

**Critères d'acceptation non encore vérifiés indépendamment :**
- 1 confirmation par opération réseau (DISCOVER / TCP / UDP), pas par hôte
- `--yes` inchangé

#### T22 — Credentials (périmètre V1 approuvé)

**Périmètre V1 approuvé :** FTP, SNMP, SSH (mot de passe uniquement), SMB.

| Protocole | Commit | Implémentation | Tests |
|---|---|---|---|
| FTP | pré-existant | `_check_ftp_defaults` via `ftplib` | `test_default_creds.py` |
| SNMP | pré-existant | `_check_snmp_defaults` via SNMPv1 GET raw | `test_default_creds.py` |
| SSH (password only) | `fafd5ff` | `_ssh_session` via `paramiko` | `test_ssh_creds.py` (893 lignes) |
| SMB | `6ad9a86` | session auth via `smbprotocol` | `test_smb_creds.py` (624 lignes) |

**Hors périmètre V1 (volontairement non implémentés) :** Telnet, HTTP/HTTPS, RDP, clés SSH.

**Incertitude :** les tests SSH nécessitent `umask 022` — comportement rapporté par Kiro, pas validé par tiers.

### 6.3 Tickets non implémentés

| Ticket | Titre | Dépendances | Spec |
|---|---|---|---|
| **T20** | Rapport HTML — refonte présentation | — | Approuvée (voir §7) |

### 6.4 Tâches locales en attente de commit

| Tâche | Fichiers | État |
|---|---|---|
| Confidence CLI | `cli.py`, `tests/test_cli.py` | Modifié local, 14/14 tests ✓, commit en attente d'autorisation |

### 6.5 Proposition d'ordre de la feuille de route

```
Confidence CLI (commit) → T20
```

🔒 Proposition uniquement. T24 et T25 partiellement livrés — leur validation finale peut s'insérer à tout moment selon la décision du propriétaire. Aucune réorganisation sans autorisation explicite.

---

## 7. T20 — Spécification détaillée (approuvée)

### 7.1 Objectif

Refonte du rapport HTML comme vraie interface de restitution, groupée par machine, pas simple liste plate.

### 7.2 Fichiers concernés

| Fichier | Modification |
|---|---|
| `reports/templates/report.html` | Structure réorganisée, CSS palette rouge/noir/blanc, JS Top 5 + Voir plus, dark/light |
| `reports/generator.py` | Calcul nouveaux indicateurs, `findings_by_host` passé au template |

### 7.3 Structure HTML cible

```
SYNTHÈSE (Section 01)
  Worst Current Threat (existant, gauge SVG)
  Bloc indicateurs :
    Highest Severity | Targets with open findings | Assessment Completeness
    Discovery State  | Priority Target            | Main Open Problems
  Summary cards (existant)

SESSION (Section 02) — inchangé
NETWORK OVERVIEW (Section 03) — inchangé

PAR MACHINE (Section 04)
  Pour chaque IP :
    Security Findings (Top 5 + Voir plus)
    Inventory Observations
    Recommendations (Top 5 + Voir plus)

SCORING FORMULA (bas de page, inchangé)
```

### 7.4 Indicateurs à calculer dans `generator.py`

```
highest_severity
targets_with_open_findings
assessment_completeness
discovery_state
priority_target
main_open_problems
findings_by_host   # Dict[ip → List[Finding]] trié sévérité décroissante
```

Contrat existant préservé : `worst_current_threat`, `summary`, `formula`, `logo_filename`, `host_map` inchangés.

### 7.5 CSS et branding

- `--accent` : `#e02020` (rouge SentinelX, couleur d'identité)
- Badges severity : Critical garde `#ff3b3b`, séparé de l'accent branding
- `SENTINEL` taille normale, `X` : `font-size: 1.2em`, couleur rouge
- Logo existant conservé

### 7.6 Critères d'acceptation T20

| # | Critère |
|---|---|
| 1 | Findings groupés par machine (séparation visuelle nette) |
| 2 | 7 indicateurs synthèse visibles sans scrolling excessif |
| 3 | `Main Open Problems` présent dans la synthèse |
| 4 | Top 5 Findings + "Voir plus" par machine |
| 5 | Top 5 Recommendations + "Voir plus" par machine |
| 6 | Ligne Finding cliquable → détails inline |
| 7 | `SENTINEL X` avec X plus grand et rouge |
| 8 | Palette rouge/noir/blanc, rouge = couleur d'identité |
| 9 | Dark/light : basculer, contraste vérifié dans Firefox |
| 10 | Rouge = identité branding, badges severity indépendants |
| 11 | JSON report inchangé (mêmes clés) |
| 12 | `worst_current_threat`, `scoring_formula`, `logo` toujours présents |
| 13 | T10 (Worst Current Threat) préservé |

### 7.7 Exclusions T20

- ❌ Modification du contrat de données JSON
- ❌ PDF (hors scope V1)
- ❌ Nouvelle page ou navigation externe

### 7.8 Vérification T20

```bash
venv/bin/python cli.py report generate --session <id> --format html
grep -c "priority_target|main_open_problems|Inventory Observations" rapport.html
venv/bin/python cli.py report generate --session <id> --format json  # inchangé
venv/bin/python -m pytest tests/test_reports.py
# Visuel Firefox : dark/light, rouge, X, sections par machine, Top 5 + Voir plus
```

---

## 8. T21 — Implémenté (commit `5e2be6b`)

Statut : **implémenté**. Déviation du critère 7 acceptée par le propriétaire (2026-11-08) — voir §5.

`findings list` groupé par machine dans le terminal, avec blocs Security Findings / Inventory Observations séparés. `device_fingerprint` dans Inventory Observations uniquement, jamais dans Security Findings, jamais présenté comme problème.

Colonnes Security Findings : `ID | Severity | Module | Port | Service | Status | Score`.
Colonnes Inventory Observations : `ID | Observation | Detail | Confidence` (sans sévérité, score, statut).

---

## 9. T23-B — Implémenté (commit `3657498`)

Statut : **implémenté et clôturé** (commit Arena `3657498`, revue Kiro, 2026-11-10).

Spécification complète, critères d'acceptation et décisions de révision 12 (B1/B2/B3) : voir `ARENA.md` révision 13 (disponible dans les téléchargements du propriétaire), §9.

**Résumé :** extension de Sentinel avec 5 nouveaux types sans Finding (4 observations + 1 interne), correction des types `new_host` et `new_port`. Horodatage strictement croissant par réseau (B1). Notifications sans Finding avec identité `event_id` (B2). `scan_degraded` à portée réseau (B3).

**Réserves acceptées :**
- `host_ports_initialized` utilise `state="whitelisted"` pour contourner le quota (solution propre reportée)
- `_classify_host` ne vérifie pas le champ `dev` explicitement (amélioration secondaire différée)

---

## 10. Périmètre V1 — ce que V1 N'EST PAS

- ❌ Imports AI (`openai`, `groq`, `anthropic`) — V2
- ❌ REST API — V2
- ❌ Auto-fix / fermeture de port — V2
- ❌ GUI — V3
- ❌ Comptes utilisateurs — V3
- ❌ Agents distribués — V4
- ❌ SIEM, EDR, machine learning, cloud
- ❌ PDF export — V2 (utiliser HTML + impression navigateur)
- ❌ Global Risk Score composite réseau — hors V1 (steering §H)

---

## 11. Procédure de validation standard

```bash
TESTHOME=$(mktemp -d /tmp/sentinelx-test-XXXXXX)
cd /home/anonymous/sentinelX
HOME=$TESTHOME SENTINEL_TEST_EXECUTABLE=/home/anonymous/sentinelX/venv/bin/sentinel \
  bash -c "umask 022 && venv/bin/python -m pytest --tb=short -q"
git diff --check
git rev-parse HEAD
git status --porcelain=v1 | grep -v "^??"
```

---

## 12. Autorité et provenance

**Autorité finale sur le produit et la feuille de route : le propriétaire.**

Les agents peuvent examiner le dépôt, implémenter une tâche autorisée, vérifier les tests, actualiser les preuves. Ils ne peuvent pas décider seuls de modifier le périmètre V1, changer l'architecture, modifier une décision approuvée, changer l'ordre de la feuille de route, ou ajouter / supprimer / annuler une tâche.

**Provenance des vérifications :** `git rev-parse HEAD`, `git log`, `git show --stat`, `grep -n` sur les sources, `pytest` (HOME isolé, umask 022). Ces vérifications ne constituent pas une validation indépendante. Présence d'un commit ≠ ticket terminé — il faut comparer au critères d'acceptation. C'est particulièrement important pour T24, T25 et T22.

**Suivi opérationnel des tâches :** voir `docs/IMPLEMENTATION-TRACKING.md`.
