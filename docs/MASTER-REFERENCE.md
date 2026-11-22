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
Dépôt    : $SENTINELX_REPO
Branche  : a4-arena
HEAD     : 9034f0131ebeaf63dc51bf217cea3ec3f6ab068e  (origin/a4-arena, ticket 4 ; T23-B = 365749878aa3e886da9cd33c2322fb75277c16ce)
Tests    : 2024–2026 passed à HEAD 3657498 (2 tests lifecycle flaky sous forte charge CPU — passent en isolation) ; 2083 passed à HEAD 9034f01 (ticket 4, mesure de l'agent, non revue par tiers)
Deps     : paramiko 5.1.0, smbprotocol 1.17.0 (installés dans venv principal)
```

**Modifications locales (non vérifiées) :**
- `cli.py` — colonne Confidence (Confidence CLI) : commit `85870ac` présent dans `origin/a4-arena` ; l'état du poste du propriétaire n'est pas vérifié
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

**Décisions A1 approuvées par le propriétaire** (inscription à l'Étape 0 ; plan V2.2 approuvé, DEC-02, 2026-11-13) :

| Décision | Statut |
|---|---|
| A1 : hôte absent du cycle → remise à zéro des compteurs de ses ports (V4) | Approuvée |
| A1 : fermeture individuelle après deux observations `closed` explicites consécutives, pour chaque port connu ; aucun seuil global (G-b écartée ; G-c reportée) | Approuvée |
| A1 : aucune fermeture confirmée sur passage `closed` → `filtered` | Approuvée (réserve à consigner) |
| A1 : validation XML commune au monitor et à l'apprentissage de baseline | Approuvée |
| A1 : compteurs intermédiaires non restaurés après redémarrage (R7) ; redémarrages répétés = conséquence documentée | Approuvée |
| D5-B : preuve de fermeture dans `events.details` | Conception approuvée ; implémentation non autorisée |
| D1 : distinction preuve / historique | Approuvée (forme) ; libellé ouvert (DEC-03) |
| D6 : ticket indépendant hors A1 | Approuvé ; DEC-04 examinée au moment du ticket |
| CRED-02 : absence de candidats SSH génériques | Conforme à `docs/T22-CREDENTIALS.md` ; sans ticket |
| NET-01 : réseau `192.168.57.0/24` | Non reproduit ; `--target` obligatoire ; sans ticket de code |
| ARENA §9.6 | Supersédée par la politique A1 approuvée ; `docs/MASTER-REFERENCE.md` est le document maître officiel |

**Décision DEC-05 — exécution privilégiée des commandes credentials** (décision propriétaire du 2026-11-21) :

| Élément | Décision |
|---|---|
| Décision initiale (Option B) | Refus de `creds check` lorsque l'effective UID est 0 (via `sudo` ou exécution directe en root). Le credential testing s'exécute depuis la session normale de l'utilisateur, sans élévation de privilèges. |
| Décision complémentaire | Le refus est étendu à `creds list` et `creds show`, y compris en lecture seule. |
| Condition de référence | `os.geteuid() == 0` (POSIX). La détection ne repose pas uniquement sur `SUDO_USER`/`SUDO_UID`. |
| Effet du refus | Aucun accès, lecture, déchiffrement, création ou initialisation du vault ; aucune session de credential testing ; aucune transmission de credential ; aucun accès réseau ; aucune écriture persistante ; aucune modification de baseline ou d'état. |
| Message | « Les commandes creds ne peuvent pas être exécutées avec les privilèges root. Relancez SentinelX sans sudo. » (code de sortie à préciser dans les critères d'acceptation de CRED-01). |
| Portée | Uniquement les trois commandes `creds`. `scan`, `monitor`, rapports, cleanup et autres commandes réseau restent à examiner séparément. |
| Windows | Règle POSIX uniquement ; aucune politique Administrator n'est définie par cette décision. |
| Exception root interactive | Aucune exception implicite ; toute exception nécessiterait une décision distincte. |
| Migration / stockage | Aucune migration automatique ; `NETLAB_HOME` hors V1 ; aucun changement de schéma SQLite, de format du vault, de KDF ni de verrou. |

**DEC-05 — état et questions encore ouvertes.** DEC-05 n'est **pas entièrement clôturée**. **CRED-01 est implémenté et accepté par le propriétaire avec réserves explicites** ; l'audit Arena a exécuté **533 tests ciblés réussis** (`umask 022`). **Réserves non corrigées** : tests symlink dédiés à `validate_vault_location()`, interruption/création partielle du vault, garde de `open_vault()` bas niveau, coexistence de deux résolveurs, différence `uid`/`euid` dans `_private`, suite complète du dépôt non exécutée. Aucune migration automatique ; aucun changement de schéma, KDF ou format. Points non tranchés : validation de `SUDO_USER`/`SUDO_UID` ; détection d'un ancien `/root/.netlab` sans création silencieuse d'un second vault ; comportement des autres commandes SentinelX sous `sudo` ; propriété et permissions des fichiers créés dans le home utilisateur par des commandes privilégiées ; périmètre exact du résolveur `core/user_paths.py` ; procédure manuelle de récupération d'un ancien coffre ; compatibilité Windows et éventuelle politique Administrator.

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

### 6.4 Confidence CLI (commit présent, revue non tracée)

| Tâche | Fichiers | État |
|---|---|---|
| Confidence CLI | `cli.py`, `tests/test_cli.py` | Commit `85870ac` présent dans `origin/a4-arena` (vérifié 2026-11-12) ; revue Kiro non tracée |

### 6.4bis Commits de `origin/a4-arena` non consignés (audit 2026-11-12)

| Commit | Date (git) | Sujet (git) | État consigné |
|---|---|---|---|
| `85870ac` | 2026-11-10 | feat(cli): add confidence column to findings tables | Consigné en 6.4 (CONFIDENCE-CLI) |
| `7ff3d89` | 2026-11-10 | docs: add master reference, implementation tracking and agent skill | Ajoute le document maître (version antérieure) |
| `13e7849` | 2026-11-10 | fix Commit 3657498 (`requirements.txt`, 1 ligne) | Non consigné |
| `63e1a7b` | 2026-11-10 | feat(sentinel): interrupt nmap on stop request (point 1) | Non consigné |
| `b1ab727` | 2026-11-11 | fix(sentinel): detect gateway on connected routes (point 2) | Non consigné |
| `e4f3f9e` | 2026-11-11 | feat(sentinel): colour event types and label closed ports (ticket 3) | Non consigné |
| `9034f01` | 2026-11-11 | feat(sentinel): number hosts in monitor table (ticket 4) | Non consigné (HEAD réel) |

Dates git (2026-11-10 et 2026-11-11) antérieures à la date de référence de la mission (2026-11-12). Date de rédaction de cette proposition : 2026-11-12.

### 6.5 Proposition d'ordre de la feuille de route

```
Confidence CLI (commité, `85870ac`) → T20
```

Ordre approuvé (plan v2.2, `docs-proposees/PLAN-tickets-global.md` §5, DEC-02) : Étape 0 (documentation préalable, §5.0) → SMB-01 → A1 (ticket parent unique) → CRED-01 → D5 (après A1) → D1 (après D5) ; autres tickets selon dépendances et priorité ; D6 indépendant.

🔒 Ordre validé ; aucun ticket autorisé. T24 et T25 partiellement livrés — leur validation finale peut s'insérer à tout moment selon la décision du propriétaire. Aucune réorganisation sans autorisation explicite.

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
cd $SENTINELX_REPO
HOME=$TESTHOME SENTINEL_TEST_EXECUTABLE=$SENTINELX_REPO/venv/bin/sentinel \
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
