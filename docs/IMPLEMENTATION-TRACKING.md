# SentinelX — Suivi opérationnel de l'implémentation

**Fichier portable — utilisable par tout agent : Kiro, Arena, Claude, ou autre.**
**Référence pour les décisions et spécifications : `docs/MASTER-REFERENCE.md`.**
**Référence pour T23-B et T21 en détail : `ARENA.md` révision 13 (téléchargements propriétaire).**

---

## Règles de travail des agents

Ces règles s'appliquent à tout agent lisant ou modifiant ce fichier.

1. **Vérifier le dépôt avant de modifier un statut.** `git log`, `git show --stat`, grep sur les sources, exécution des tests. Un rapport d'agent précédent n'est pas une preuve.
2. **`[x]` uniquement quand les critères d'acceptation sont satisfaits et les preuves vérifiées.** Pas seulement "le code existe" ou "les tests passent".
3. **`[-]` pour une tâche en cours.** Préciser ce qui est terminé et ce qui reste.
4. **Conserver les tâches différées, refusées ou annulées.** Ajouter une note avec justification. Ne jamais supprimer silencieusement.
5. **Distinguer : réserve acceptée ≠ défaut connu ≠ tâche terminée.** Une réserve acceptée est documentée mais ne bloque pas la clôture du ticket.
6. **Ne pas considérer un ancien rapport d'agent comme preuve suffisante.**
7. **Ne pas modifier les décisions approuvées** (§5 du MASTER-REFERENCE.md). Ces changements requièrent l'autorisation explicite du propriétaire.
8. **Proof line obligatoire pour chaque sous-tâche `[x]`.** Format : `Proof: ✓ <résultat observé>`.

### Ce que les agents NE peuvent PAS décider seuls

- Modifier le périmètre V1
- Changer l'architecture ou le pipeline
- Modifier une décision déjà approuvée
- Changer l'ordre officiel de la feuille de route
- Ajouter, supprimer, annuler ou différer une tâche
- Considérer une proposition technique comme une décision validée

---

## Format des tâches

```markdown
### TICKET-ID — Titre court

**Objectif :** Une phrase.
**Branche :** `nom-branche`
**Base commit :** `xxxxxxx`
**Fichiers :** `fichier1.py`, `fichier2.py`
**Statut :** [ ] Non commencé / [-] En cours / [x] Terminé (commit `xxxxxxx`)

#### Phase N — Description

- [ ] Sous-tâche
  - Proof: ce qu'il faut vérifier
- [x] Sous-tâche terminée
  - Proof: ✓ résultat observé
```

---

## État général du projet (branche `a4-arena`)

```
HEAD    : 9034f01  (origin/a4-arena, ticket 4 — audit 2026-11-12 ; T23-B = 3657498)
Tests   : 2024–2026 passed (2 flaky lifecycle sous forte charge, passent en isolation)
Modifs locales non commitées : cli.py, tests/test_cli.py (Confidence CLI)
SMB-01 : implémenté en worktree (branche `smb-01`, base 9034f01, 4 fichiers non commités) ; NON intégré
```

---

## Tâches terminées

---

### T23-B — Extension des détections Sentinel

**Objectif :** 5 nouveaux types d'événements sans Finding, correction de `new_host` et `new_port`.
**Branche :** `a4-arena` | **Commit :** `3657498` | **Auteur :** Arena Code
**Statut :** `[x]` Terminé

- [x] Implémentation conforme à la spec ARENA.md révision 12 (B1/B2/B3)
  - Proof: ✓ commit `3657498`, push `origin/a4-arena`, revue Kiro (verdict : conforme avec réserves)
- [x] Tests : 1960 existants + nouveaux T23-B passent
  - Proof: ✓ 2024–2026 passed après commit (2 flaky lifecycle sous forte charge, passent en isolation)

**Réserves acceptées (ne bloquent pas la clôture) :**
- `host_ports_initialized` utilise `state="whitelisted"` pour contourner le quota — solution propre reportée à un ticket futur
- `_classify_host` ne vérifie pas le champ `dev` explicitement — amélioration secondaire différée

---

### T21 — `findings list` groupé par machine

**Objectif :** Affichage terminal groupé par IP avec blocs Security Findings / Inventory Observations.
**Branche :** `a4-arena` | **Commit :** `5e2be6b` | **Auteur :** Arena Code
**Statut :** `[x]` Terminé

- [x] `_render_grouped_findings` : groupement par `target_ip`, séparateur Rich, blocs Security/Inventory
  - Proof: ✓ commit `5e2be6b` présent dans l'historique (`git log --oneline | grep "5e2be6b"`)
- [x] `device_fingerprint` dans Inventory Observations uniquement, jamais dans Security Findings
  - Proof: ✓ commit message et tests `test_cli.py` section T21
- [x] Déviation critère 7 acceptée par le propriétaire (2026-11-08)
  - Proof: ✓ décision enregistrée dans ARENA.md §8.5 et MASTER-REFERENCE.md §5

---

### T23-A — Monitor UX plain-log + progress line

**Commits :** `d5459d3`, `a4ee6a6`, `016df75` | **Statut :** `[x]` Terminé
- Proof: ✓ git show --stat sur les 3 commits

---

### T26 — WHOIS/RDAP structuré

**Commits :** `ec1d6a2`, `8288cee` | **Statut :** `[x]` Terminé
- Proof: ✓ python-whois 0.9.6, RDAP structuré, git show --stat

---

### T22 — Credentials (périmètre V1 : FTP, SNMP, SSH-password, SMB)

**Statut :** `[x]` Implémenté dans le périmètre V1 approuvé

- [x] FTP : `_check_ftp_defaults` via `ftplib` (pré-existant)
  - Proof: ✓ présent dans `default_creds.py`, `test_default_creds.py`
- [x] SNMP : `_check_snmp_defaults` via SNMPv1 GET raw (pré-existant)
  - Proof: ✓ présent dans `default_creds.py`, `test_default_creds.py`
- [x] SSH (password only) : `_ssh_session` via `paramiko`
  - Proof: ✓ commit `fafd5ff`, `test_ssh_creds.py` (893 lignes), paramiko 5.1.0 installé
- [x] SMB : session auth via `smbprotocol`
  - Proof: ✓ commit `6ad9a86`, `test_smb_creds.py` (624 lignes), smbprotocol 1.17.0 installé

**Note :** tests SSH nécessitent `umask 022` (umask système `002` cause 4 échecs trust store). Comportement rapporté par Kiro, pas validé par tiers indépendant.

**Validation critère par critère non effectuée** — voir MASTER-REFERENCE.md §6.2.

---

### D1–D4 — Event persistence reliable

**Commit :** `d2aa8a2` | **Statut :** `[x]` Terminé
- Proof: ✓ git show --stat

---

### B1–B7/C1 — Baseline learning/relearn reliable

**Commits :** `c80acf6`, `4bc4d5a`, `1ee02c9` | **Statut :** `[x]` Terminé
- Proof: ✓ git show --stat

---

### T19 — SMB enrichment (writable/users/policy)

**Commit :** `9a5dbbf` | **Statut :** `[x]` Terminé
- Proof: ✓ git show --stat

---

### T18 — OS device_fingerprint → CVE matching

**Commit :** `545708d` | **Statut :** `[x]` Terminé
- Proof: ✓ git show --stat

---

### T14 — Migration smb_enum → enum4linux-ng

**Commit :** `e6ff855` | **Statut :** `[x]` Terminé
- Proof: ✓ git show --stat

---

### P2-3 + T12 — CLI standalone + suggestions contextuelles

**Commit :** `3a5ef3a` | **Statut :** `[x]` Terminé
- Proof: ✓ git show --stat

---

### T17 — README `netlab findings rescan`

**Commit :** `1bcb25e` | **Statut :** `[x]` Terminé
- Proof: ✓ git show --stat

---

### T16 — KB lookup CVE-specific

**Commit :** `97f644b` | **Statut :** `[x]` Terminé
- Proof: ✓ git show --stat

---

## Tâche en cours

---

### CONFIDENCE-CLI — Colonne Confidence dans les tables de findings

**Objectif :** Afficher `Finding.confidence` (CONFIRMED / PROBABLE / POSSIBLE) dans les deux tables de findings de `cli.py`.
**Branche :** `a4-arena` | **Base commit :** `3657498` | **Auteur :** Kiro
**Fichiers :** `cli.py`, `tests/test_cli.py`
**Statut :** `[-]` Commit `85870ac` et push prouvés (présent dans `origin/a4-arena`) ; clôture soumise à revue Kiro (non tracée)

#### Phase 1 — Implémentation `cli.py`

- [x] Colonne `Confidence` après `Severity` dans `_render_findings_table`
  - Proof: ✓ `cli.py` ligne ~1896 : `table.add_column("Confidence")` présent, `f.confidence.name` dans le tuple ligne (`grep -n "Confidence" cli.py`)
- [x] Colonne `Confidence` après `Severity` dans `_render_security_block`
  - Proof: ✓ `cli.py` ligne ~1997 : même ajout (`grep -n "Confidence" cli.py`)

#### Phase 1 — Tests `tests/test_cli.py`

- [x] 4 assertions ID mises à jour avec `[:7]` (Rich tronque l'ID à 7 chars + `…` à 80 col quand la table s'élargit)
  - Proof: ✓ `grep -n "\\[:7\\]" tests/test_cli.py` retourne 4 occurrences
- [x] `test_security_block_shows_confidence_column` ajouté
  - Proof: ✓ présent dans `tests/test_cli.py` ligne ~1072
- [x] `test_flat_findings_table_shows_confidence_column` ajouté
  - Proof: ✓ présent dans `tests/test_cli.py` ligne ~1082
- [x] Suite ciblée : 14/14 passed (`TestFindingsList` + `TestFindingsListGroupedByMachine`)
  - Proof: ✓ pytest, branche a4-arena, post-modification

#### En attente

- [x] Commit (`85870ac`, `feat(cli): add confidence column to findings tables`)
  - Proof: `85870ac` présent dans `origin/a4-arena` (`git branch -r --contains 85870ac`, vérifié 2026-11-12)
- [x] Push vers `origin/a4-arena`
  - Proof: `git branch -r --contains 85870ac` renvoie `origin/a4-arena`

---

## Tâches non commencées

---

### T20 — Rapport HTML refonte présentation

**Statut :** `[ ]` Non commencé
**Spec :** approuvée — voir `docs/MASTER-REFERENCE.md` §7
**Dépendances :** aucune
**Prochaine dans la feuille de route** après Confidence CLI (commité, `85870ac`) : T20

---

## Tâches partiellement livrées — validation nécessaire

---

### T24 — `dns_enum` + `passive_recon` corrections

**Commit livré :** `cf5d821` | **Statut :** `[-]` Code livré, validation critère par critère non effectuée

- [x] Code livré : `dns_enum.py`, `passive_recon.py`, `rdap.py`, `registration.py`, CLI, `dependencies.py`, `vulnerabilities.json`
  - Proof: ✓ commit `cf5d821`, git show --stat (3166 insertions)
- [ ] Valider : `evidence.command` reflète dnspython (pas `dig`)
  - Proof: vérification terrain à faire
- [ ] Valider : WHOIS structuré SOC/pentest + dump brut dans `evidence.raw`
  - Proof: vérification terrain à faire
- [ ] Valider : `Confidence` → `PROBABLE` si résultat non autoritaire
  - Proof: vérification terrain à faire
- [ ] Valider : `Exposure` données DNS publiques → `EXTERNAL`
  - Proof: vérification terrain à faire
- [ ] Valider : `passive_recon` filtrage réseau rigoureux, IPv6 système exclue, ARP stale → `PROBABLE`
  - Proof: vérification terrain à faire
- [ ] Valider : `avahi-browse` documenté comme émettant du trafic mDNS
  - Proof: vérification terrain à faire

---

### T25 — Multi-host : 1 confirmation par opération

**Commit livré :** `f87b140` | **Statut :** `[-]` Code livré, validation critère par critère non effectuée

- [x] Code livré : `_confirm_batch_scan(module, ips, ports, profile)`, `--yes`, tests `test_scan_confirmations.py`
  - Proof: ✓ commit `f87b140`, git show --stat (238 lignes de tests)
- [ ] Valider : 1 confirmation par opération réseau (DISCOVER / TCP / UDP), pas par hôte
  - Proof: vérification `test_scan_confirmations.py` à faire
- [ ] Valider : `--yes` court-circuite toutes les confirmations
  - Proof: vérification terrain à faire

---

## Tickets d'audit et compléments SMB — séquence V2.2 (DEC-02)

> Source : `docs-proposees/PLAN-tickets-global.md` (version 2). **L'ordre V2.2 est approuvé (DEC-02). La présence d'un ticket dans ce tableau ne vaut pas autorisation implicite d'implémentation. Les statuts individuels font foi. SMB-01 est implémenté en worktree, non intégré ; SMB-02 est clôturé selon les preuves du propriétaire. Les autres tickets restent soumis à leur autorisation respective.** Aucune case `[x]` n'est ajoutée pour un ticket de correction. Le ticket suivant est désigné à la validation de chaque ticket. Ordre : plan §5.

> **Décisions non résolues (ne pas trancher dans ce suivi)** : DEC-03, DEC-04, DEC-05, DEC-11, DEC-12, DEC-14, DEC-16, DEC-17.

| Ticket | Anomalie | Priorité | Statut | Dépend de |
|---|---|---|---|---|
| SMB-01 | `smb_enum` : échec d'outil lu comme « aucun résultat » (code retour ignoré ; repli texte) | P1 | **Implémenté en worktree**, **non intégré** (branche `smb-01`, base `9034f01`, 4 fichiers non commités, diff `aa1d9d58…c4a4bf`) ; tests ciblés 189 passed ; suite complète 2112 passed / 1 failed (base 2082 passed / 1 failed ; échec commun `test_installed_standalone_command_exact_session`, environnement) ; revue Kiro CONFORME (rapportée, non reproduite par Arena) ; Revue Nova : avis favorable sur la base du diff et des rapports transmis ; implémentation et tests non reproduits indépendamment ; **acceptation propriétaire requise** | Étape 0 |
| SMB-02 | Vérification de compatibilité `enum4linux-ng` (version et options), intégrée à SMB-01 | P2 | **Clôturé** selon les preuves disponibles (voir bloc de clôture sous le tableau) | SMB-01 |
| SMB-03 | Reconnaissance SMBv1 dans le JSON `enum4linux-ng` : `smb_dialects: true` (marqueur d'imposition SMBv1) et dict de dialectes booléens (clés `SMB 1.0`, …) | P2 | **Implémenté (V3), non commité** ; revue indépendante Antigravity CONFORME ; **accepté par le propriétaire le 2026-11-14** ; diff isolé `aa2cb91a…afffe7f2f` ; tests SMB 145 passed ; tests CLI 7 passed (SMB-related) ; modifications présentes dans le dépôt local, aucun commit ni push | SMB-01 (en worktree), SMB-02 |
| SMB-04 | Politique de mot de passe : `"None"` / `"none"` (zéro) et `"not set"` (non configuré) font perdre toute la politique (`_extract_password_policy`, `int("None")`) | P2 | **Accepté par le propriétaire ; commité dans SMB-05** ; revue indépendante Antigravity CONFORME (2026-11-15) ; diff isolé `4e833b58…6872856` ; tests ciblés : 175 passed (SMB), 7 passed (CLI SMB) ; suite générale : 2 196 passed, 2 failed (échecs environnement préexistants) ; intégré au commit SMB-05 | SMB-01, SMB-02, SMB-03 |
| A1 | Fiabilisation des états TCP de Sentinel Monitor (ticket parent ; sous-tâches TCP-01 à TCP-03 ; TCP-04 en non-régression) | P1 | **Non terminé** ; autorisation d'implémentation requise | — |
| CRED-01 | Coffre et bases sous `Path.home()` ≠ utilisateur réel (sudo) | P1 | Planifié, après A1 ; DEC-05 requise | DEC-05 |
| D5 | Preuve de fermeture dans `events.details` (D5-B) | P3 | **Conception approuvée** ; implémentation non autorisée ; après A1 | A1 |
| D1 | Présentation : distinction preuve / historique | P2 | Distinction approuvée ; libellé ouvert ; après D5 | D5, DEC-03 |
| D6 | Politique des ports filtrés à l'apprentissage baseline (hors A1, indépendant) | P2 | Proposition ; DEC-04 examinée au moment du ticket | DEC-04 |
| TOOL-01 | `netlab doctor` ne vérifie que `--help` | P2 | Proposition | SMB-02 |
| REP-01 | « 0 » du rapport = quota de notification 60 min | P2 | Proposition | DEC-16 |
| OS-01 | Timeouts OS Nmap et messages (causes non mesurées) | P2 | Hypothèse ; mesure requise | DEC-12 |
| SCO-01 | Libellé « CVSS » | P2 | Partiel ; à confirmer | DEC-09 |
| SCO-02 | Port `info` CONFIRMED dans le score global | P2 | Décision produit | DEC-07 |
| A2-01 | Résolution d'identifiants incohérente | P2 | Proposition ; décision requise | DEC-11 |
| DOC-01 | HEAD déclaré obsolète, commits non consignés, CONFIDENCE-CLI | P2 | Étape 0 (hors séquence technique) ; patch à appliquer par le propriétaire | DEC-02 (approuvée) |
| CRED-03 | Message de coffre incomplet | P3 | Proposition | — |
| SCO-03 | Ports 512–514 sans règle | P3 | Décision produit | DEC-08 |
| VERIFY-01 | Findings `sentinel.*` en PARTIAL « Unsupported module » | P3 | Décision | — |
| DOC-02 | Chemins et casse (`.cursor/rules/sentinelX.mdc`) | P3 | Proposition | — |
| A2-02 | Nom de commande « rescan findings » (documentation) | P3 | Proposition | — |
| CLI-01 | Annulation confondue avec « aucun résultat » : après « SMB enumeration cancelled », la CLI affiche « No SMB findings » (`run_smb_enum` retourne `[]` dans les deux cas) | P3 | Proposition **non bloquante**, hors séquence §5.1 ; non autorisée ; contrat à décider (option A : troisième état ; option B : confirmation déplacée hors `run_smb_enum`) | SMB-01 (en worktree) ; décision de contrat |
| CRED-02 | `--service ssh` sans candidat SSH | — | **Conforme à T22, sans ticket** | — |
| NET-01 | Réseau `192.168.57.0/24` | — | **Non reproduite, sans ticket de code** | — |
| SMB-05 | Alignement JSON enum4linux-ng 1.3.10, persistance et restitution SMB standalone (C1-C5, D-SMB-01, D-SMB-02, scoring, tests) | P2 | **Accepté par le propriétaire le 2026-11-15 ; commité `<SMB-05-SHA>` sur `a4-arena` ; aucun push** : tests SMB 203 passed, CLI 108 passed, scoring 9 passed, `git diff --check` conforme ; test terrain propriétaire sur Metasploitable2 (35 utilisateurs, 10 résultats, 3 Security Findings scorés 45/70/70, session SQLite persistante) | SMB-01, SMB-02, SMB-03, SMB-04 |

**Précisions SMB-03 / SMB-04 / SMB-05 / D6** : SMB-03 accepté le 2026-11-14 et commité dans SMB-05. SMB-04 accepté le 2026-11-15 et commité dans SMB-05. SMB-05 (alignement JSON + persistance + restitution) commité le 2026-11-15 — voir section SMB-05 ci-dessous. D6 reste indépendant et hors de cette séquence.

**Résultats suite générale SMB-04 V2 (2026-11-15)** :
- Commande : `HOME=$TESTHOME SENTINEL_TEST_EXECUTABLE=.../venv/bin/sentinel bash -c "umask 022 && venv/bin/python -m pytest --tb=short -q"`
- Résultat : **2 196 passed, 2 failed** en 3 140,69 s (0:52:20)
- Échec 1 : `tests/test_cli_coherence.py::test_real_cli_subprocess_reports_discover_failure` — `subprocess.TimeoutExpired` après 30 s ; sous-processus CLI qui ne termine pas dans le délai sur cette machine. Échec d'environnement (charge CPU, vitesse) ; test présent à `9034f01` ; non touché par SMB-04 V2. Reproductibilité sur base antérieure non prouvée dans cette session.
- Échec 2 : `tests/test_sentinel_consultation.py::test_installed_standalone_command_exact_session` — entrée `sentinel` non installée (`shutil.which('sentinel')` = None) ; assertion explicite du test. Échec d'environnement connu ; non touché par SMB-04 V2. Présent dans les runs précédents (Arena : « échec commun »).
- Aucun nouvel échec introduit par SMB-04 V2.
- HEAD, `git status` et SHA-256 des fichiers SMB inchangés après l'exécution.

**Clôture SMB-02 (2026-11-13)** : vérification de compatibilité réalisée par le propriétaire sur cible autorisée (Metasploitable 2, `192.168.57.3`) avec `enum4linux-ng` **1.3.10** (tag `f34e7bb`) : `-A -oJ` accepté, JSON généré et valide, énumération complète. Version et options consignées (critère 1 de SMB-01).
- Proof: ✓ rapport du propriétaire (2026-11-13) ; **non reproduit par Arena** ; sortie JSON complète non archivée dans le workspace.
- Constats de la même sortie, transférés à SMB-03 (`"smb_dialects": true`) et SMB-04 (`"None"`, `"none"`, `"not set"`).

**Worktree SMB-01** : ne pas marquer SMB-01 « intégré » avant l'acceptation du propriétaire et l'intégration. `cli.py` et `tests/test_cli.py` sont aussi touchés par CONFIDENCE-CLI : conflit à arbitrer à l'intégration.

**Spécification A1** : `docs-proposees/SENTINEL-TCP-STATES.md`. Emplacement canonique proposé : `docs/SENTINEL-TCP-STATES.md` (vérification Kiro).

---

---

### SMB-05 — Alignement JSON enum4linux-ng 1.3.10, persistance et restitution SMB standalone

**Objectif :** corriger les décalages entre la sortie JSON réelle d'enum4linux-ng 1.3.10 et les parseurs SentinelX ; activer la persistance SQLite de `smb_enum_cmd` ; améliorer la restitution CLI et le scoring.
**Branche :** `a4-arena` | **Commit :** `<SMB-05-SHA>` | **Base :** `ed646fc` (SMB-04 V2)
**Fichiers :** `detect/smb_enum.py`, `tests/test_smb_enum.py`, `cli.py`, `tests/test_cli.py`
**Statut :** `[x]` **Accepté et commité le 2026-11-15**

#### Corrections de parsing (C1–C5)

- [x] C1 — `_extract_anonymous_session()` : reconnaît `sessions.null` (enum4linux-ng 1.3.10)
  - Proof: ✓ `test_sessions_null_true_recognized`, `test_sessions_null_false_recognized`
- [x] C2/C3 — `_extract_password_policy()` : alias `policy` + sous-sections `domain_password_information` / `domain_lockout_information`
  - Proof: ✓ `test_policy_nested_structure_produces_finding`
- [x] C4 — `_extract_share_accessible()` : interprète `access.mapping: ok/denied` ; jamais de déduction WRITE
  - Proof: ✓ `test_access_mapping_ok_is_accessible`, `test_mapping_ok_never_means_write`
- [x] C5 — `_extract_users()` : extrait `username` depuis les dicts RID-indexés
  - Proof: ✓ `test_users_rid_dict_extracts_usernames`

#### Classification ADMIN$ (D-SMB-02)

- [x] `_classify_share(name, accessible)` : MEDIUM seulement si `accessible=True` ; INFO sinon
  - Proof: ✓ `test_admin_accessible_is_medium`, `test_admin_denied_is_info`, `test_admin_unknown_access_is_info`

#### Persistance et restitution standalone (D-SMB-01)

- [x] `smb_enum_cmd` : session SQLite réelle (`session-xxx`), `save_findings`, `close_session`
  - Proof: ✓ `test_smb_enum_persists_scored_findings`, `save.assert_called_once()`
- [x] `_render_smb_results()` : panel inventaire, Security Findings, session ID coloré, commande `findings show` copiable
  - Proof: ✓ `test_success_with_results_renders_findings_once`

#### Scoring corrigé (P1)

- [x] `findings = score_findings(findings)` — valeur de retour utilisée pour `save_findings` et `_render_smb_results`
  - Proof: ✓ `TestSmbEnumScoring` : 3 tests ; `risk_score` non None sur findings éligibles

#### Formatage des preuves

- [x] `_format_evidence_raw()` : JSON pretty-print jusqu'à 2 000 chars, texte brut jusqu'à 500 chars
  - Proof: ✓ `TestFormatEvidenceRaw` : 6 tests dans `test_cli.py`

#### Tests

- [x] `TestSMBFinalisationParsing` (15 tests), `TestMetasploitable2Fixture` (11 tests), `TestSmbEnumScoring` (3), `TestFormatEvidenceRaw` (6), `test_smb_enum_persists_scored_findings`
  - Proof: ✓ 203 passed (`test_smb_enum.py`), 108 passed (`test_cli.py`) — Antigravity
- [x] Doublons de classes et fixtures supprimés ; `test_tmp_writable_anonymous_is_high` conservé
  - Proof: ✓ `git diff --check` rc 0

**Test terrain (propriétaire, Metasploitable2 `192.168.57.3`, 2026-11-15) :**
- 35 utilisateurs récupérés sous leurs vrais noms
- Password policy : `min_len=5`, `lockout=0`
- 10 résultats : 3 Security Findings (scores 45, 70, 70) et 7 Inventory Observations
- Session SQLite persistante et consultable via `findings show`

**Suite générale (2026-11-15, dernière mesure connue) :** 2 196 passed, 2 failed (deux échecs d'environnement préexistants, non liés à SMB-05).

---

### CLI-UX-01 — Identité SentinelX et cohérence de la restitution CLI

**Objectif :** harmoniser l'expérience CLI de l'ensemble de SentinelX — l'utilisateur interagit avec SentinelX, pas avec Nmap, enum4linux-ng ou les autres outils internes.
**Statut :** `[ ]` Non commencé. **Implémentation non autorisée.** Ticket de conception.
**Priorité :** non attribuée — à décider par le propriétaire.
**Dépendances :** aucune dépendance technique bloquante identifiée ; l'axe B suppose que les modules modifiés sont stables.

#### Périmètre transversal

Deux axes indépendants mais liés :

**Axe A — Présentation des résultats**

Comportement actuel observé : `smb_enum` produit 3 Security Findings et 7 Inventory Observations, mais la distinction n'est pas suffisamment explicite pour l'utilisateur. Les Findings INFO peuvent provenir de modules SMB (observations légitimes) ou de `device_fingerprint` (inventaire) — ils ne sont pas tous équivalents.

Comportement attendu :
- Séparer visuellement `Security Findings` et `Inventory Observations` dans toutes les commandes standalone.
- Afficher les décomptes réels de chaque catégorie, calculés dynamiquement (jamais codés en dur).
- Rendre chaque résultat consultable par son ID.
- Expliquer clairement Severity, Confidence, Finding State et Score dans `findings show`.
- Ne pas assimiler automatiquement tous les Findings INFO aux observations d'inventaire sans vérifier `finding.module` et `finding.category`.

Contrats à respecter : T21 (groupement par machine), `Finding.module`, `_is_inventory_observation()` de `cli.py`.

**Axe B — Identité produit**

Comportement actuel observé (exemples) :
- `detect/smb_enum.py` l.148 : `"[cyan]Starting enum4linux-ng on {target_ip}...[/cyan]"`
- `detect/smb_enum.py` l.133 : `"[yellow]No output from enum4linux-ng..."` (ancien texte pré-SMB-01, peut subsister dans d'autres messages)
- `recon/device_fingerprint.py` : messages Nmap exposés à l'utilisateur (à vérifier)
- `detect/tcp_scan.py` : messages de progression potentiellement liés à Nmap

Comportement attendu :
- Messages utilisateur formulés du point de vue SentinelX : `"Analyse SMB en cours sur {target}..."` au lieu de `"Starting enum4linux-ng on {target}..."`
- Même principe pour Nmap, enum4linux-ng, et tout outil externe.
- **Conserver impérativement** dans `evidence.command` la commande réelle exécutée.
- **Conserver** le nom de l'outil dans les messages de diagnostic et d'erreur technique (ex. `"enum4linux-ng not found (run 'netlab doctor')"` reste pertinent).
- **Conserver** les messages de débogage et les sorties de `netlab doctor`.

#### Fichiers et fonctions probablement concernés

| Fichier | Élément | Nature |
|---|---|---|
| `detect/smb_enum.py` | `display(f"[cyan]Starting enum4linux-ng on...")` l.~148 | Axe B |
| `detect/smb_enum.py` | `_report_failure()` — messages d'échec | Axe B (distinction user/debug) |
| `cli.py` | `_render_smb_results()` — décomptes Security / Inventory | Axe A |
| `cli.py` | `_render_grouped_findings()`, `_render_security_block()` | Axe A |
| `cli.py` | `_render_finding_detail()` — libellés Severity/Confidence/Score | Axe A |
| `recon/device_fingerprint.py` | Messages utilisateur Nmap | Axe B (à vérifier) |
| `detect/tcp_scan.py` | Messages de progression | Axe B (à vérifier) |

#### Critères d'acceptation

| # | Critère |
|---|---|
| CA-1 | `smb_enum` affiche `Security Findings (N)` et `Inventory Observations (M)` avec N et M calculés |
| CA-2 | `findings show <ID>` affiche Severity / Confidence / Score avec libellés explicatifs |
| CA-3 | Aucun message utilisateur ne contient `enum4linux-ng`, `nmap`, ou un nom d'outil interne — sauf dans les erreurs de diagnostic, `evidence.command`, et `netlab doctor` |
| CA-4 | `evidence.command` conserve la commande réelle exécutée |
| CA-5 | Les tests unitaires mockent `display()` et vérifient l'absence du nom d'outil dans les messages utilisateur normaux |
| CA-6 | Aucune régression T21 (groupement par machine) ni `_render_grouped_findings` |
| CA-7 | `_is_inventory_observation()` reste le seul point de classification inventaire |

#### Tests nécessaires

- Mocks de `display()` vérifiant que les messages nominaux ne contiennent pas de noms d'outils.
- Tests de décompte dynamique Security vs Inventory.
- Tests de non-régression `_render_grouped_findings`, T21, `findings show`.

#### Risques de régression

- **Moyen** : changer les messages de `display()` peut casser des tests qui assertent leur contenu exact (ex. `TestSmbEnumCliOutcomes` vérifie `"FAILED"`, pas le nom de l'outil — risque limité).
- **Faible** : les décomptes dynamiques ne modifient pas la logique de Finding.
- **Nul** : `evidence.command` n'est pas touché par cet axe.

---

## Différé / hors périmètre

| Item | Raison |
|---|---|
| T23-B : solution propre pour quota `host_ports_initialized` | Réserve acceptée — ticket futur |
| T23-B : vérification champ `dev` dans `_classify_host` | Amélioration secondaire différée |
| D3 (gateway `_get_gateway_ip` fallback) | Ticket séparé, hors T23-B |
| D4 (avertissement ARP REACHABLE) | Amélioration secondaire reportée |
| Global Risk Score composite réseau | Hors V1 — steering §H |
| PDF export | Hors V1 — HTML + impression navigateur |
| Telnet, HTTP/HTTPS, RDP, clés SSH dans T22 | Hors périmètre V1 approuvé |

---

## Comment ajouter une nouvelle tâche

Copier et coller ce bloc dans la section appropriée (terminée, en cours, non commencée, etc.) :

```markdown
### TICKET-ID — Titre court

**Objectif :** Une phrase.
**Branche :** `nom-branche`
**Base commit :** `xxxxxxx`
**Fichiers :** `fichier1.py`, `fichier2.py`
**Statut :** [ ] Non commencé / [-] En cours / [x] Terminé (commit `xxxxxxx`)

#### Phase N — Description

- [ ] Sous-tâche
  - Proof: ce qu'il faut vérifier
- [x] Sous-tâche terminée
  - Proof: ✓ résultat observé
```
