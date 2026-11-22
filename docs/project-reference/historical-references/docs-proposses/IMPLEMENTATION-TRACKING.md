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
HEAD    : 3657498  (T23-B — 2026-11-10)
Tests   : 2024–2026 passed (2 flaky lifecycle sous forte charge, passent en isolation)
Modifs locales non commitées : cli.py, tests/test_cli.py (Confidence CLI)
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
**Statut :** `[-]` En cours — modifications faites, tests passent, commit en attente d'autorisation

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

- [ ] Commit (`cli.py`, `tests/test_cli.py`, `docs/MASTER-REFERENCE.md`, `docs/IMPLEMENTATION-TRACKING.md`)
  - Proof: en attente d'autorisation du propriétaire
  - Message suggéré : `feat(cli): add confidence column to findings tables`
- [ ] Push vers `origin/a4-arena`
  - Proof: en attente d'autorisation du propriétaire

---

## Tâches non commencées

---

### T20 — Rapport HTML refonte présentation

**Statut :** `[ ]` Non commencé
**Spec :** approuvée — voir `docs/MASTER-REFERENCE.md` §7
**Dépendances :** aucune
**Prochaine dans la feuille de route** après Confidence CLI (commit)

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
