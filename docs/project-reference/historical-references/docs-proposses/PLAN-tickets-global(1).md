# Plan global de tickets — audit SentinelX (réconciliation A1 et anomalies confirmées)

**Statut : PROPOSITION. Aucun ticket n'est approuvé ni implémenté.** Aucun fichier du dépôt n'est modifié. Aucun commit, push, nettoyage ni scan réel.
**Date de rédaction** : 2026-09-24 (date du jour fournie). Voir réserve R-1 sur l'horloge de la sandbox.
**Référence de code** : `origin/a4-arena` = `9034f01` (clone de lecture `/tmp/audit-global-ref`, arbre propre).
**Sources** : `RAPPORT-audit-global.md`, `PLAN-correction.md` (ancien plan), `RAPPORT-complement-A1-transitions-ports.md`, `RAPPORT-complement-B2-credentials-coffre.md`, `RAPPORT-verification-A1-chaine-production.md`, `SPEC-A1-consolidee.md`, `PROPOSITION-A1-formalisation-TCP.md`, `docs-proposees/SENTINEL-TCP-STATES.md`.

Légende des statuts : **Confirmé** = reproduit (fixture, faux binaire, simulation) ou établi par lecture de code ; **Partiel** = une partie seulement est établie ; **Hypothèse** = non reproduite, à vérifier ; **Décision** = pas un bug, choix du propriétaire requis.

Légende des priorités : **P1** = fausse fermeture, faux négatif sur outil de sécurité, ou risque d'emplacement de données sensibles, confirmé ; **P2** = défaut confirmé sans conséquence de sécurité immédiate, ou mesure requise avant correction ; **P3** = documentation ou cosmétique.

---

## 1. Réconciliation des statuts A1

| Élément | Avant (documents de la mission) | Après (décisions du propriétaire) | Où |
|---|---|---|---|
| `open`, `closed` (2 observations), `filtered`, `open\|filtered`, inconnus, hôte entièrement filtré, compteurs non restaurés | [APPROUVÉ] | [APPROUVÉ] | SPEC §1, PROPOSITION §0 |
| Libellé D1 (« Port N closed » ou conditionnel) | [OUVERT] | **Libellé : [OUVERT] (DEC-03)** ; distinction preuve / historique : **[APPROUVÉ]** | SPEC R8, §12 ; PROPOSITION §0 |
| D5 | [NON APPROUVÉ] / [OUVERT] | **[APPROUVÉ] D5-B** ; D5-A et D5-C non retenues | SPEC §10 ; PROPOSITION §10 |
| D6 | [NON APPROUVÉ] | **Périmètre [APPROUVÉ] : ticket indépendant hors A1** ; politique C2/C3 **[OUVERT] (DEC-04)** ; A1 garde C1 = D6-A | SPEC §11 ; PROPOSITION §11 |
| V4 (hôte absent du cycle) | [OUVERT] | **[APPROUVÉ]** : remise à zéro | SPEC §5.4 ; PROPOSITION §0 |
| Garde de masse : G-a / G-b / G-c | [OUVERT] | **G-a [APPROUVÉ]** (fermetures individuelles après deux `closed` explicites pour tous les ports connus) ; **G-b [ÉCARTÉ]** (aucun seuil global) ; **G-c [REPORTÉ]** hors A1 | SPEC §5.3 |
| Perte de détection `closed` → `filtered` | [OUVERT] | **[APPROUVÉ]** : aucune fermeture confirmée sur `closed` → `filtered` ; réserve à consigner | SPEC §12, §13 |
| Validation d'attribution partagée monitor / apprentissage | [OUVERT] | **[APPROUVÉ]** : validation XML commune | SPEC §9.3 |
| Redémarrages répétés sans fermeture confirmée (S3) | [OUVERT] | **[APPROUVÉ]** R7 (non restauré) ; réserve à consigner (DEC-15) | SPEC §12 |
| Hôte absent : statut de « lecture stricte » | « recommandé » | Remplacé par [APPROUVÉ] V4 | — |

Spécification canonique proposée : `docs-proposees/SENTINEL-TCP-STATES.md` (remplace la spec de travail `SPEC-A1-consolidee.md` ; emplacement final **DEC-01**).

Incohérence de fond : **ARENA §9.6 est déclaré « règle définitive » et contredit les règles approuvées** (`[]` incrémente les compteurs ; `[ports]` remet à zéro les présents). Le code `9034f01` suit ARENA §9.6. Modifier ARENA est un acte du propriétaire (DEC-13). Le texte proposé est au §6.

---

## 2. Correspondance des identifiants

Les anciens identifiants se chevauchent (`A1-1` et `A1-2` désignent deux choses différentes selon le document). Les nouveaux identifiants remplacent les anciens dans les documents proposés.

| Ancien identifiant | Source | Anomalie | Nouveau ticket |
|---|---|---|---|
| A1-1 (PLAN, P2) | PLAN-correction | `filtered` → fermeture | TCP-02, TCP-06 (priorité relevée à **P1**, voir §3) |
| A1-2 (PLAN, P3) | PLAN-correction | compteurs non restaurés | **Décision R7 (approuvée) : pas de ticket de restauration** |
| A1-2 (complément, P1) | RAPPORT-complement-A1 | hôte entièrement filtré → `port_not_open` | TCP-03 (et TCP-02) |
| A1-3 | complément A1 | états non prévus fail-open | TCP-01 |
| A1-4 | complément A1 | trois libellés | TCP-06 |
| A1-5 | complément A1 | `states` jetés | TCP-01 |
| A1-6 | complément A1 | compteurs non reconstruits | Décision R7 (même traitement que PLAN A1-2) |
| A1-7 | complément A1 | baseline sous filtrage → `new_port` | D6-01 (hors A1) |
| A1-8 | complément A1 | `evidence` non persistée | TCP-05 |
| A1 (rapport global §0 n°5) | RAPPORT-audit-global | = PLAN A1-1 | TCP-02, TCP-06 |
| B2-1 … B2-3 | PLAN, rapport B2 | coffre, SSH, message | CRED-01, CRED-02, CRED-03 |
| B3-1 … B3-4 | PLAN, rapport global | `smb_enum`, `--json`, regex, doctor | SMB-01, SMB-02, TOOL-01 |
| A2-1, A2-2 | PLAN | identifiants ; `rescan` | A2-01, A2-02 |
| A3-1 | PLAN | « 0 » du rapport | REP-01 |
| B1-1 | PLAN | VERIFY `sentinel.*` | VERIFY-01 |
| B4-1, B4-2 | PLAN | timeouts OS, messages | OS-01 |
| B5-1 … B5-3 | PLAN | scoring, libellé, 512-514 | SCO-01, SCO-02, SCO-03 |
| C-1 | PLAN, rapport global | réseau `192.168.57.0/24` | NET-01 (pas de ticket de code) |
| DOC-1, DOC-2 | PLAN | HEAD, chemins, statuts | DOC-01, DOC-02 |

---

## 3. Tickets

Format : identifiant · anomalie · preuve · priorité · périmètre · dépendances · critères · tests · statut.

### 3.1 Sentinel — états TCP (A1)

**TCP-01 — Parsing, attribution et représentation des états TCP ; validation commune.**
- **Anomalie** : `filtered`, `open|filtered` et états inconnus sont réduits à « absence de `open` » ; `states` est jeté (`detect/tcp_scan.py` l.558) ; fail-open sur attributions ambiguës (P1–P12 : `prod=[22]`, `valid=True`). Preuve : `preuves/a1/a1_chain_verify-run5.json` (identique à run 4), `RAPPORT-verification-A1` V6, V7, §12.
- **Priorité** : **P1** (point de départ de TCP-02 ; fausses fermetures en chaîne, S7/S8).
- **Périmètre** : `detect/tcp_scan.py` (`_recorded_port_states` l.337, `_check_tcp_xml` l.354, `_parse_tcp_xml_with_states` l.444, `parse_sentinel_open_ports` l.558) ; `sentinel/monitor.py` `_get_open_ports` l.264 ; `sentinel/baseline.py` `learn_baseline` l.431 (appel l.481). Signatures publiques inchangées (CA-10).
- **Dépendances** : aucune.
- **Critères** : SPEC §9 CA-8, CA-9, CA-10, CA-12, CA-17.
- **Tests** : `tests/test_tcp_scan.py` (ajouts : `filtered`, `open|filtered`, `unfiltered`, sans état, `bogus`, attributions `<extraports>`) ; `tests/test_sentinel_baseline*.py` (XML ambigu → baseline inchangée).
- **Statut** : proposé, non approuvé.

**TCP-02 — Compteurs par séquence et remise à zéro sur absence.**
- **Anomalie** : `filtered` ×2 produit `port_not_open` (S7, mesuré) ; `open|filtered` ×2 idem (S8) ; hôte absent du cycle conserve ses compteurs (S5 : c3 au lieu de c4, V4 approuvé).
- **Priorité** : **P1**.
- **Périmètre** : `sentinel/sentinel_manager.py` `NetworkState.port_absent_count` l.291 ; `_rebuild_transition_state` l.300-362 ; `_compute_port_transitions` l.460-505 (boucle l.463 sur `current_hosts` seulement) ; `_do_check` l.594, `ScanFailedError` l.626-636.
- **Dépendances** : TCP-01.
- **Critères** : SPEC-TCP §5 (tableau) ; CA-1 à CA-4, CA-6, CA-7, CA-14.
- **Tests** : révision `test_port_not_open_after_two_complete_scans_then_never_repeated` (`tests/test_sentinel_manager.py` l.429-440) ; conserver `test_unknown_tcp_observation_restarts_the_absence_count` (l.450-455) et `test_error_status_resets_the_absence_count` (l.487-497) ; ajout : absence d'hôte au cycle intermédiaire (aucun test existant).
- **Statut** : proposé, non approuvé.

**TCP-03 — Prévention des fermetures de masse ; tests de séquences de non-régression.**
- **Anomalie** : hôte entièrement filtré (22 et 80, dix cycles) → `port_not_open` au cycle 2 (S11, mesuré, A1-2 complément, P1). Le quota ne protège pas (il masque l'affichage, pas la fermeture).
- **Priorité** : **P1**.
- **Périmètre** : garde R6 (conséquence de TCP-01/TCP-02, à vérifier) ; harnais `preuves/a1/a1_chain_verify.py` (référence, non modifié par ce plan) ; nouveaux tests de séquence.
- **Dépendances** : TCP-02.
- **Critères** : CA-5, CA-13 (S7, S8, S11 passent), CA-15 (deux `closed` explicites pour chaque port connu : une fermeture par port, sans seuil).
- **Tests** : S1 à S11 et L1, L2 du harnais, portés en tests unitaires (fixtures XML, aucun scan réel) ; ajout S5 (V4) et S7/S8/S11.
- **Statut** : proposé, non approuvé.

**TCP-04 — Redémarrage : non-restauration des compteurs et réserve.**
- **Anomalie** : aucune (comportement approuvé R7). Risque : redémarrages plus fréquents que deux cycles → aucune fermeture confirmée (S3, mesuré).
- **Priorité** : **P2** (tests de confirmation ; la réserve est une décision).
- **Périmètre** : `sentinel/sentinel_manager.py` `_rebuild_transition_state` (ne pas restaurer `port_absent_count`).
- **Dépendances** : TCP-02.
- **Critères** : CA-6 ; réserve §8 de `SENTINEL-TCP-STATES.md` acceptée explicitement (DEC-15).
- **Tests** : S2, S3, S10 du harnais en tests unitaires.
- **Statut** : proposé.

**TCP-05 — Preuve de fermeture dans `events.details` (D5-B).**
- **Anomalie** : `evidence` n'est pas persistée (A1-8) ; une fermeture ne garde aucune trace de sa justification.
- **Priorité** : **P3** (demandé par le propriétaire ; faible risque ; peut suivre TCP-03).
- **Périmètre** : `sentinel/alerting.py` `_detail_extras` l.138, `process_changes` l.149, `details` l.168 ; `core/database.py` `sentinel_save_event` l.1572-1586 (aucun changement de schéma, CA-18).
- **Dépendances** : TCP-02 (le compteur consécutif est la source de la preuve).
- **Critères** : SPEC-TCP §7.1 ; CA-11, CA-18. Clés : `proof = {observed, consecutive, scan, run}` (proposition, valider au ticket).
- **Tests** : nouvel événement avec `proof` ; ancien événement inchangé ; lecteurs de `details` ignorent la clé (`sentinel_manager.py` l.331-355, `notifications.py` l.32-60, `reports/sentinel_report.py` l.27-35) ; reprise au démarrage (`tests/test_sentinel_lifecycle.py`).
- **Statut** : approuvé (D5-B), à planifier.

**TCP-06 — Présentation D1 : distinction preuve / historique.**
- **Anomalie** : « Port N closed » est affiché pour tout `port_not_open`, y compris les anciens événements (A1-4, libellés trois fois) ; le rapport HTML affiche `details['detail']` brut.
- **Priorité** : **P2**.
- **Périmètre** : `sentinel/monitor_view.py` `presentation_detail` l.52-61, `_PORT_NOT_OPEN_DETAIL` l.49 ; `reports/sentinel_report.py` l.27-35 ; `tests/test_sentinel_event_display.py` l.76-82 (à réviser).
- **Dépendances** : TCP-05 (la distinction exige la preuve) ; **DEC-03 (libellé exact)**.
- **Critères** : SPEC-TCP §7.3 ; CA-16. Libellé exact non approuvé : **aucun changement de libellé avant DEC-03**.
- **Tests** : réviser `test_closed_port_is_labelled_closed` et `test_label_is_derived_from_stored_detail...` ; ajout : événement avec `proof` vs historique sans `proof`.
- **Statut** : proposé ; bloqué par DEC-03.

### 3.2 Hors A1

**D6-01 — Politique des ports `filtered` à l'apprentissage baseline.**
- **Anomalie** : `learn_baseline` accepte un hôte entièrement filtré avec baseline `{}`, puis chaque port ouvert ensuite produit `new_port` (A1-7, L1/L2 mesurés, `sentinel/baseline.py` l.480-490).
- **Priorité** : **P2**. Ticket indépendant, hors A1 (décision).
- **Périmètre** : `sentinel/baseline.py` ; `core/database.py` `baseline.services` (écrit `"{}"`, `sentinel_replace_baseline` l.1503-1543, aucun lecteur logique trouvé — grep non exhaustif).
- **Dépendances** : **DEC-04** (C2, C3 ou statu quo D6-A). TCP-01 déjà en place (la validation commune ne change pas cette politique).
- **Critères** : à rédiger après DEC-04.
- **Tests** : L1, L2 ; contrat de `services` si D6-B.
- **Statut** : proposé ; décision requise.

### 3.3 Sentinel — reporting

**REP-01 — « 0 » du rapport = quota de notification (A3-1).**
- **Anomalie** : le « 0 » de la colonne « Affichées » est le quota 60 min par couple réseau/IP (`reports/sentinel_report.py` l.48 ; `sentinel/notifications.py` `LIMIT`/`WINDOW`) ; un `new_port` de 2 h s'affiche « 0 » (**Confirmé**, reproduit).
- **Priorité** : **P2**.
- **Périmètre** : libellé du rapport, `reports/templates/sentinel_status.html` l.28-29 (« quotas par hôte à la génération (60 dernières minutes) »).
- **Dépendances** : DEC-16 (formulation du libellé).
- **Critères** : le libellé indique « notifications affichées sur 60 min », pas « événements ».
- **Tests** : rendu HTML d'un réseau avec événement hors fenêtre.
- **Statut** : proposé.

### 3.4 Outils externes et découverte

**SMB-01 — `smb_enum` : échec d'outil présenté comme absence de résultat (B3-1, B3-3).**
- **Anomalie** : code de retour ignoré ; faux binaire rc=2 → « no shares or domain info », 0 finding (**Confirmé** en isolation) ; repli texte : regex doublement échappée, `users=()` pour « Account: alice » (**Confirmé**).
- **Priorité** : **P1** (faux négatif sur outil de sécurité).
- **Périmètre** : `detect/smb_enum.py` l.94 (`_resolve_tool_path`), l.138 (`_run_enum4linux_ng`), l.150 et l.183 (commande, `check=False`), `_normalize_text_output` (regex).
- **Dépendances** : aucune. Indépendant de TCP-01.
- **Critères** : rc≠0 → erreur explicite, aucun finding, message distinct de « no shares » ; stdout seul parsé ; repli texte lit « Account: alice ».
- **Tests** : `tests/test_smb_enum.py` l.122 (fige `-A --json <ip>`, à réviser après SMB-02) ; ajout : code non nul avec sortie non JSON ; faux binaire en HOME temporaire.
- **Statut** : proposé.

**SMB-02 — Syntaxe d'export de `enum4linux-ng` (B3-2).**
- **Anomalie** : `--json` probablement inexistant (export JSON documenté `-oJ`). **Hypothèse forte, non vérifiée** avec la version installée.
- **Priorité** : **P2** (vérification d'abord, par lecture locale `--help`, sans scan).
- **Périmètre** : aucune modification avant vérification.
- **Dépendances** : SMB-01 pour le message d'échec.
- **Critères** : version installée identifiée ; option retenue confirmée par `--help` de cette version.
- **Tests** : mesure seule, consignée dans le ticket.
- **Statut** : **Hypothèse** — non ouvert comme bug.

**TOOL-01 — `netlab doctor` ne vérifie que `--help` (B3-4).**
- **Anomalie** : `core/dependencies.py` l.118-135 : un `--help` réussi ne prouve pas l'existence des options utilisées (**Confirmé** par lecture).
- **Priorité** : **P2**.
- **Périmètre** : `core/dependencies.py`.
- **Dépendances** : SMB-02.
- **Critères** : doctor signale une option absente de la version installée.
- **Tests** : faux binaire sans l'option → signalé.
- **Statut** : proposé.

**OS-01 — Timeouts OS Nmap et « no usable fingerprint » (B4-1, B4-2).**
- **Anomalie** : `timeout=60` codé en dur (`recon/device_fingerprint.py` l.181-196) ; sortie partielle perdue à l'échéance (`core/process_control.py`) ; deux messages distincts sous le même libellé. **Causes non mesurées** : aucune cause confirmée.
- **Priorité** : **P2** : mesurer avant de corriger.
- **Périmètre** : `recon/device_fingerprint.py` l.64, l.181, l.199, l.368 ; `core/process_control.py`.
- **Dépendances** : DEC-12 (délai configurable ou non).
- **Critères** : temps réel mesuré sur hôte de test autorisé ; messages distincts pour timeout et absence d'`osmatch`.
- **Tests** : fixtures XML sans `osmatch` ; `TimeoutExpired` simulé.
- **Statut** : **Hypothèse** (causes) ; mesure requise.

### 3.5 Identifiants et interface

**A2-01 — `sentinel findings show` refuse un préfixe accepté par `findings show` (A2-1).**
- **Anomalie** : `core/database.py` `resolve_finding_id` l.597 vs `sentinel_read_finding` l.2034 : règles de résolution différentes (**Confirmé** par lecture).
- **Priorité** : **P2**.
- **Périmètre** : `core/database.py` l.597, l.2034 ; `cli.py` (sous-commandes `findings`/`sentinel findings`).
- **Dépendances** : DEC-11 (option (a), (b) ou (c)).
- **Critères** : même règle pour les deux commandes (option retenue).
- **Tests** : préfixe accepté par les deux, ou refus identique et message cohérent.
- **Statut** : proposé ; décision requise.

**A2-02 — Nom de commande dans la demande (A2-2).**
- **Anomalie** : `findings rescan` existe ; le nom « rescan findings » n'existe pas (**Documentation**).
- **Priorité** : **P3**.
- **Périmètre** : documentation seulement.
- **Dépendances** : aucune.
- **Critères** : documentation indique `findings rescan`.
- **Tests** : aucun.
- **Statut** : proposé.

### 3.6 Credentials et coffre

**CRED-01 — Coffre et bases sous `Path.home()` ≠ `_real_user_home()` sous sudo (B2-1).**
- **Anomalie** : sous `sudo`, le coffre peut être créé sous `/root` (**Reproduit** par simulation de chemin, rapport B2 §0 P1).
- **Priorité** : **P1**.
- **Périmètre** : `core/credential_vault.py` l.34-35 ; chemins de base dans `core/database.py`.
- **Dépendances** : **DEC-05** (emplacement cible et procédure de migration). Aucune migration sans décision : **ne pas déplacer, migrer ni supprimer de coffre**.
- **Critères** : chemin unique résolu par utilisateur réel ; test sans coffre réel.
- **Tests** : HOME et coffre temporaires uniquement ; sudo simulé.
- **Statut** : proposé ; décision requise.

**CRED-02 — `--service ssh` sans candidat SSH par défaut (B2-2).**
- **Anomalie** : catalogue `legacy` = FTP + SNMP ; SSH absent (`detect/credential_dictionary.py` l.200) ; « messages précis masqués volontairement » (rapport B2, P2).
- **Priorité** : **Décision** (non un bug : choix produit documenté).
- **Périmètre** : catalogue ou `--dict`.
- **Dépendances** : **DEC-06**.
- **Critères** : comportement choisi et documenté.
- **Tests** : selon choix.
- **Statut** : décision produit.

**CRED-03 — Message de coffre incomplet (B2-3).**
- **Anomalie** : la règle des 8 caractères distincts n'apparaît pas dans le message (**Confirmé** par lecture).
- **Priorité** : **P3**.
- **Périmètre** : message du coffre (`core/credential_vault.py`).
- **Dépendances** : aucune.
- **Critères** : message complet, sans révéler de valeur.
- **Tests** : message contient la règle ; aucun secret journalisé.
- **Statut** : proposé.

### 3.7 Scoring

**SCO-01 — Libellé « CVSS » (B5-1). Statut révisé : Partiel.**
- **Anomalie** : la valeur « 5.0 » est bien un `risk_score` (`core/risk_scorer.py` l.109 ; 5 × 1,00 × 1,00). **Le libellé « CVSS » n'est pas trouvé en sortie produit** : seul `reports/templates/report.html` l.857-858 l'affiche, et seulement si `cvss_score` n'est pas nul (**non vérifié** dans l'affichage terminal). Le constat « CVSS 5.0 affiché » du rapport global n'est donc pas établi par recherche statique.
- **Priorité** : **P2** (à confirmer avant correction).
- **Périmètre** : à confirmer ; `reports/templates/report.html` l.857-858 si le libellé est confirmé.
- **Dépendances** : aucune.
- **Critères** : une sortie contenant « CVSS » pour un `risk_score` est impossible.
- **Tests** : rendu d'un port `info` CONFIRMED sans `cvss_score`.
- **Statut** : **Partiel** ; à confirmer.

**SCO-02 — Port `info` CONFIRMED et OPEN dans le score global (B5-2).**
- **Anomalie** : `get_global_score` (`core/risk_scorer.py` l.207) n'exclut que `device_fingerprint` (`INVENTORY_MODULES`, l.101) ; un port `info` ouvert donne 5,0 (**Confirmé** par lecture).
- **Priorité** : **P2**.
- **Périmètre** : `core/risk_scorer.py` l.101, l.207.
- **Dépendances** : **DEC-07**.
- **Critères** : décision appliquée et testée.
- **Tests** : score global avec seul port `info` ouvert.
- **Statut** : **Décision** (produit).

**SCO-03 — Ports 512, 513, 514 sans règle (B5-3).**
- **Anomalie** : aucune entrée dans `cve_db.json`, `ports.json` (512-514 = `None`), `vulnerabilities.json`, ni dans le code (recherche complète).
- **Priorité** : **P3**.
- **Périmètre** : `knowledge/`, éventuellement une règle dédiée.
- **Dépendances** : **DEC-08** (risque voulu ou non).
- **Critères** : décision documentée.
- **Tests** : si règle ajoutée, avec source et sévérité justifiées.
- **Statut** : **Décision**.

### 3.8 Divers

**VERIFY-01 — Findings `sentinel.*` en PARTIAL « Unsupported module » (B1-1).**
- **Anomalie** : confirmé par lecture (rapport global §3.B1).
- **Priorité** : **P3**.
- **Périmètre** : module VERIFY.
- **Dépendances** : aucune.
- **Critères** : contrôle dédié ou décision de ne pas en avoir.
- **Tests** : à définir.
- **Statut** : **Décision** (contrôle dédié ou non).

**NET-01 — Réseau `192.168.57.0/24` surveillé de façon inattendue (C).**
- **Anomalie** : cause non établie. Le CIDR est celui passé à `--target` ; le code ne choisit pas ce réseau. `~/.netlab` n'a pas été lu (interdit par la mission).
- **Priorité** : **P1 provisoire** (P0 si un démarrage non voulu est confirmé). Aucun P0 n'est confirmé.
- **Périmètre** : aucun code. Diagnostic par le propriétaire (historique de commandes, `~/.netlab` sous sa responsabilité).
- **Dépendances** : DEC-10.
- **Critères** : cause identifiée par le propriétaire.
- **Tests** : aucun.
- **Statut** : **Hypothèse** ; pas de ticket de code.

**DOC-01 — Dérives de la documentation maître (DOC-1).**
- **Anomalie** : HEAD déclaré `3657498` (MASTER-REFERENCE §2 l.28 ; IMPLEMENTATION-TRACKING l.57) ; `9034f01` non consigné ; `CONFIDENCE-CLI` marqué « commit en attente » alors que `85870ac` est présent dans `origin/a4-arena` ; six commits non consignés (voir §6.4bis du MASTER-REFERENCE proposé). **Confirmé** par `git cat-file -e` et `git log`.
- **Priorité** : **P2**.
- **Périmètre** : `docs/MASTER-REFERENCE.md`, `docs/IMPLEMENTATION-TRACKING.md`. **Patches proposés** : `docs-proposees/MASTER-REFERENCE.md`, `docs-proposees/IMPLEMENTATION-TRACKING.md` (diffs dans `diffs/`).
- **Dépendances** : approbation du plan (DEC-02).
- **Critères** : HEAD et tous les commits cités existent ; statut CONFIDENCE-CLI conforme à la preuve.
- **Tests** : `git cat-file -e` sur chaque SHA cité.
- **Statut** : proposé (patch prêt, non appliqué).

**DOC-02 — Chemins et références non portables (DOC-2).**
- **Anomalie** : `/home/anonymous/sentinelX` (MASTER-REFERENCE l.26, l.310-311) ; Skills vers un chemin de steering en minuscules inexistant ; `ARENA.md` cité comme téléchargement propriétaire alors que le chemin réel est `uploads/ARENA.md`.
- **Priorité** : **P3**.
- **Périmètre** : `docs/`, `.kiro/skills/` (**Skills canoniques : ne pas modifier sans demande**).
- **Dépendances** : DEC-14.
- **Critères** : chemins vérifiables sur le dépôt.
- **Tests** : `ls` sur chaque chemin cité.
- **Statut** : proposé.

---

## 4. Ordre recommandé

Règles : **A1 avant D5** ; **D1 après D5** ; **D6 indépendant** ; le reste selon urgence et dépendances.

| Rang | Ticket | Motif | Bloqué par |
|---|---|---|---|
| 1 | SMB-01 | P1, indépendant, petit périmètre | — |
| 2 | TCP-01 | P1, base de A1 | — |
| 3 | TCP-02 | P1, cœur de A1 | TCP-01 |
| 4 | TCP-03 | P1, prévention des fermetures de masse, tests | TCP-02 |
| 5 | TCP-04 | P2, confirmation R7 et réserve | TCP-02 |
| 6 | CRED-01 | P1, emplacement du coffre | DEC-05 |
| 7 | TCP-05 | D5-B, après A1 | TCP-02 |
| 8 | TCP-06 | D1, après D5 | TCP-05, DEC-03 |
| 9 | SMB-02 | vérification (hypothèse) | — |
| 10 | TOOL-01 | P2 | SMB-02 |
| 11 | REP-01 | P2 | DEC-16 |
| 12 | A2-01 | P2 | DEC-11 |
| 13 | SCO-01 | P2, à confirmer | — |
| 14 | SCO-02 | P2, décision | DEC-07 |
| 15 | OS-01 | P2, mesure d'abord | DEC-12 |
| 16 | DOC-01 | P2, patch prêt | approbation du plan |
| 17 | D6-01 | P2, hors A1 | DEC-04 |
| 18 | CRED-02, CRED-03 | décision ; P3 | DEC-06 |
| 19 | SCO-03, VERIFY-01 | P3, décision | DEC-08, — |
| 20 | DOC-02, A2-02 | P3 | DEC-14 |
| — | NET-01 | diagnostic du propriétaire, hors code | DEC-10 |

---

## 5. Décisions restantes (à soumettre au propriétaire)

| Réf. | Point | Recommandation |
|---|---|---|
| DEC-01 | Emplacement canonique de la spec A1 | `docs/SENTINEL-TCP-STATES.md` |
| DEC-02 | Approbation du plan et des patches documentaires (`docs-proposees/`) | Approuver après revue Kiro |
| DEC-13 | Révision d'ARENA §9.6 (texte du §6) : acte du propriétaire, à faire dans ARENA | Décider après DEC-02 |
| DEC-03 | Libellé exact D1 | Non tranché ; proposition : « Port N closed (2 observations complètes consécutives) » pour les événements avec preuve ; « Port N not open (historique, preuve absente) » pour l'historique |
| DEC-04 | Politique des ports filtrés à l'apprentissage (D6) | C2 ou C3 ; statu quo D6-A = C1 en attendant |
| DEC-05 | Emplacement du coffre et migration (CRED-01) | Décision et procédure avant tout déplacement |
| DEC-06 | SSH : catalogue ou `--dict` seul (CRED-02) | Choix produit |
| DEC-07 | Port `info` ouvert dans le score global (SCO-02) | Non : inventaire, comme `device_fingerprint` |
| DEC-08 | Règle 512-514 (SCO-03) | Choix produit |
| DEC-09 | Libellé « CVSS » (SCO-01) | Renommer en « score de risque (interne) » si confirmé |
| DEC-10 | Réseau `192.168.57.0/24` (NET-01) | Diagnostic du propriétaire |
| DEC-11 | Résolution d'identifiants (A2-01) | Option (a), (b) ou (c) au choix |
| DEC-12 | Délai OS (OS-01) | Mesure d'abord ; délai configurable ensuite |
| DEC-14 | Chemins non portables (DOC-02) | Corriger en P3 |
| DEC-15 | Réserve redémarrages répétés (TCP-04, S3) | Accepter explicitement ou rejeter |
| DEC-16 | Libellé « Affichées » du rapport (REP-01) | « Notifications affichées sur 60 min » |

**Décisions déjà approuvées** (intégrées, non ouvertes) : remise à zéro sur hôte absent (V4) ; fermetures individuelles après deux `closed` explicites pour tous les ports connus ; aucun seuil global ; G-c reportée ; aucune fermeture sur `closed` → `filtered` ; validation XML commune ; D5-B ; D1 à deux catégories ; D6 hors A1 ; compteurs intermédiaires non restaurés.

---

## 6. Texte proposé pour ARENA §9.6 (non appliqué ; décision propriétaire)

ARENA §9.6 est déclaré « règle définitive ». Le texte actuel est incompatible avec les décisions approuvées sur un point : `[]` (scan complet, zéro `open`) incrémente aujourd'hui les compteurs, alors que seul un `closed` explicite doit compter. Proposition de remplacement de la section « Traitement TCP » :

> **Traitement TCP (révision proposée).**
> - Un compteur par port connu. Il n'est incrémenté que par une observation TCP complète où le port est explicitement `closed`.
> - Deux observations `closed` complètes et consécutives : `port_not_open`, compteur remis à zéro, port retiré de `known_open`. Pas de réémission tant que le port reste absent.
> - `filtered`, `open|filtered`, état inconnu ou invalide : remise à zéro du compteur du port, aucune conclusion.
> - `None` (scan incomplet) ou hôte sans observation TCP complète dans le cycle : remise à zéro du compteur de tous les ports de l'hôte.
> - `[]` (scan complet sans port `open`) : n'est pas une preuve de fermeture ; les compteurs des ports sont traités selon leur état explicite.
> - Un hôte entièrement `filtered` ne produit aucune fermeture.
> - Aucune fermeture confirmée sur passage `closed` → `filtered`.
> - Les compteurs intermédiaires ne sont pas restaurés après redémarrage.

---

## 7. Corrections apportées à l'audit (par rapport aux documents précédents)

| Élément | Avant | Après | Motif |
|---|---|---|---|
| B5-1 « CVSS » | Confirmé (P2) | **Partiel** | La valeur est un `risk_score` ; le libellé « CVSS » n'est pas trouvé en sortie (seul un gabarit HTML conditionnel) |
| B2-2 SSH | Reproduit, P2 | **Décision produit** | Choix documenté (rapport B2, P2 décision) ; pas une anomalie de code |
| B3-2 `--json` | Cause probable | **Hypothèse forte** | Non vérifiée avec le binaire installé |
| A1-1 (filtered) | P2 | **P1** | Fausse fermeture reproduite en chaîne (S7, S8) et règle approuvée |
| A1-2 (compteurs non restaurés) | P3, à corriger | **Décision approuvée (R7)** | Pas de ticket de restauration |
| Hôte absent (V4) | « conservé » | **Remise à zéro (approuvé)** | Décision propriétaire |
| P11, P12 | Non mesurés | **Mesurés** : `prod=[22]`, `valid=True` ; identiques run 4 et run 5 | `RAPPORT-verification-A1` §12 |
| Verdicts `conforme` de la section `parse` | Lus comme conformité spec | **Comportement de production attendu uniquement** | `RAPPORT-verification-A1` §12 |
| Spécification « référence » `/tmp/audit-spec-ref` | Cité | **Absent** ; clone `/tmp/audit-global-ref` | — |

---

## 8. Références de commits (`origin/a4-arena`, vérifiées par `git cat-file -e` et `git log`)

| Commit | Sujet (git) | Consigné dans docs ? |
|---|---|---|
| `365749878aa3e886da9cd33c2322fb75277c16ce` = `3657498` | feat(sentinel): implement T23-B network change detection | oui (HEAD déclaré, à corriger) |
| `13e7849` | fix Commit 3657498 (`requirements.txt`, 1 ligne) | non |
| `85870ac` | feat(cli): add confidence column to findings tables | non (marqué « en attente ») |
| `7ff3d89` | docs: add master reference, implementation tracking and agent skill | non |
| `63e1a7b` | feat(sentinel): interrupt nmap on stop request (point 1) | non |
| `b1ab727` | fix(sentinel): detect gateway on connected routes (point 2) | non |
| `e4f3f9e` | feat(sentinel): colour event types and label closed ports (ticket 3) | non |
| `9034f0131ebeaf63dc51bf217cea3ec3f6ab068e` = `9034f01` | feat(sentinel): number hosts in monitor table (ticket 4) | non (HEAD réel) |

Ordre git (`git log --reverse 3657498..9034f01`) : `85870ac`, `7ff3d89`, `13e7849`, `63e1a7b`, `b1ab727`, `e4f3f9e`, `9034f01`.

---

## 9. Réserves

- **R-1 Horloge.** La date du jour fournie est 2026-09-24. L'horloge de la sandbox indique 2026-11-12, et les dates de commit (2026-11-10 et 2026-11-11) sont postérieures à 2026-09-24. Aucune conclusion chronologique n'est tirée de ces dates. À vérifier par le propriétaire.
- **R-2** Structure réelle des `<extrareasons>` Nmap : non vérifiée hors fixtures. Le DTD valide le schéma seulement.
- **R-3** Sémantique réelle de `extraports state=open` : non vérifiée.
- **R-4** Comportement de `ScanDegradedError` en production au-delà des cas mesurés : non mesuré.
- **R-5** Lecteurs de `baseline.services` : grep non exhaustif ; aucun lecteur logique trouvé.
- **R-6** Le harnais `a1_chain_verify.py` remplace les sondes réseau ; un cycle = un appel de `_do_check`. Aucun scan réel.
- **R-7** `preuves/a1/a1_model_spec.py` est une spécification exécutable, pas une preuve de conformité.
- **R-8** Les constats B3, B4, A2, A3, B1 et B5 sont des lectures ou des reproductions en isolation ; aucun n'a été vérifié sur le poste du propriétaire.
- **R-9** `~/.netlab` : non lu ni modifié pendant ce plan (4744 entrées mesurées antérieurement). Aucun secret demandé.
- **R-10** Aucun ticket n'est présenté comme bug confirmé s'il ne l'est pas : SCO-01, SMB-02, OS-01, NET-01 restent en hypothèse, partiel ou décision.
- **R-11** Les clones locaux non alignés (`/home/user/sentinelX` `2eb1b20`, 27 modifs ; `sentinelX-impl` `13e7849`, 12 ; `sentinelX-reference` `2283166`, 6) n'ont pas été touchés.
- **R-12** Une revue indépendante (Kiro) est requise avant toute décision (DEC-02).
