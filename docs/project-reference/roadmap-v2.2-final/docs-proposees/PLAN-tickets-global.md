# Plan global de tickets — audit SentinelX (version 2.2, après seconde revue Kiro)

**Statut : PROPOSITION (version 2.2).** Ce document n'approuve, n'implémente et ne valide aucun ticket. Aucun fichier du dépôt n'est modifié. Aucun code, test, Skill, commit, push, nettoyage ni scan réel n'est effectué dans ce cycle.

| Élément | Valeur |
|---|---|
| Date de rédaction | **2026-11-12** |
| Date de référence de la mission | **12 novembre 2026** |
| Commit de référence | **`9034f01`** = `origin/a4-arena` (HEAD réel), commit daté 2026-11-11 (date git). Clone de lecture `/tmp/audit-global-ref`, arbre propre. |
| Autre branche citée | `main` = `8366722` : hors périmètre, non examinée |
| Dates des rapports antérieurs | Non réconciliées : les fichiers `RAPPORT-*` portent la date de leur dernière écriture (2026-11-12) ; leur date de rédaction d'origine n'est pas tracée. |
| Date 2026-09-24 | **N'est pas la date de rédaction** et n'est utilisée comme date de mission dans aucune version de ce plan. |
| Remplace | Version 1, archivée dans `docs-proposees/archive-v1/PLAN-tickets-global.md` |
| Revue | Kiro (revue indépendante, puis seconde revue : verdict « recevable après corrections », corrections V2.2 en §8) ; analyse de Nova (§12) |

---

## 0. Vocabulaire des statuts

Ces catégories ne doivent jamais être confondues.

| Statut | Signification |
|---|---|
| **Décision approuvée** | Arbitrée par le propriétaire. Ne pas la redemander. |
| **Proposition** | Texte, ticket ou spécification proposé, non approuvé. |
| **Ticket planifié** | Inscrit dans l'ordre de réalisation. Ne donne aucune autorisation d'implémentation. |
| **Conception approuvée** | La conception est approuvée, mais l'implémentation n'est pas autorisée (cas de D5-B). |
| **Autorisation d'implémentation** | Donnée explicitement par le propriétaire. **Aucune n'est donnée dans ce plan.** |
| **Ticket validé** | Implémenté, testé et accepté selon ses critères. **Aucun ticket n'est validé à ce jour.** |
| **Conforme** | Comportement vérifié comme conforme à une décision approuvée. **Pas de ticket.** |

---

## 1. Synthèse

- **A1 n'est pas terminé.** Il est présenté comme un ticket parent unique, « Fiabilisation des états TCP de Sentinel Monitor », proposé et non implémenté. Ses sous-tâches TCP-01 à TCP-03 seront implémentées, testées et acceptées ensemble ; elles ne sont pas des tickets autonomes. TCP-04 relève des non-régressions de A1. Aucune autorisation d'implémentation n'est donnée.
- **Ordre** : Étape 0 (mise à jour documentaire, §5.0) avant toute implémentation, puis **SMB-01** (`smb_enum` lit un échec d'outil comme une absence de résultat).
- **Anomalies retirées ou reclassées** après revue Kiro : CRED-02 (conforme, sans ticket), NET-01 (non reproduite, sans ticket de code, P1 provisoire retiré).
- **Décisions déjà approuvées** et intégrées au plan (§2) : elles ne sont plus posées comme questions.
- **Décisions ouvertes** : 12 points restent à arbitrer par le propriétaire (§3).

---

## 2. Décisions approuvées (intégrées, non redemandées)

| Réf. | Décision | Effet dans le plan |
|---|---|---|
| A-V4 | Hôte absent du cycle : remise à zéro des compteurs de ses ports | A1, CA-15 |
| A-G-a | Fermeture individuelle après deux observations `closed` explicites consécutives, pour chaque port connu | A1 |
| A-G-b | Aucun seuil global (écartée) | A1 |
| A-G-c | Reportée, hors A1 | Non planifiée |
| A-closed-filtered | Aucune fermeture confirmée sur passage `closed` → `filtered` (réserve à consigner) | A1 |
| A-XML | Validation XML commune au monitor et à l'apprentissage de baseline | A1 (TCP-01) |
| A-R7 | Compteurs intermédiaires non restaurés après redémarrage | A1 (TCP-04) |
| A-R7-risque | Redémarrages répétés sans fermeture confirmée : **conséquence documentée de R7**, non soumise à arbitrage | A1, documentation |
| D5-B | Preuve de fermeture dans `events.details` : **conception approuvée, implémentation non autorisée** | D5 |
| D1-forme | Distinction à deux catégories : événements avec preuve / historiques sans preuve | D1 (le libellé reste ouvert, DEC-03) |
| D6-indép | D6 est un ticket indépendant hors A1 ; DEC-04 n'est pas un bloqueur de A1 | D6 |
| CRED-02 | Comportement conforme à `docs/T22-CREDENTIALS.md` : SSH uniquement via `--service ssh`, sans candidat SSH générique. Sans ticket et sans ajout de candidat. | Conforme |
| NET-01 | Anomalie non reproduite. `--target` est obligatoire et le code ne choisit pas le réseau. Pas de ticket de code. | Non reproduite |
| ARENA-9.6 | ARENA §9.6 est supersédée par la politique A1 approuvée. | Mise à jour proposée dans `docs-proposees/` ; le document maître officiel est `docs/MASTER-REFERENCE.md` |

---

## 3. Décisions ouvertes (à soumettre au propriétaire)

| Réf. | Point | Recommandation ou état |
|---|---|---|
| DEC-02 | Validation du plan et des propositions documentaires | Condition de l'Étape 0 (§5.0) : à valider avant toute implémentation |
| DEC-03 | Libellé exact de D1 | Non tranché. Proposition : « Port N closed (2 observations complètes consécutives) » pour les événements avec preuve ; « Port N not open (historique, preuve absente) » pour l'historique. Le libellé exact reste à arbitrer. |
| DEC-04 | Politique D6 : C2 ou C3 (statu quo D6-A = C1) | Examinée au moment du ticket D6. **Non bloquant pour A1.** |
| DEC-05 | Emplacement et procédure de migration, **seulement si** CRED-01 retient un changement de chemin | Décision et procédure avant tout déplacement de coffre ou de base |
| DEC-07 | Port `info` ouvert dans le score global (SCO-02) | Proposition : non, comme `device_fingerprint` (inventaire) |
| DEC-08 | Règle 512-514 (SCO-03) | Choix produit |
| DEC-09 | Libellé « CVSS » (SCO-01) | Renommer en « score de risque (interne) » si le libellé est confirmé |
| DEC-11 | Résolution d'identifiants (A2-01) | Option (a), (b) ou (c) |
| DEC-12 | Délai OS (OS-01) | Mesurer d'abord ; délai configurable ensuite |
| DEC-14 | Chemins absolus non portables : `docs/MASTER-REFERENCE.md` (corrigé en DOC-02) et défauts de code `core/dependencies.py` l.48-49 ; message `core/database.py` l.85 (`/root/.netlab`) | Correction documentaire proposée ; les défauts et messages de code relèvent d'une décision séparée |
| DEC-16 | Libellé « Affichées » du rapport (REP-01) | Proposition : « Notifications affichées sur 60 min » |
| DEC-17 | Normalisation Unicode de la phrase du coffre (NFC/NFD, `core/credential_vault.py` l.97-99) | Constat distinct (§4.3). Toute normalisation change la clé des coffres existants : stratégie de compatibilité à arbitrer avant tout ticket. Aucune migration. |

**Retirés de la liste** (ne sont plus des questions) :
- **DEC-01** (emplacement de la spec A1) : remplacé par une **proposition** justifiée, `docs/SENTINEL-TCP-STATES.md`, à faire vérifier par Kiro. La convention de nommage est celle des autres fichiers de `docs/` : `SENTINEL-LIFECYCLE.md`, `SENTINEL-NOTIFICATIONS.md`, `SENTINEL-FINDINGS.md`.
- **DEC-06** (SSH) : CRED-02 est conforme.
- **DEC-10** (réseau `192.168.57.0/24`) : NET-01 n'est pas reproduit.
- **DEC-13** (révision ARENA §9.6) : supersédée par la politique A1 approuvée.
- **DEC-15** (réserve redémarrages) : conséquence documentée de R7 (§2).

**Points à vérifier (ne sont pas des décisions)** :
- Rôle de `ARENA.md` : ce fichier n'est pas dans le dépôt. Il est cité en révision 13 (`docs/MASTER-REFERENCE.md` l.5 et l.282) et en révision 12 (l.114). La copie de travail de l'environnement d'audit est `/home/user/uploads/ARENA.md`. Son statut canonique est à vérifier par le propriétaire et par Kiro.
- Structure réelle des `<extrareasons>` et sémantique réelle de `extraports state=open` (Nmap) : non vérifiées hors fixtures.
- Dossier réellement examiné par Kiro : `docs-processes/` et les fichiers `(1)`/`(2)` n'existent pas dans l'environnement d'audit (`find -xdev /` sans résultat). Ce dossier est à identifier.

---

## 4. Tickets

Format : identifiant · anomalie · preuve · priorité · périmètre · dépendances · critères · tests · statut · ticket suivant (désigné à la validation).

### 4.1 Sentinel — états TCP

#### A1 — Fiabilisation des états TCP de Sentinel Monitor (ticket parent unique)

- **Anomalie** : états `filtered`, `open|filtered` et inconnus réduits à « absence de `open` » ; `states` jeté (`detect/tcp_scan.py` l.601, dans `parse_sentinel_open_ports` définie l.558) ; fermetures sur séquences `filtered` ou `open|filtered` (S7, S8, mesurés) ; fermeture de masse d'un hôte entièrement filtré (S11, mesuré) ; hôte absent qui conserve ses compteurs (S5, mesuré) ; attributions XML ambiguës acceptées (P1-P7, P11, P12 : `prod=[22]`, mesuré).
- **Preuves** : `preuves/a1/a1_chain_verify.json` et `a1_chain_verify-run5.json` (identiques sur les sections `parse` et séquences) ; `RAPPORT-verification-A1-chaine-production.md` §12 ; spécification `docs-proposees/SENTINEL-TCP-STATES.md`.
- **Priorité** : **P1**.
- **Statut** : **Non terminé ; proposé, non implémenté.** Ticket parent proposé. Spécification `docs-proposees/SENTINEL-TCP-STATES.md` proposée, non encore approuvée comme spécification de référence. **Aucune autorisation d'implémentation.**
- **Dépendances** : **aucune**. A1 ne dépend ni de D5 ni de D6.
- **Périmètre** : `detect/tcp_scan.py` (`_recorded_port_states` l.337, `_parse_tcp_xml_with_states` l.444, `parse_sentinel_open_ports` définie l.558, `states` jeté l.601) ; `sentinel/monitor.py` (`_get_open_ports` l.264 ; import l.276 ; appel `_run_nmap_tcp(strict=True)` l.277-281 ; `parse_sentinel_open_ports` l.282) ; `sentinel/baseline.py` (`learn_baseline` l.431 ; validation l.480-490 ; appel `_run_nmap_tcp` **sans** `strict=True` l.481-483) ; `sentinel/sentinel_manager.py` (`NetworkState.port_absent_count` l.291 ; `_rebuild_transition_state` l.300-362 ; `_compute_port_transitions` l.460-505 ; `_do_check` l.594 ; bloc `except ScanFailedError` l.629-636 avec vidage l.632-633).
- **Inclus dans A1** : hôte absent (remise à zéro) ; hôte entièrement filtré (aucune fermeture) ; fermetures individuelles après deux `closed` explicites pour chaque port connu ; `closed → filtered` (aucune fermeture) ; prévention des attributions XML ambiguës ; validation XML commune ; compteurs non restaurés (R7).
- **Exclu de A1** : D5, D1, D6, le libellé D1, CA-16 (rattaché à D1), CRED-*, SMB-*, et tout seuil global (G-b écartée, G-c reportée).

**Sous-tâches internes** (non autonomes : elles seront implémentées, testées et acceptées **ensemble** dans le ticket parent) :

| Sous-tâche | Contenu | Périmètre principal |
|---|---|---|
| **TCP-01** | Parsing, attribution et représentation des états TCP ; validation XML commune monitor / baseline (l'appel baseline passe au même mode `strict=True` que le monitor) ; refus des attributions ambiguës. Attendu : P1 à P7, P11 et P12 refusés (production accepte `[22]`). | `detect/tcp_scan.py`, `sentinel/monitor.py`, `sentinel/baseline.py` |
| **TCP-02** | Un compteur par port connu. Fermeture après deux `closed` explicites consécutifs. Remise à zéro sur `filtered`, `open\|filtered`, état inconnu, `None`, hôte absent. Aucune fermeture sur `closed → filtered`. | `sentinel/sentinel_manager.py` |
| **TCP-03** | Hôte entièrement filtré : aucune fermeture. Tests de séquence S1 à S11 (fixtures XML, sans scan réel). | Tests et garde |
| **TCP-04** | Non-régressions R7 : compteurs non restaurés après redémarrage (S2, S3, S10). Inscrit dans les non-régressions de A1. | `_rebuild_transition_state` |

- **Critères d'acceptation** : CA-1 à CA-15, CA-17 et CA-18 de `docs-proposees/SENTINEL-TCP-STATES.md` (§9.1). **CA-16 est rattaché à D1** (§9.2) et n'est pas un critère A1 : A1 n'exige ni la clé `proof` ni un changement de libellé. Cas de référence : S1 à S11, P1 à P12. (L1 et L2 relèvent de D6, hors A1.)
- **Écart mesuré à corriger** : S5, S7, S8, S11 (non conformes) ; P1 à P7, P11, P12 (non conformes).
- **Tests** : `tests/test_tcp_scan.py` (ajouts : `filtered`, `open|filtered`, `unfiltered`, sans état, `bogus`, attributions `<extraports>`) ; `tests/test_sentinel_manager.py` (révision de `test_port_not_open_after_two_complete_scans_then_never_repeated` l.429-440 ; conserver l.450-455 et l.487-497 ; ajout d'absence d'hôte pendant un cycle, aucun test existant) ; `tests/test_sentinel_baseline*.py` (XML ambigu : baseline inchangée).
- **Réserves** : harnais avec sondes remplacées (un cycle = un appel de `_do_check`) ; passage `closed → filtered` en cycle réel non mesuré ; `ScanDegradedError` en production non mesuré au-delà des cas testés.

#### D5 — Preuve de fermeture dans `events.details` (D5-B)

- **Anomalie** : `evidence` n'est pas persistée (`sentinel/alerting.py`, `NO_FINDING_TYPES` l.67) ; une fermeture ne garde aucune trace de sa justification.
- **Statut** : **Conception approuvée (D5-B). Implémentation non autorisée.** Ticket planifié **après A1**.
- **Priorité** : P3 (demande du propriétaire ; faible risque).
- **Dépendances** : **A1** (le compteur consécutif est la source de la preuve).
- **Périmètre** : `sentinel/alerting.py` (`_detail_extras` l.138, `process_changes` l.149, `details` l.168) ; `core/database.py` (`sentinel_save_event` l.1572-1586). Aucun changement de schéma.
- **Critères** : `SENTINEL-TCP-STATES.md` §7.1 (clé `proof`) ; CA-11 (anciens événements inchangés). D5 produit la preuve dans `events.details` ; D1 l'utilise. Clés proposées : `proof = {observed, consecutive, scan, run}` (à valider au ticket).
- **Tests** : nouvel événement avec `proof` ; ancien événement inchangé ; lecteurs de `details` ignorent la clé (`sentinel/sentinel_manager.py` l.331-355, `sentinel/notifications.py` l.32-60, `reports/sentinel_report.py` l.27-35) ; reprise au démarrage (`tests/test_sentinel_lifecycle.py`).
- **Ticket suivant** : D1.

#### D1 — Présentation : distinction preuve / historique

- **Anomalie** : « Port N closed » est affiché pour tout `port_not_open`, y compris pour les anciens événements (libellé répété trois fois) ; le rapport HTML affiche `details['detail']` brut.
- **Statut** : **distinction approuvée** (deux catégories). **Libellé non tranché** (DEC-03). Ticket planifié **après D5**.
- **Priorité** : P2.
- **Dépendances** : **D5** (la distinction exige la preuve) ; **DEC-03** (libellé exact). Aucun changement de libellé avant DEC-03.
- **Périmètre** : `sentinel/monitor_view.py` (`_PORT_NOT_OPEN_DETAIL` l.49, `presentation_detail` l.52-61) ; `reports/sentinel_report.py` l.27-35 ; `tests/test_sentinel_event_display.py` l.76-82 (à réviser).
- **Critères** : `SENTINEL-TCP-STATES.md` §7.3 ; CA-16 (rattaché à D1, §9.2). D1 utilise la preuve produite par D5 pour distinguer événements nouveaux et historiques.
- **Tests** : événement avec preuve vs historique sans preuve.
- **Ticket suivant** : selon l'ordre (§5), TOOL-01.

#### D6 — Politique des ports filtrés à l'apprentissage baseline (ticket indépendant hors A1)

- **Anomalie** : `learn_baseline` accepte un hôte entièrement filtré avec baseline `{}` ; chaque port ouvert ensuite produit `new_port` (L1 et L2, mesurés ; `sentinel/baseline.py` l.480-490).
- **Statut** : **Proposition**, ticket indépendant **hors A1**.
- **Priorité** : P2.
- **Dépendances** : aucune pour A1. **DEC-04** (C2, C3 ou statu quo) est examinée au moment du ticket D6.
- **Périmètre** : `sentinel/baseline.py` ; `core/database.py` (`baseline.services` écrit `"{}"` l.1543 ; aucun lecteur logique trouvé, grep non exhaustif).
- **Critères** : à rédiger après DEC-04.
- **Tests** : L1 (80 filtré puis ouvert → `new_port`) et L2 (hôte entièrement filtré appris, puis `new_port`) ; contrat de `services` si la politique le modifie.

### 4.2 Outils externes

#### SMB-01 — `smb_enum` : échec d'outil présenté comme absence de résultat

- **Anomalie** (confirmée en isolation) :
  - le code de retour est ignoré (`check=False`, `detect/smb_enum.py` l.157) ; commande `-A --json` l.150 et commande affichée l.183 ;
  - stdout et stderr sont fusionnés (l.169) ; le stderr est donc lu comme des données ;
  - un faux binaire rc=2 produit « no shares or domain info » (l.133) et 0 finding ;
  - repli texte : la regex `Account:\\s*(\\S+)` (l.509, chaîne brute) ne lit pas « Account: alice ». Reproduit par fonction pure : aucune correspondance, `users=()`.
- **Constat rapporté** : l'export JSON de `enum4linux-ng` est `-oJ OUT_JSON_FILE` et `--json` n'existe pas dans la version 1.3.10. Constat **rapporté par le propriétaire, vérifié sur son poste** ; non reproduit dans l'environnement d'audit (`enum4linux-ng` absent).
- **Priorité** : **P1** (faux négatif sur un outil de sécurité).
- **Statut** : **Proposition**. Premier ticket de l'ordre. Aucune autorisation d'implémentation.
- **Dépendances** : Étape 0 (§5.0). La vérification de compatibilité est SMB-02, exécutée dans le cadre de ce ticket.
- **Périmètre** : `detect/smb_enum.py` (`_run_enum4linux_ng` l.138-173, commande l.150, `check=False` l.157, concaténation l.169, message l.183, `_normalize_text_output` l.486, regex l.509) ; `tests/test_smb_enum.py` l.122 (fige `-A --json <ip>`, à réviser).
- **Critères** :
  1. commande compatible avec la version installée (vérifiée par SMB-02) ;
  2. lecture du fichier JSON produit par `-oJ <fichier>` ;
  3. code retour non nul → erreur explicite, aucun finding, message distinct de « no shares » : **un code non nul n'est jamais assimilé à « aucun résultat »** ;
  4. stdout et stderr séparés ; stderr jamais parsé comme donnée ;
  5. repli texte : lit « Account: alice » ;
  6. fichier JSON absent ou invalide → erreur explicite.
- **Tests** : faux binaire rc=2 (HOME temporaire) ; code 0 sans JSON ; JSON valide ; regex sur « Account: alice ». Aucune exécution d'`enum4linux-ng` réel.
- **Ticket suivant** : A1.

#### SMB-02 — Vérification de compatibilité d'`enum4linux-ng`

- **Nature** : **vérification**, non une hypothèse sur `--json`. Remplace la formulation v1 « `--json` probablement inexistant ».
- **Contenu** : lecture de `--help` et de la version installée, sans scan. Consigner la version (1.3.10 rapportée) et les options réellement présentes (`-A`, `-oJ`).
- **Critères** : version et options consignées dans le ticket SMB-01 ; aucune option supposée.
- **Priorité** : P2, intégrée à SMB-01.

#### TOOL-01 — `netlab doctor` ne vérifie que `--help`

- **Anomalie** : un `--help` réussi ne prouve pas l'existence des options utilisées (`core/dependencies.py` `_detect_ng_version` l.141-152, appel `--help` l.152 ; confirmé par lecture).
- **Statut** : Proposition. **P2.** Dépend de SMB-02.
- **Critères** : `doctor` signale une option absente de la version installée.
- **Tests** : faux binaire sans l'option → signalé.

### 4.3 Credentials et coffre

#### CRED-01 — Coffre et bases sous `Path.home()` ≠ `_real_user_home()` sous sudo

- **Anomalie** : sous `sudo`, le coffre peut être créé sous `/root` (reproduit par simulation de chemin ; rapport B2).
- **Priorité** : **P1**.
- **Statut** : Ticket planifié, **après A1**. **DEC-05** requise avant toute implémentation touchant un chemin de coffre ou de base.
- **Périmètre** : résolveurs de chemins seulement. `Path.home()` (sans `_real_user_home()`) : `core/credential_vault.py` l.35 (coffre) ; `sentinel/whitelist.py` l.37 ; `detect/default_creds.py` l.221 ; `core/dependencies.py` l.174 ; `cli.py` l.1805 (rapports) ; `cleanup/restore.py` l.181 et l.193 ; `cleanup/artifact_detector.py` l.128 et l.146. `_real_user_home()` : `core/database.py` l.56-88. **Un chemin n'est changé que si sa divergence sous sudo est démontrée** ; la simulation (`env -i`, `HOME=/root`, `SUDO_USER=user`) montre `Path.home()` = `/root` et `_real_user_home()` = `/home/user`. Chaque site est confirmé par test avant tout changement.
- **Critères** : chaque chemin modifié résout vers l'utilisateur réel sous sudo (test simulé) ; aucun autre chemin modifié ; test sans coffre réel.
- **Tests** : HOME et coffre temporaires uniquement ; sudo simulé.
- **Interdiction** : aucune migration, aucun déplacement, aucune suppression de coffre sans décision.
- **Ticket suivant** : D5.

#### Constat distinct — normalisation Unicode de la phrase du coffre (sans ticket)

- **Constat** : `core/credential_vault.py` l.97-99 (`_derive`) encode la phrase en UTF-8 sans normalisation. Une même phrase saisie en NFC puis en NFD produit des octets différents, donc une clé scrypt différente (démontré sur une chaîne synthétique, paramètres réduits ; aucune phrase réelle utilisée).
- **Statut** : constat, **sans ticket**. Toute modification changerait la clé des coffres existants : stratégie de compatibilité à arbitrer (**DEC-17**) avant tout ticket.
- **Interdiction** : ne jamais demander, reproduire ni journaliser la phrase réelle.

#### CRED-02 — SSH sans candidat : **conforme, sans ticket**

- **Constat** : `docs/T22-CREDENTIALS.md` définit SSH comme explicite. SSH n'est contrôlé que par `--service ssh`. Sans candidat SSH (catalogue sans profil SSH, ou `--dict` sans ligne `ssh`), la commande échoue explicitement. Un profil SSH produit (par exemple `--profile dell-idrac-legacy-root`) reste utilisable.
- **Décision** : comportement **conforme** à T22. **Aucun ticket. Aucun ajout de candidat SSH générique.**

#### CRED-03 — Message de coffre incomplet

- **Anomalie** : la règle des 8 caractères distincts n'apparaît pas dans le message (lecture).
- **Priorité** : P3. Proposition. Aucune dépendance.
- **Critères** : message complet, sans révéler de valeur. **Tests** : le message contient la règle ; aucun secret journalisé.

### 4.4 Reporting, scoring, découverte et identifiants

#### REP-01 — « 0 » du rapport = quota de notification

- **Anomalie** : le « 0 » de la colonne « Affichées » est le quota 60 min par couple réseau/IP (`sentinel/notifications.py` `WINDOW` l.7, `LIMIT` l.8). Un `new_port` de deux heures s'affiche « 0 » (reproduit).
- **Périmètre** : `reports/templates/sentinel_status.html` l.28 (« quotas par hôte à la génération (60 dernières minutes) ») ; `sentinel/monitor_view.py` l.122 (« Affichées ») et l.129 (« Affichées (60 min) ») ; `sentinel/notifications.py` `WINDOW` l.7 et `LIMIT` l.8 ; `tests/test_sentinel_presentation.py` l.55 (asserte « Affichées »).
- **Priorité** : P2. **Dépend de DEC-16.**
- **Critères** : le libellé indique « notifications affichées sur 60 min », pas « événements ». **Tests** : rendu HTML d'un réseau avec événement hors fenêtre.

#### OS-01 — Timeouts OS Nmap et « no usable fingerprint »

- **Anomalie** : `timeout=60` codé en dur (`recon/device_fingerprint.py` l.196, dans `_run_nmap_os` l.181) ; sortie partielle perdue à l'échéance (`core/process_control.py`) ; deux messages distincts sous un même libellé. **Causes non mesurées.**
- **Statut** : **Hypothèse**. Mesurer avant de corriger. **P2.** **DEC-12** requise pour le délai.
- **Critères** : temps réel mesuré sur hôte de test autorisé ; messages distincts pour timeout et absence d'`osmatch`.

#### SCO-01 — Libellé « CVSS » (Partiel)

- **Constat** : la valeur « 5.0 » est un `risk_score` (formule à `core/risk_scorer.py` l.113). Le libellé « CVSS » n'est pas trouvé dans la sortie produit ; seul un gabarit HTML conditionnel (`reports/templates/report.html` l.857-858) l'affiche, si `cvss_score` n'est pas nul. **Partiel.** P2, à confirmer. **DEC-09.**

#### SCO-02 — Port `info` CONFIRMED et OPEN dans le score global

- **Anomalie** : `get_global_score` (`core/risk_scorer.py` l.207) n'exclut que `device_fingerprint` (`INVENTORY_MODULES` l.101). **Décision produit** ; **DEC-07**. P2.

#### SCO-03 — Ports 512, 513, 514 sans règle

- **Constat** : aucune entrée dans `cve_db.json`, `ports.json` (512-514 = `None`) ni `vulnerabilities.json`. **Décision produit** ; **DEC-08**. P3.

#### A2-01 — Résolution d'identifiants incohérente

- **Anomalie** : `core/database.py` `resolve_finding_id` l.597 et `sentinel_read_finding` l.2034 : règles différentes. **DEC-11.** P2.
- **Critères** : même règle pour `findings show` et `sentinel findings show`.

#### A2-02 — Nom de commande dans la demande

- **Constat** : `findings rescan` existe ; « rescan findings » n'existe pas. Documentation seulement. P3.

#### VERIFY-01 — Findings `sentinel.*` en PARTIAL « Unsupported module »

- **Constat** : confirmé par lecture. **Décision** : contrôle dédié ou non. P3.

#### DOC-01 — Dérives de la documentation maître

- **Anomalie** : HEAD déclaré `3657498` (`docs/MASTER-REFERENCE.md` §2 l.28 ; `docs/IMPLEMENTATION-TRACKING.md` l.57) alors que le HEAD réel est `9034f01` ; `CONFIDENCE-CLI` marqué « commit en attente » (`docs/MASTER-REFERENCE.md` l.163) alors que `85870ac` est présent dans `origin/a4-arena` ; six commits non consignés. **Confirmé** par `git cat-file -e` et `git log`.
- **Statut** : **Proposition** ; patchs prêts dans `docs-proposees/` (non appliqués à `docs/`). **P2.** **Dépend de DEC-02.** **Hors séquence des tickets : traité par l'Étape 0 (§5.0), avant SMB-01.**
- **Critères** : HEAD et tous les SHA cités existent ; statut CONFIDENCE-CLI conforme à la preuve.

#### DOC-02 — Chemins et références non portables

- **Constats reproduits** :
  - `.cursor/rules/sentinelX.mdc` l.9 : référence `.kiro/steering/sentinelx.md` en minuscules. Le fichier réel est `.kiro/steering/sentinelX.md` (majuscule X). Le chemin est cassé sous Linux. **Reproduit** (ls).
  - Chemins absolus démontrés : `docs/MASTER-REFERENCE.md` l.26 et l.310-311 (`/home/anonymous/sentinelX`). **Constat conservé** ; correction proposée dans `docs-proposees/` (non appliquée à `docs/`).
- **Constats retirés** :
  - `.kiro/skills/impl-tracking.md` ne référence pas le steering : **pas de constat de casse sur ce Skill**. Le Skill canonique n'est pas modifié ; la proposition de Skill Kiro (correction de date) est **retirée du paquet actif** (V2.2) ; le fichier reste dans le dossier d'audit.
- **Hors périmètre documentaire (décision séparée, DEC-14)** : `core/dependencies.py` l.48-49 (défauts `/home/anonymous/enum4linux-ng/...`). Non modifié.
- **Références non portables à « téléchargements du propriétaire »** : `docs/MASTER-REFERENCE.md` l.5 et l.282 ; `docs/IMPLEMENTATION-TRACKING.md` l.5. **ARENA.md** est hors dépôt (`git ls-files` sans résultat) ; son rôle est à vérifier (§3).
- **Priorité** : P3. Aucune dépendance.
- **Périmètre** : `docs/` (propositions dans `docs-proposees/`) ; `.cursor/rules/sentinelX.mdc` (diff limité à la casse). **Aucun Skill canonique n'est modifié.**
- **Tests** : `ls` sur chaque chemin cité.

### 4.5 Net — hors code

#### NET-01 — Réseau `192.168.57.0/24` : **non reproduit, sans ticket de code**

- **Constat** : anomalie « réseau surveillé de façon inattendue » **non reproduite**. Le réseau est fourni explicitement via `--target` (**obligatoire**) ; rien dans le code ne le sélectionne.
- **Décision** : pas de ticket de code. **Le P1 provisoire et DEC-10 sont retirés.**
- **Limite** : `~/.netlab` n'a pas été lu (interdit par la mission).

---

## 5. Ordre de réalisation

### 5.0 Étape 0 — Mise à jour documentaire préalable

- **Nature** : étape documentaire, **hors séquence des tickets techniques**. Elle sort DOC-01 (§4.4) de la séquence.
- **Contenu** :
  - Master Reference : `docs/MASTER-REFERENCE.md` (patch de référence : `diffs/master-reference.diff`) ;
  - Implementation Tracking : `docs/IMPLEMENTATION-TRACKING.md` (patch : `diffs/impl-tracking.diff`) ;
  - spécification canonique A1 : `docs/SENTINEL-TCP-STATES.md`, emplacement proposé (patch : `diffs/SENTINEL-TCP-STATES.diff`) ;
  - réconciliation DOC-01 des commits et références (HEAD déclaré, CONFIDENCE-CLI, six commits non consignés).
- **Entrée** : validation du plan par le propriétaire (DEC-02).
- **Condition de sortie** (toutes requises) :
  1. patch documentaire **appliqué par le propriétaire** (aucun agent n'écrit dans `docs/`) ;
  2. dépôt vérifié : HEAD, SHA cités et statut CONFIDENCE-CLI conformes à `git log` et `git cat-file -e` ;
  3. décisions et spécifications présentes dans les fichiers canoniques (bloc « Décisions A1 approuvées », spécification A1, critères CA).
- **Suivant** : **SMB-01**. Aucune étape technique n'est avancée ni modifiée par l'Étape 0.

### 5.1 Séquence technique

Règles : SMB-01, puis A1 (unité complète), puis CRED-01, puis D5 **après A1**, puis D1 **après D5**. Les autres tickets suivent leurs dépendances et leur priorité. **D6 est indépendant** et n'entre dans aucune séquence. Le « suivant » est désigné au moment de la validation du ticket. **SMB-01 ne commence qu'après l'Étape 0.**

| Rang | Ticket | Priorité | Statut | Bloqué par | Suivant (si validé) |
| 0 | Étape 0 (§5.0) : DOC-01, Master, Tracking, spec A1, réconciliation | — | Préalable ; après validation du plan | DEC-02 | SMB-01 |
|---|---|---|---|---|---|
| 1 | SMB-01 (+ SMB-02) | P1 | Proposition | Étape 0 | A1 |
| 2 | A1 (TCP-01 à TCP-04) | P1 | Proposé, non implémenté ; autorisation requise | — | CRED-01 |
| 3 | CRED-01 | P1 | Planifié, après A1 | A1 ; DEC-05 | D5 |
| 4 | D5 | P3 | Conception approuvée ; implémentation non autorisée | A1 | D1 |
| 5 | D1 | P2 | Distinction approuvée ; libellé ouvert | D5, DEC-03 | TOOL-01 |
| 6 | TOOL-01 | P2 | Proposition | SMB-02 (dans SMB-01) | REP-01 |
| 7 | REP-01 | P2 | Proposition | DEC-16 | OS-01 |
| 8 | OS-01 | P2 | Hypothèse ; mesure d'abord | DEC-12 | SCO-01 |
| 9 | SCO-01 | P2 | Partiel ; à confirmer | DEC-09 | SCO-02 |
| 10 | SCO-02 | P2 | Décision produit | DEC-07 | A2-01 |
| 11 | A2-01 | P2 | Proposition ; décision | DEC-11 | CRED-03 |
| 12 | CRED-03 | P3 | Proposition | — | SCO-03 |
| 13 | SCO-03 | P3 | Décision produit | DEC-08 | VERIFY-01 |
| 14 | VERIFY-01 | P3 | Décision | — | DOC-02 |
| 15 | DOC-02 | P3 | Proposition | — | A2-02 |
| 16 | A2-02 | P3 | Proposition | — | — |
| — | D6 | P2 | Proposition ; **indépendant** | DEC-04 (au moment du ticket) | — |
| — | CRED-02 | — | **Conforme, sans ticket** | — | — |
| — | NET-01 | — | **Non reproduite, sans ticket** | — | — |

Tableau détaillé des tickets et dépendances : `docs-proposees/TABLEAU-tickets-dependances.md`.

---

## 6. Texte proposé pour ARENA §9.6 (non appliqué)

ARENA §9.6 est supersédée par la politique A1 approuvée. La mise à jour proposée se trouve dans `docs-proposees/` ; **`docs/` n'est pas modifié**. Le texte de §9.6 (révision 13) est incompatible sur ce point : `[]` (scan complet sans `open`) incrémente les compteurs, alors que la politique A1 approuvée ne retient qu'un `closed` explicite.

> **Traitement TCP (révision proposée).**
> - Un compteur par port connu. Il n'est incrémenté que par une observation TCP complète où le port est explicitement `closed`.
> - Deux observations `closed` complètes et consécutives : `port_not_open`, compteur remis à zéro, port retiré de `known_open`. Pas de réémission tant que le port reste absent.
> - `filtered`, `open|filtered`, état inconnu ou invalide : remise à zéro du compteur du port, aucune conclusion.
> - `None` (scan incomplet) ou hôte sans observation TCP complète dans le cycle : remise à zéro du compteur de tous les ports de l'hôte.
> - `[]` (scan complet sans port `open`) : n'est pas une preuve de fermeture ; les compteurs sont traités selon l'état explicite de chaque port.
> - Un hôte entièrement `filtered` ne produit aucune fermeture.
> - Aucune fermeture confirmée sur passage `closed` → `filtered`.
> - Les compteurs intermédiaires ne sont pas restaurés après redémarrage.

---

## 7. Correspondance des anciens identifiants

| Ancien identifiant (v1 et sources) | Nouveau traitement |
|---|---|
| A1-1 (`filtered` → fermeture) | A1 (TCP-01, TCP-02) |
| A1-2 (compteurs non restaurés) | A1 (TCP-04, R7) |
| A1-2 complément (hôte entièrement filtré) | A1 (TCP-03) |
| A1-3 (états non prévus fail-open) | A1 (TCP-01) |
| A1-4 (trois libellés) | D1 |
| A1-5 (`states` jetés) | A1 (TCP-01) |
| A1-6 (compteurs non reconstruits) | A1 (TCP-04, R7) |
| A1-7 (baseline sous filtrage → `new_port`) | D6 (hors A1) |
| A1-8 (`evidence` non persistée) | D5 |
| TCP-05 (v1) | **D5** |
| TCP-06 (v1) | **D1** |
| TCP-04 (v1, autonome) | **Sous-tâche de non-régression de A1** (plus de ticket autonome) |
| B2-1 | CRED-01 |
| B2-2 (SSH) | **CRED-02, conforme** (plus de ticket) |
| B2-3 | CRED-03 |
| B3-1, B3-3 | SMB-01 |
| B3-2 (`--json`) | SMB-02, **vérification** (plus d'hypothèse sur `--json`) |
| B3-4 | TOOL-01 |
| A2-1 | A2-01 |
| A2-2 | A2-02 |
| A3-1 | REP-01 |
| B1-1 | VERIFY-01 |
| B4-1, B4-2 | OS-01 |
| B5-1, B5-2, B5-3 | SCO-01, SCO-02, SCO-03 |
| C-1 (réseau `192.168.57.0/24`) | NET-01, **non reproduit, sans ticket** |
| DOC-1 | DOC-01 (Étape 0) |
| DOC-2 | DOC-02 |

---

## 8. Corrections apportées par rapport à la version 1

| Élément | Version 1 | Version 2 | Motif (revue Kiro, sauf mention) |
|---|---|---|---|
| Date de rédaction | 2026-09-24 | **2026-11-12** | Date de mission de référence |
| A1 | Trois tickets autonomes TCP-01 à TCP-03, TCP-04 autonome | **Ticket parent unique**, sous-tâches internes, TCP-04 en non-régression | Revue Kiro |
| A1 | Non traité comme unité | **Unité complète** : hôte absent, hôte entièrement filtré, fermetures individuelles, `closed → filtered`, attributions XML | Revue Kiro |
| D5 | « Approuvé, à planifier » | **Conception approuvée, implémentation non autorisée**, après A1, priorité P3 | Revue Kiro |
| D1 | Bloqué par DEC-03 et TCP-05 | **Distinction approuvée**, libellé ouvert, après D5 | Revue Kiro |
| D6 | Dépendance DEC-04 | **Indépendant hors A1** ; DEC-04 examinée au moment du ticket | Revue Kiro |
| CRED-02 | Décision produit (DEC-06) | **Conforme, sans ticket** | Revue Kiro ; conforme à T22 |
| SMB-01 | `--json`, code de retour ignoré | Complété : export `-oJ`, lecture du JSON, code retour, stdout/stderr séparés, repli texte | Revue Kiro (rapporté, vérifié sur le poste du propriétaire) |
| SMB-02 | Hypothèse « `--json` probablement inexistant » | **Vérification de compatibilité** intégrée à SMB-01 | Revue Kiro |
| NET-01 | P1 provisoire, DEC-10 | **Non reproduit, sans ticket, DEC-10 retiré** | Revue Kiro |
| ARENA §9.6 / DEC-13 | Décision à soumettre | **Supersédée** par la politique A1 approuvée | Revue Kiro |
| DEC-15 | Réserve à accepter | **Retiré** : conséquence documentée de R7 | Revue Kiro |
| DEC-01 | Décision d'emplacement | **Proposition** justifiée par la convention de `docs/` | Revue Kiro |
| DOC-02 | Skills vers steering en minuscules ; `uploads/ARENA.md` | **Constat recentré sur `.cursor/rules/sentinelX.mdc`** ; Skill `impl-tracking.md` retiré du constat ; chemins absolus conservés | Revue Kiro |
| Ordre | Voir v1 §4 | Étape 0 (DOC-01, Master, Tracking, spec A1, réconciliation) ; SMB-01 ; A1 ; CRED-01 ; D5 après A1 ; D1 après D5 ; D6 indépendant | Revue Kiro |
| Seconde revue Kiro (V2.2) — séquence | DOC-01 dans la séquence technique | **Étape 0** préalable à SMB-01 ; DOC-01 hors séquence | Seconde revue Kiro |
| Seconde revue Kiro (V2.2) — CA-16 | CA-16 dans les critères A1 | **Rattaché à D1** (§9.2 de la spécification) ; A1 n'exige ni `proof` ni libellé | Seconde revue Kiro |
| Seconde revue Kiro (V2.2) — Skill | Proposition de Skill Kiro dans le paquet | **Retirée du paquet actif** ; fichier conservé dans le dossier d'audit ; Skill canonique non modifié | Seconde revue Kiro |
| Statuts | « Décision » et « Proposé » mélangés | Vocabulaire §0 distinct | Revue Kiro |
| Date de la spec A1 | « Réconciliée le 2026-09-24 » | **Réconciliée le 2026-11-12** | Date de mission |
| SPEC §2.3 l.49 | `ScanFailedError` l.626-636 | **l.629-636**, vidage l.632-633 | Vérification de code (`9034f01`) |
| SPEC l.195 | « Fixture filtered (sortie réelle nmap 7.95) » | **« annotée »**, non prouvée (V6) | Contradiction interne relevée |

---

## 9. Références de commits (`origin/a4-arena`, vérifiées par `git cat-file -e` et `git log`)

| Commit | Date git | Sujet (git) | Consigné dans `docs/` ? |
|---|---|---|---|
| `3657498` (`365749878aa3e886da9cd33c2322fb75277c16ce`) | 2026-11-10 | feat(sentinel): implement T23-B network change detection | Oui, comme HEAD déclaré (à corriger) |
| `85870ac` | 2026-11-10 | feat(cli): add confidence column to findings tables | Non (marqué « en attente ») |
| `7ff3d89` | 2026-11-10 | docs: add master reference, implementation tracking and agent skill | Non |
| `13e7849` | 2026-11-10 | fix Commit 3657498 (`requirements.txt`, 1 ligne) | Non |
| `63e1a7b` | 2026-11-10 | feat(sentinel): interrupt nmap on stop request (point 1) | Non |
| `b1ab727` | 2026-11-11 | fix(sentinel): detect gateway on connected routes (point 2) | Non |
| `e4f3f9e` | 2026-11-11 | feat(sentinel): colour event types and label closed ports (ticket 3) | Non |
| `9034f01` (`9034f0131ebeaf63dc51bf217cea3ec3f6ab068e`) | 2026-11-11 | feat(sentinel): number hosts in monitor table (ticket 4) | Non (HEAD réel) |

Ordre git (`git log --reverse 3657498..9034f01`) : `85870ac`, `7ff3d89`, `13e7849`, `63e1a7b`, `b1ab727`, `e4f3f9e`, `9034f01`.

---

## 10. Réserves

- **R-1 Dates.** La date de mission est le 12 novembre 2026. Les dates git (2026-11-10 et 2026-11-11) sont antérieures à cette date. Les dates des rapports antérieurs ne sont pas réconciliées (§ en-tête).
- **R-2** Structure réelle des `<extrareasons>` Nmap : non vérifiée hors fixtures. Le DTD valide le schéma seulement.
- **R-3** Sémantique réelle de `extraports state=open` : non vérifiée.
- **R-4** Comportement de `ScanDegradedError` en production au-delà des cas mesurés : non mesuré.
- **R-5** Lecteurs de `baseline.services` : grep non exhaustif ; aucun lecteur logique trouvé.
- **R-6** Le harnais `preuves/a1/a1_chain_verify.py` remplace les sondes réseau ; un cycle = un appel de `_do_check`. Aucun scan réel.
- **R-7** `preuves/a1/a1_model_spec.py` est une spécification exécutable, pas une preuve de conformité.
- **R-8** Les constats B3, B4, A2, A3, B1 et B5 sont des lectures ou des reproductions en isolation. Aucun n'est vérifié sur le poste du propriétaire, sauf le constat SMB-02 rapporté par le propriétaire.
- **R-9** `~/.netlab` : non lu ni modifié (4744 entrées mesurées antérieurement). Aucun secret demandé.
- **R-10** Aucun ticket n'est présenté comme bug confirmé s'il ne l'est pas : SCO-01, OS-01 restent en partiel ou en hypothèse ; CRED-02 et NET-01 sont clos sans ticket.
- **R-11** Les clones locaux non alignés (`/home/user/sentinelX` `2eb1b20`, 27 modifications ; `sentinelX-impl` `13e7849`, 12 ; `sentinelX-reference` `2283166`, 6) n'ont pas été touchés.
- **R-12** Revue Kiro effectuée ; seconde revue : « recevable après corrections » (V2.2). Décision propriétaire requise (DEC-02) avant l'Étape 0.
- **R-13** Dossier de Kiro : `docs-processes/` et les doublons `(1)`/`(2)` sont introuvables dans l'environnement d'audit. Ils ne sont pas intégrés au paquet. Le dossier examiné reste à identifier.

---

## 11. Corrections de la spécification A1 (`SPEC-A1-consolidee.md`)

- §2.3 l.49 : `ScanFailedError` est au bloc **l.629-636** (et non l.626-636) ; le vidage des compteurs est aux **l.632-633**.
- l.195 : la fixture `filtered` unique est **« annotée »** comme sortie réelle nmap 7.95 ; cette annotation n'est pas prouvée (V6).
- l.3 : date de réconciliation **2026-11-12**.

---

## 12. Contrôle avant livraison

| Contrôle | Résultat |
|---|---|
| Cohérence des décisions : aucune décision approuvée redemandée | Voir §2 (décisions retirées de §3) |
| Absence de statuts obsolètes | Voir §8 ; contrôle par grep dans la transmission |
| Absence de chemins inventés | Chaque chemin cité a été vérifié dans `/tmp/audit-global-ref` (`9034f01`) ou dans l'espace d'audit |
| Références de lignes | Vérifiées par `grep -n` / `sed -n` sur `9034f01` (2026-11-12) ; lignes corrigées : SMB-01, TOOL-01, REP-01, SCO-01, A1 (`monitor.py`) |
| Cohérence statut / rang / dépendances | §4 et §5 concordants ; D5 = P3 partout ; CRED-01 après A1 |
| Aucune anomalie auditée oubliée | Voir §7 : chaque identifiant A1, B1 à B5, A2, A3, C, DOC, CRED, NET a un traitement |
| Critères d'acceptation complets | A1 : CA-1 à CA-15, CA-17, CA-18 + S1 à S11 + P1 à P12 (CA-16 : D1 ; L1, L2 : D6, hors A1) |
| Séparation des tickets | Étape 0 (documentation) avant SMB-01 ; DOC-01 hors séquence technique |
| Livraison à Nova pour seconde vérification indépendante par Kiro | **Dossier déposé, non transmis** : aucun canal disponible dans cet environnement |

**Seconde vérification demandée à Kiro** : points de contrôle listés dans `docs-proposees/TRANSMISSION-revue-Kiro-et-Nova.md`.
