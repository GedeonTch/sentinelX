# DEC-05 / CRED-01 — Préparation de la décision et du plan d'implémentation

**Statut : décisions propriétaires DEC-05 enregistrées ; CRED-01 implémenté et accepté avec réserves explicites (audit Arena, 2026-11-22). Aucune nouvelle implémentation n'est autorisée.**
**Date :** 2026-11-21 (décisions) ; mise à jour de livraison 2026-11-22 | **Branche de référence :** `a4-arena` | **HEAD :** `6af1f72`
**Sources :** plan V2.2 (`docs/project-reference/roadmap-v2.2-final/docs-proposees/PLAN-tickets-global.md`, §3 DEC-05 et §4.3 CRED-01) ; `docs/MASTER-REFERENCE.md` ; `docs/IMPLEMENTATION-TRACKING.md` ; `docs/T22-CREDENTIALS.md` ; code du coffre, de la base et des résolveurs de chemins.

> Ce document enregistre les décisions DEC-05 et l'état de livraison CRED-01. Il ne tranche pas les questions opérationnelles encore ouvertes.

---

## 1. Texte exact de DEC-05 et portée de CRED-01

### DEC-05 (plan V2.2, §3)

> **DEC-05** — Emplacement et procédure de migration, **seulement si** CRED-01 retient un changement de chemin.
> Recommandation / état : décision et procédure avant tout déplacement de coffre ou de base.

### CRED-01 (plan V2.2, §4.3)

- **Anomalie** : sous `sudo`, le coffre peut être créé sous `/root` (reproduit par simulation de chemin).
- **Priorité** : P1.
- **Statut** : ticket planifié, **après A1**. DEC-05 requise avant toute implémentation touchant un chemin de coffre ou de base.
- **Périmètre** : **résolveurs de chemins seulement**. Sites `Path.home()` (sans `_real_user_home()`) : `core/credential_vault.py` l.35 (coffre) ; `sentinel/whitelist.py` l.37 ; `detect/default_creds.py` l.221 ; `core/dependencies.py` l.174 ; `cli.py` l.1805 (rapports) ; `cleanup/restore.py` l.181 et l.193 ; `cleanup/artifact_detector.py` l.128 et l.146. `_real_user_home()` : `core/database.py` l.56-88.
- **Règle** : un chemin n'est changé que si sa divergence sous sudo est démontrée. Chaque site est confirmé par test avant tout changement.
- **Interdiction** : aucune migration, aucun déplacement, aucune suppression de coffre sans décision.

**Statut actuel de CRED-01 :** désigné après A1 dans l'ordre V2.2 approuvé (DEC-02), mais **bloqué par DEC-05**. Aucune implémentation ne doit commencer avant la clôture de DEC-05 et l'autorisation explicite du propriétaire.

### Décisions propriétaires (DEC-05, 2026-11-21)

**Décision initiale — Option B : refus de l'exécution privilégiée.** `creds check` est refusé lorsque l'effective UID du processus est égal à 0 (via `sudo` ou exécution directe en root). Le credential testing s'exécute depuis la session normale de l'utilisateur, sans élévation de privilèges.

**Décision complémentaire — extension aux trois commandes `creds`.** Le refus s'applique à `creds check`, `creds list` et `creds show`, y compris pour les commandes habituellement en lecture seule.

| Élément | Décision |
|---|---|
| Condition de référence | `os.geteuid() == 0` (POSIX) ; ne pas se fonder uniquement sur `SUDO_USER`/`SUDO_UID`. |
| Effets avant refus | Aucun accès au vault, aucune lecture/déchiffrement, aucune création/initialisation, aucune session de credential testing, aucune transmission de credential, aucun accès réseau, aucune écriture persistante, aucune modification de baseline ou d'état. |
| Message | « Les commandes creds ne peuvent pas être exécutées avec les privilèges root. Relancez SentinelX sans sudo. » |
| Code de sortie | À préciser dans les critères d'acceptation de CRED-01, selon les conventions CLI existantes. |
| Portée | Uniquement les trois commandes `creds`. `scan`, `monitor`, rapports, cleanup et autres commandes réseau restent à examiner séparément. |
| Windows | Règle POSIX uniquement ; aucune politique Administrator n'est définie par cette décision. |
| Root interactif | Aucune exception implicite ; toute exception exigerait une décision distincte du propriétaire. |

**DEC-05 n'est pas entièrement clôturée** : les questions opérationnelles listées au §4 restent ouvertes. **CRED-01 est implémenté et accepté avec réserves explicites** (voir ci-dessous) ; aucune nouvelle implémentation n'est autorisée.

### État de livraison CRED-01 (audit Arena, 2026-11-22)

- **Statut** : implémenté et **accepté par le propriétaire avec réserves explicites**.
- **Fichiers livrés** : `cli.py`, `core/user_paths.py`, `core/credential_vault.py`, `detect/default_creds.py`, `tests/test_user_paths.py`, `tests/test_creds_security.py`, `tests/test_ssh_creds.py`.
- **Tests** : **533 tests ciblés exécutés par Arena, réussis** (`umask 022`) ; suite complète du dépôt **non exécutée**.
- **Décisions appliquées** : refus des trois commandes `creds` sous `euid 0` ; home credentials via `pwd.getpwuid(os.geteuid())` ; validation du vault sans remplacement ; aucune migration automatique ; aucun changement de schéma, KDF ou format.
- **Réserves non corrigées** : tests symlink dédiés à `validate_vault_location()`, interruption/création partielle du vault, garde de `open_vault()` bas niveau, coexistence de deux résolveurs, différence `uid`/`euid` dans `_private`, suite complète du dépôt non exécutée.

---

## 2. État actuel du code (vérifié par lecture)

### 2.1 Résolveur déjà en place

`core/database.py` l.56-88 définit `_real_user_home()` :

- `SUDO_USER` → `pwd.getpwnam(...).pw_dir` ;
- sinon `SUDO_UID` → `pwd.getpwuid(...).pw_dir` ;
- si métadonnées sudo présentes mais irrésolvables : **RuntimeError** (refus de `/root`) ;
- sans métadonnées sudo : `Path.home()` (comportement inchangé).

Ce résolveur est déjà utilisé pour les **bases** (sessions et Sentinel) :

| Usage | Emplacement |
|---|---|
| `get_db_path()` (sessions) | `core/database.py` l.131 |
| `get_sentinel_db_path()` (réseau) | l.1237 |
| `list_sentinel_network_ids()` | l.1820 |
| `_sentinel_existing_session_path()` | l.2274 |

Tests existants : `tests/test_database_paths.py` (non-sudo, `SUDO_USER`, `SUDO_UID`, refus `/root`).

### 2.2 Sites encore sous `Path.home()` (périmètre CRED-01)

| # | Fichier / fonction | Ligne | Chemin actuel | Nature des données | Impact sudo |
|---|---|---|---|---|---|
| 1 | `core/credential_vault.py` — `default_vault_path()` | 34-35 | `Path.home()/.netlab/credentials/vault.enc` | **Coffre chiffré (secrets)** | Coffre créé sous `/root` |
| 2 | `sentinel/whitelist.py` — `WHITELIST_PATH` (constante module) | 37 | `Path.home()/.netlab/baseline_whitelist.yaml` | Configuration Sentinel | Whitelist lue/écrite sous `/root` |
| 3 | `detect/default_creds.py` — `ssh_trust_path()` | 219-221 | `Path.home()/.netlab/ssh_known_hosts` | Confiance SSH (TOFU) | Trust file sous `/root` |
| 4 | `core/dependencies.py` — `netlab_home_path()` | 168-174 | `Path.home()/.netlab` | `netlab doctor` (probe) | Diagnostic faux / mauvais dossier |
| 5 | `cli.py` — génération de rapport | 2039-2043 | `Path.home()/.netlab/reports` | Rapports HTML/JSON | Rapport écrit sous `/root` |
| 6 | `cleanup/restore.py` — `_is_owned_session_db()` / `_is_owned_report()` | 181, 193 | `Path.home()/.netlab/sessions|reports` | Contrôle de propriété avant restauration | **Mauvaise racine ⇒ refus ou ciblage erroné** |
| 7 | `cleanup/artifact_detector.py` — `_detect_session_db()` / `_detect_reports()` | 128, 146 | `Path.home()/.netlab/sessions|reports` | Détection d'artefacts | Détection sous `/root` |

### 2.3 Points structurels observés

1. **Séparation des stockages** (décision existante, T22 §Coffre local) : sessions `~/.netlab/sessions/<session>.db`, Sentinel `~/.netlab/sentinel/<network>.db`, coffre `~/.netlab/credentials/vault.enc`, rapports `~/.netlab/reports/`, trust SSH `~/.netlab/ssh_known_hosts`. **Aucun schéma SQLite ne doit changer ; aucune migration automatique.**
2. **Coffre** : répertoire `0700`, fichiers `0600`, liens refusés, verrou exclusif, remplacement atomique, `fsync`, relecture, refus des permissions non privées, **aucune réparation automatique** (T22 l.322-330).
3. **`.netlab` lui-même** : créé par `mkdir(parents=True, exist_ok=True)` sans mode explicite dans plusieurs chemins (sessions, sentinel, reports, `doctor`). Le mode effectif dépend de l'umask (souvent `0755`), alors que le sous-dossier du coffre est forcé à `0700`. **Incohérence de permissions potentielle**, hors périmètre strict CRED-01 (qui ne traite que la résolution de chemins) mais à connaître pour DEC-05.
4. **`_real_user_home()` ne valide pas** l'existence, l'appartenance ou les permissions du home résolu : un `SUDO_USER`/`SUDO_UID` forgé peut rediriger les données. C'est le modèle de confiance actuel des bases ; toute extension hérite de cette limite.
5. **`WHITELIST_PATH` est une constante évaluée à l'import** et utilisée comme **valeur par défaut** de 8 fonctions. Une résolution paresseuse impose de remplacer ces défauts par `None` + résolution interne (ou une fonction `whitelist_path()`), sans changer les signatures publiques de façon cassante.

---

## 3. Analyse comparative des options (pré-décision)

| Option | Description | Avantages | Risques | Compatibilité | Effort |
|---|---|---|---|---|---|
| **A — Résolveur unique étendu, sans migration** *(recommandée)* | Extraire `_real_user_home()` dans un module partagé (`core/user_paths.py`) et l'appliquer aux 7 sites. Les données existantes restent où elles sont ; aucun déplacement automatique. | Cohérence avec les bases ; corrige la cause P1 ; pas de manipulation de secrets ; rollback trivial (revert) ; périmètre conforme au plan. | Les anciennes données sous `/root/.netlab` restent invisibles (à documenter) ; dépendance à la fiabilité des variables sudo. | Forte : non-sudo inchangé ; coffre/crypto/schéma inchangés. | **M** (7 sites + tests) |
| **B — Résolveur + migration automatique** | Comme A, plus détection et déplacement des données `/root/.netlab` vers le home réel au premier lancement sudo. | Corrige aussi les données déjà créées sous `/root`. | Manipulation de **secrets** et de bases actives ; atomicité, permissions, verrous, reprise après interruption ; risque de perte ; règle « aucune migration sans décision » viole l'esprit CRED-01. | Faible : chemin de migration à maintenir et tester. | **L/XL** |
| **C — Base configurable (`NETLAB_HOME`)** | Variable d'environnement/option pour choisir la racine, défaut `_real_user_home()/.netlab`. | Contrôle explicite ; utile aux tests et environnements isolés. | Nouveau contrat transverse ; risque de divergence entre modules ; surface de configuration accrue ; hors périmètre CRED-01. | Moyenne : nécessite de toucher tous les résolveurs. | **L** |
| **D — Statu quo + documentation/refus** | Conserver `Path.home()` ; documenter d'éviter sudo ou d'utiliser `sudo -H` ; éventuellement refuser l'écriture sous `/root`. | Aucun changement de code de stockage. | Ne corrige pas la cause P1 ; le coffre peut rester sous `/root` ; CRED-01 non résolu. | Totale (aucun changement). | **S** (mais ne satisfait pas CRED-01) |

### Décision retenue et portée de l'analyse

Le propriétaire a retenu l'**option B (refus de l'exécution privilégiée)**, étendue aux trois commandes `creds` (§1). Les options ci-dessus sont conservées comme analyse pré-décision.

L'**option A** (résolveur partagé) reste envisagée pour l'harmonisation des chemins autorisés, **sans permettre de contourner le refus** : elle ne doit être appliquée qu'après vérification qu'aucune écriture sous privilèges élevés ne crée de données root-owned dans le home utilisateur (voir §4 et §5).

L'option C (`NETLAB_HOME`) reste **hors V1** (décision). L'option D (statu quo) est écartée : elle ne corrige pas le défaut P1.

La migration des données déjà présentes sous `/root/.netlab` reste **manuelle, documentée et exécutée par le propriétaire**, jamais automatique.

---

## 4. Décisions tranchées et questions encore ouvertes

### 4.1 Décisions tranchées par le propriétaire

| # | Décision |
|---|---|
| D1 | Refus de `creds check` sous `euid 0` (Option B), avant tout accès au coffre ou aux credentials. |
| D2 | Refus étendu à `creds list` et `creds show` sous `euid 0`, y compris en lecture seule. |
| D3 | Condition de référence : `os.geteuid() == 0` (POSIX) ; pas de détection fondée uniquement sur `SUDO_USER`/`SUDO_UID`. |
| D4 | Aucune migration automatique ; aucun déplacement, fusion, écrasement ou suppression de coffre. |
| D5 | Aucune création silencieuse d'un nouveau coffre lorsqu'un ancien coffre risque de contenir les données attendues. |
| D6 | Permissions du coffre conservées : répertoire `0700`, fichier `0600`, contrôle du propriétaire, aucune réparation automatique, aucun `chown`/`chmod` automatique. |
| D7 | Aucun changement de schéma SQLite, de format du vault, de KDF ni de verrou. |
| D8 | `NETLAB_HOME` reste hors périmètre V1. |
| D9 | Aucune exception implicite pour une session root interactive. |
| D10 | La décision ne s'étend pas automatiquement à `scan`, `monitor`, rapports, cleanup ni aux autres commandes réseau. |
| D11 | La règle est POSIX ; aucune politique Windows Administrator n'est définie. |

### 4.2 Questions encore ouvertes (non tranchées)

1. Politique de résolution et validation de `SUDO_USER` / `SUDO_UID`.
2. Détection d'un ancien `/root/.netlab` sans créer silencieusement un second vault.
3. Comportement des autres commandes SentinelX sous `sudo`.
4. Propriété et permissions des fichiers créés dans le home utilisateur par les autres commandes privilégiées.
5. Périmètre exact du résolveur partagé `core/user_paths.py`.
6. Procédure manuelle de récupération d'un ancien coffre.
7. Compatibilité Windows et éventuelle politique Administrator, à traiter séparément.

**Ces questions ne sont pas tranchées par ce document.**

### 4.3 Conditions de clôture de DEC-05

DEC-05 ne sera déclarée résolue qu'après :

1. Spécification formelle du refus des trois commandes et de l'absence de tout effet secondaire.
2. Décision sur les questions 1 à 7 ci-dessus.
3. Documentation des permissions et propriétaires attendus.
4. Validation explicite du propriétaire.

**La livraison de CRED-01 ne clôt pas DEC-05 : les questions du §4.2 restent ouvertes.**

---

## 5. Plan d'implémentation CRED-01 (exécuté ; DEC-05 partiellement tranchée)

> **État : plan exécuté par la livraison CRED-01.** Les réserves de l'audit restent **non corrigées** (voir « État de livraison CRED-01 »).

### 5.0 Phase 0 — refus des trois commandes `creds` sous `euid 0`

Objectif : garantir qu'aucune opération liée au coffre ou aux credentials n'est effectuée lorsque `os.geteuid() == 0`.

- Garde en première instruction de `creds_check_cmd`, `creds_list` et `creds_show` (`cli.py`), avant toute ouverture de coffre, lecture de dictionnaire, création de session ou appel réseau.
- Défense en profondeur : même garde au début de `check_default_creds` (appelant de production actuel : CLI uniquement ; vérifié).
- Message utilisateur explicite (sans information sensible) : « Les commandes creds ne peuvent pas être exécutées avec les privilèges root. Relancez SentinelX sans sudo. »
- Code de sortie : à fixer dans les critères d'acceptation, selon les conventions CLI existantes.
- Aucun effet secondaire avant le refus : pas de vault, pas de session, pas de réseau, pas d'écriture persistante, pas de baseline.

### 5.1 Périmètre exact

**Inclus :**

- garde de refus des trois commandes `creds` sous `euid 0` (phase 0, priorité) ;
- extraction d'un résolveur partagé `real_user_home()` (comportement identique à `_real_user_home()`), **après résolution des questions ouvertes du §4.2** ;
- remplacement de `Path.home()` par ce résolveur aux 7 sites du tableau §2.2, sous réserve qu'aucune écriture privilégiée ne crée de données root-owned dans le home utilisateur ;
- conservation de `core.database._real_user_home` comme alias/compatibilité interne ;
- tests unitaires de refus, de résolution sous sudo simulé et de non-régression.

**Exclu :**

- toute migration, copie ou suppression de coffre/base ;
- tout changement de schéma SQLite, de format de coffre, de KDF ou de verrou ;
- tout nouveau mécanisme de stockage ou racine configurable ;
- toute modification des messages métier, du scoring, des Findings ;
- CLI-01, TOOL-01, D5, D1 et tout autre ticket.

### 5.2 Fichiers et modifications envisagées

| Fichier | Modification envisagée |
|---|---|
| `cli.py` | **Phase 0** : garde de refus dans `creds_check_cmd`, `creds_list` et `creds_show`, avant toute opération coffre/réseau/session ; dossier de rapports → `real_user_home()/.netlab/reports`. |
| `core/privileges.py` *(ou helper équivalent, proposition)* | `is_privileged()` : `os.geteuid() == 0` sous POSIX ; `False` si `geteuid` absent (Windows). Testable par monkeypatch. |
| `detect/default_creds.py` | **Défense en profondeur** : garde au début de `check_default_creds` ; `ssh_trust_path()` → `real_user_home()`. |
| `core/user_paths.py` *(nouveau, proposition)* | `real_user_home()` : logique extraite de `core/database.py` l.56-88. |
| `core/database.py` | Importe `real_user_home` ; `_real_user_home = real_user_home` (compatibilité) ; usages inchangés. |
| `core/credential_vault.py` | `default_vault_path()` → `real_user_home()/.netlab/credentials/vault.enc`. |
| `sentinel/whitelist.py` | Résolution paresseuse : `whitelist_path()` ; défauts des fonctions passés à `None` puis résolus. |
| `core/dependencies.py` | `netlab_home_path()` → `real_user_home()`. |
| `cleanup/restore.py` | Racines sessions/reports → `real_user_home()`. |
| `cleanup/artifact_detector.py` | Détection sessions/reports → `real_user_home()`. |

> Le module dédié `core/user_paths.py` est **requis** (indépendance vis-à-vis de `core.database`, conformément à DEC-05). L'import depuis `core.database` est exclu. Le module ne contient aucune logique de stockage.

### 5.3 Comportements à préserver

- Sans sudo : `Path.home()` — aucun changement observable.
- Sous sudo résolu : home de l'utilisateur invocateur.
- Sous sudo irrésolvable : erreur explicite, **jamais** `/root/.netlab`.
- Coffre : chiffrement, verrou, remplacement atomique, permissions, refus des liens — **inchangés**.
- Bases : chemins, schéma et transactions — **inchangés**.
- Nettoyage : les contrôles de propriété restent stricts (nom exact, racine exacte, liens refusés).
- Aucun secret dans les Findings, logs, preuves, rapports ou sorties.

### 5.4 Matrice de tests

#### Phase 0 — refus des commandes creds

| # | Test | Attendu |
|---|---|---|
| T0-1 | `creds check` avec `euid 0` | Refus immédiat, message explicite, code de sortie défini |
| T0-2 | `creds list` avec `euid 0` | Refus immédiat, aucun accès au vault |
| T0-3 | `creds show` avec `euid 0` | Refus immédiat, aucun accès au vault |
| T0-4 | `euid 0` avec `SUDO_USER` présent | Refus |
| T0-5 | `euid 0` avec `SUDO_USER` absent | Refus |
| T0-6 | Exécution directe en root (`euid 0`, sans sudo) | Refus |
| T0-7 | `euid ≠ 0` | Comportement normal préservé |
| T0-8 | Refus | Aucun vault ouvert/créé, aucune session, aucun appel réseau, aucune transmission, aucune écriture persistante |
| T0-9 | Refus | Aucune modification de baseline ou d'état |
| T0-10 | Windows (`geteuid` absent) | Pas de refus fondé sur `geteuid` ; politique Administrator non définie |

#### Résolution de chemins (après questions ouvertes)

| # | Test | Attendu |
|---|---|---|
| T1 | Non-sudo (`SUDO_USER`/`SUDO_UID` absents) | Tous les résolveurs = `Path.home()/.netlab/...` |
| T2 | `SUDO_USER` valide, `HOME=/root` | Tous les résolveurs = home réel de `SUDO_USER` |
| T3 | `SUDO_UID` seul, valide | Repli sur le home de l'UID |
| T4 | Sudo irrésolvable | Erreur explicite ; aucun chemin `/root` retourné |
| T5 | Coffre sous sudo simulé | `vault.enc` sous le home réel ; création `0700` ; fichier `0600` |
| T6 | Whitelist | Défaut résolu sous le home réel ; signatures publiques inchangées |
| T7 | Trust SSH | `ssh_known_hosts` sous le home réel ; contrôles de permissions inchangés |
| T8 | `netlab_home_path()` | Home réel sous sudo |
| T9 | Rapport CLI | Dossier `reports` sous le home réel |
| T10 | Cleanup restore/artifact | Racines sessions/reports sous le home réel ; aucun faux positif |
| T11 | HOME/DB temporaires | Aucune base réelle, aucun secret réel, `HOME` isolé |
| T12 | Non-régression | Suites vault, database paths, cleanup, CLI vertes |
| T13 | `creds list/show` sans vault (non privilégié) | Aucune création de vault |
| T14 | Adaptation des tests existants | `test_database_paths` cible `core.user_paths.pwd` ; les 8 modules patchant `db._real_user_home` restent verts |

### 5.5 Critères d'acceptation

1. `creds check`, `creds list` et `creds show` refusent `euid 0` avant tout effet secondaire (vault, session, réseau, écriture, baseline).
2. Message utilisateur conforme, sans information sensible ; code de sortie fixé.
3. Les 7 sites n'utilisent plus `Path.home()` directement pour les données utilisateur (après résolution des questions ouvertes).
4. T0-1 à T0-10 et T1–T11 passent ; T12–T14 sans nouvelle régression.
5. `git diff --check` rc 0.
6. Aucune migration, aucun déplacement, aucune suppression de coffre/base.
7. Aucun changement de schéma SQLite, de format de coffre, de KDF ni de verrou.
8. Aucun secret dans la sortie des tests ou des commandes.

### 5.6 Risques et rollback

| Risque | Mitigation |
|---|---|
| `SUDO_USER` forgé → redirection de données | Modèle de confiance existant des bases ; documenter ; ne pas élargir la surface |
| Résolution paresseuse de la whitelist → régression des défauts | Tests dédiés ; signatures par défaut `None` ; revue ciblée |
| Divergence entre modules (un site oublié) | Grep de contrôle `Path.home()` + tests par site |
| Données existantes sous `/root` invisibles | Documenter ; procédure manuelle hors CRED-01 |
| Contournement par appel direct de `check_default_creds` | Garde en défense en profondeur + test dédié |
| Code de sortie incohérent avec les conventions CLI | Fixer dans les critères d'acceptation |
| Windows : `geteuid` absent | Branche `False` explicite ; politique Administrator hors périmètre |

**Rollback :** revert du commit CRED-01. Aucune migration n'ayant été exécutée, le retour est sûr.

---

## 6. Workflow proposé (gouvernance)

1. **DEC-05** : décisions complémentaires sur les questions ouvertes du §4.2.
2. **Audit read-only** du dépôt par Arena.
3. **Validation du périmètre et des critères CRED-01** par le propriétaire.
4. **Un seul implémenteur actif** (Kiro ou DeepSeek OpenCode selon disponibilité).
5. **Inspection initiale obligatoire** de Git et des changements existants.
6. **Implémentation limitée au scope approuvé**.
7. **Tests** avec DB isolées et secrets factices.
8. **Audit indépendant Arena**.
9. **Corrections ciblées** si nécessaires.
10. **Acceptation finale du propriétaire**.
11. **Commit et push autorisés** après validation.

> Aucun agent ne commence l'implémentation avant les étapes 1 à 3.

---

## 7. Ce que ce document ne fait pas

- Il enregistre les décisions DEC-05 et l'état de livraison CRED-01 ; il **ne tranche pas** les questions ouvertes du §4.2.
- Il ne déclare pas DEC-05 entièrement clôturée et **ne présente pas les réserves comme corrigées**.
- Il n'autorise aucune nouvelle implémentation au-delà de CRED-01 déjà livré.
- Il n'implémente aucun code et ne modifie aucun test.
- Il ne propose aucune migration automatique.
- Il ne crée ni ne modifie aucun ticket (CLI-01, TOOL-01, D5, D1 restent inchangés).
