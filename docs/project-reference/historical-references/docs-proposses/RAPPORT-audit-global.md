# Audit technique global — SentinelX (Sentinel Monitor et NetLab)

Statut : **rapport d'audit, sans implémentation.** Aucune correction n'est appliquée.
Toute proposition ci-dessous est **en attente de décision du propriétaire** et de revue Nova.

Date de l'audit : 2026-09-24 (heure locale Bujumbura). Référence de code : `origin/a4-arena` = `9034f0131ebeaf63dc51bf217cea3ec3f6ab068e` (`main` = `8366722f742fcab0c76881b3b74629025b84eb44`).

---

## 0. Résumé exécutif

| Ordre | ID | Constat principal | Niveau |
|---|---|---|---|
| 1 | **B3** | `smb_enum` transforme un échec de l'outil en « no shares or domain info ». Cause probable : l'option `--json` n'existe pas dans enum4linux-ng (l'export JSON est `-oJ`). **Reproduit en isolation** : rc=2 ignoré, 0 finding, message trompeur. | P1 |
| 2 | **C** | Le CIDR surveillé est celui passé à `--target` ; rien dans le code ne choisit `192.168.57.0/24` automatiquement. Cause non établie sans lecture de `~/.netlab` (interdite). | P1 provisoire (P0 si démarrage non voulu confirmé) |
| 3 | **B2** | `--service ssh` échoue **par construction** : aucun candidat SSH dans le catalogue livré (`legacy` = FTP + SNMP). Coffre : chemin `Path.home()` ≠ `_real_user_home()` sous `sudo`. **Reproduit.** | P1 (coffre) / P2 (SSH) |
| 4 | **A3** | Le « 0 » est la colonne « Affichées » d'un **quota de notification sur 60 min**, calculée à la génération du rapport. Ce n'est pas un compteur d'événements. **Reproduit** : un `new_port` de 2 h s'affiche « 0 ». | P2 |
| 5 | **A1** | Un port `filtered` produit le même `port_not_open` qu'un port fermé après deux scans complets. Conforme au texte actuel, mais **ambigu** au regard de la règle « absence d'observation ≠ preuve de fermeture ». **Reproduit.** | P2 (décision requise) |
| 6 | **B5** | Ports 512/513/514 : aucune règle ne les produit. Le « CVSS 5.0 » est le `risk_score` de la sévérité `info` (5 × 1,00 × 1,00), **pas un CVSS**. Un port `info` CONFIRMED et OPEN entre dans le score global. | P2 |
| 7 | **B4** | Les timeouts OS Nmap (60 s, sortie jetée) et « no usable fingerprint » ont des causes multiples. Aucune n'est confirmée sans mesure réelle. | P2 |
| 8 | **A2** | Deux interfaces, deux règles de résolution d'identifiant. Pas une erreur de données, mais une incohérence d'UX. | P2/P3 |
| 9 | **B1** | `netlab findings rescan` existe déjà (VERIFY, sans nouveau scan). Le besoin est couvert ; la commande s'appelle `findings rescan`, pas `rescan findings`. Limite : Findings `sentinel.*` en PARTIAL. | P3 |
| 10 | Docs | HEAD déclaré `3657498` dans les Skills et docs, dépôt à `9034f01`. Les Skills pointent vers un chemin de steering en minuscules inexistant. | P2 |

**Aucune anomalie n'a été classée P0 avec preuve.** Le seul candidat P0 est C, et il reste non confirmé (voir §3.C).

---

## 1. Méthode, périmètre, état Git

### 1.1 Règles suivies
- Lecture de code, tests et documentation. Exécution uniquement dans un environnement isolé : fixtures, faux binaires, `HOME` temporaire, stub de dépendance manquante.
- Aucun scan Nmap ou enum4linux-ng sur les machines de l'utilisateur. Aucun test de credential réel. Le secret du coffre n'a pas été demandé ni reproduit.
- `~/.netlab` : **4744 entrées avant et après chaque reproduction** (mesure `find | wc -l`). Identique à l'empreinte du ticket 4.

### 1.2 État Git initial (constaté 2026-09-24)

| Dépôt | HEAD local | État | Remarque |
|---|---|---|---|
| `/home/user/sentinelX` | `2eb1b20` | 27 lignes `git status` (modifiées + non suivies) | Non aligné sur `9034f01`. Non touché. |
| `/home/user/sentinelX-impl` | `13e7849` | 12 lignes | Non aligné. Non touché. |
| `/home/user/sentinelX-reference` | `2283166` | 6 lignes | Non aligné. Non touché. |
| `/tmp/audit-sentinelX` | `9034f01` | propre (0 ligne) | **Créé pendant l'audit** par `git clone --branch a4-arena`. À supprimer sur demande. |
| `/tmp/sentinelX-point4` | — | **absent** | Présent dans la session précédente, plus présent maintenant. |
| `/tmp/t3-*`, `/tmp/t4-*` | — | **absents** | Journaux et venv de test du ticket 3 et 4, plus présents. Non nécessaires au présent audit. |

**Commit de référence de l'audit : `9034f01`** (`origin/a4-arena`). Il est absent des trois clones locaux : l'audit s'appuie uniquement sur le clone propre `/tmp/audit-sentinelX`.

Les modifications non commitées dans les trois clones locaux **n'ont pas été examinées en détail** ; elles ne sont pas la référence. Le propriétaire doit décider de leur sort. Aucun nettoyage n'a été fait.

### 1.3 Fichiers créés pendant l'audit (hors dépôts)
- `/tmp/audit-sentinelX/` (clone de lecture).
- `/tmp/audit-repro/` (scripts et faux binaire de reproduction ; copies dans `/home/user/AUDIT-SentinelX-global/preuves/`).
- `/home/user/AUDIT-SentinelX-global/` (ce rapport, le plan, les preuves, les propositions de Skills).

Aucun fichier existant n'a été modifié.

### 1.4 Légende
- **[C] Confirmé par lecture de code** : chemin et fonction identifiés, ligne citée.
- **[R] Reproduit** : exécuté en isolation, sortie dans `preuves/`.
- **[H] Hypothèse** : plausible, non vérifiée. Contient la vérification à faire.
- **[S] Spécification** : règle approuvée dans `ARENA.md` (`uploads/ARENA.md`, révision annoncée 13).

---

## 2. Vérification des éléments antérieurs

- **Correction de mon constat précédent :** le fait que `scan_degraded_active` ne soit pas restauré au redémarrage **n'est pas un défaut**. `ARENA.md` §9.8 le prescrit explicitement (« `scan_degraded_active = False` au démarrage (non restauré) »). Je le retire de la liste des anomalies.
- **Point de spécification non tranché :** `ARENA.md` §9.8 liste les événements rejoués au redémarrage (`new_host`, `host_ports_initialized`, `new_port`, `host_not_observed`, `host_recovered`, `port_not_open`). Il ne mentionne **ni les compteurs** (`port_absent_count`, `host_absent_count`) **ni `mac_change`**. La reconstruction ne restaure donc pas ces compteurs. C'est un **silence de spécification** [S], à trancher, pas une régression.
- `ARENA.md` §9.6 (compteurs) est désormais lu. Le code (`_compute_port_transitions`) s'y conforme pour `None`, `[]` et `[ports]` (voir A1).

---

## 3. Constats détaillés

### 3.A1 — Détection des changements de ports (`port_not_open`, `new_port`)

**Chemin d'exécution.** `sentinel/monitor.py` (`CycleObservations` l.74, `HostTcpObservation` l.43) → `sentinel/sentinel_manager.py` `_do_check` → `_compute_port_transitions` (l.460) → `NetworkChange` → `sentinel/alerting.py` → `NotificationWindow` (`sentinel/notifications.py`, `WINDOW` l.7, `LIMIT` l.8).

`detect/tcp_scan.py` : `parse_sentinel_open_ports` (l.558) ne retient que `state="open"`. `_parse_tcp_xml_with_states` (l.444) ignore `closed`, `filtered` et `open|filtered` (`if state != "open": continue`, l.~494).

**Ce que le code fait [C][R].**
- `None` (inconnu) : compteurs du host remis à zéro, aucune conclusion (l.467-470).
- `[]` (scan complet, 0 port) : les ports connus absents incrémentent, `port_not_open` au 2e scan.
- `[ports]` : ports présents remis à zéro ; un port nouvellement ouvert produit `new_port`.
- Reproduction (`preuves/repro_a1.py`) :
  - A) port 80 fermé, deux scans complets : `port_not_open(80)` au 2e scan.
  - B) port 80 `filtered`, deux scans complets : **sortie identique à A**.
  - C) scan incomplet puis `[22]` : compteur 80 = 1, aucun événement. Conforme.
  - D) deux `[]` : `port_not_open` pour 22 et 80. Conforme à §9.6.
  - E) `[22]` puis `[22,80]` : réouverture avant deux absences, aucun événement. Conforme.

**Faits.**
- Un port `filtered` est traité comme **non ouvert**, donc comme absence observée. Le message produit (« absent from two complete TCP scans ») est exact sur le plan factuel, mais il **ne distingue pas fermé et filtré**. Un port filtré signale souvent un pare-feu, ce qui est une information de sécurité différente d'un service arrêté.
- `ARENA.md` §9.2 et §9.6 parlent de « port absent » sans définir `filtered`. Le cas n'est pas tranché.
- Les tests couvrent `filtered` seulement au niveau du parseur (`tests/test_tcp_scan.py` l.13, 104, 125, 291 : « open|filtered MUST NOT produce a Finding »). **Aucun test ne couvre `filtered` dans les transitions.**

**Cause racine.** Ambiguïté de spécification : l'état Nmap `filtered` n'a pas de règle définie. Le code applique le choix implicite « non ouvert = absent ».

**Conséquences.** Un pare-feu qui filtre un port après un service arrêté produit un message identique. Pas de faux positif de « fermeture » sur l'hôte, mais une perte d'information.

**Compteurs après redémarrage [C].** `port_absent_count` n'est pas restauré : `_rebuild_transition_state` (l.286-362) l'initialise à `{}` (l.318). Une absence en cours avant redémarrage repart à zéro ; il faut deux nouvelles observations complètes. Conforme à la lettre de §9.8, mais non explicite.

**Correction minimale proposée (en attente de décision).**
1. Décider si `filtered` (et `open|filtered`) doit produire un événement distinct, par exemple `port_filtered` ou un libellé dans `evidence`, ou rester identique à `port_not_open`.
2. Si décision « identique » : documenter explicitement dans `ARENA.md` (§9.6) qu'un port filtré est traité comme non ouvert.
3. Décider si les compteurs doivent être restaurés au redémarrage (ajout à §9.8). Sans décision, ne rien changer.

**Alternative.** Ne pas toucher au code et seulement documenter. Avantage : aucun risque de régression. Inconvénient : l'ambiguïté reste.

**Tests nécessaires.** Transitions avec `filtered` (deux scans consécutifs) ; restauration post-redémarrage des compteurs si décidée.

**Tests existants.** `_rebuild_transition_state` : `tests/test_sentinel_manager.py` l.525-546. Transitions : 5 fichiers de test, aucun sur `filtered`.

---

### 3.A2 — Résolution des identifiants de Findings (`FD-…`, UUID)

**Chemin.** `netlab findings show <id> -s <session>` → `resolve_finding_id` (`core/database.py` l.597) : accepte `FD-XXXXXXXX` (résolu contre `format_finding_id`), détecte l'ambiguïté (« Ambiguous Finding ID… Use the full internal ID. Matches: … »), et accepte l'identifiant interne complet.

`netlab sentinel findings show <id> -s <session>` (`cli.py` l.1648) → `sentinel_read_finding` (`core/database.py` l.2034) : `str(uuid.UUID(finding_id)) != finding_id` → `ValueError('UUID complet canonique requis')`. Aucune résolution de préfixe. Rejette aussi les sessions mixtes et non Sentinel.

**Affichage.** Tableaux (`_render_findings_table`, `cli.py` l.1890-1912) : `FD-` + 8 hex (`format_finding_id`, `core/finding.py` l.101 ; SHA-256 si ID non UUID). Notifications du monitor (`sentinel/monitor_view.py` l.94-109) : UUID complet. Hint à la ligne l.90.

**Faits [C].** Deux règles coexistent. Un utilisateur qui copie `7888681f5ba6` depuis un tableau (`FD-` absent, 12 hex) reçoit le refus, car le hex brut sans `FD-` n'est jamais résolu par préfixe. Le texte du tableau et la commande attendue ne correspondent pas.

**Cause racine.** Deux chemins de résolution développés séparément. Le chemin Sentinel n'a pas été aligné sur `findings show`.

**Conséquences.** Friction et erreurs de copie. Risque faible : pas de mauvais Finding résolu, car la sortie reste exacte ou refusée.

**Correction proposée (en attente de décision).** Options :
- (a) Garder l'UUID complet obligatoire, mais afficher dans le message d'erreur l'UUID complet correspondant si le préfixe est unique dans la session, et la liste des correspondances si ambigu.
- (b) Aligner `sentinel findings show` sur `findings show` : résolution de préfixe **dans la session** uniquement, avec détection d'ambiguïté, UUID complet obligatoire en cas d'ambiguïté.
- (c) Afficher l'UUID complet dans les tableaux. Rejeté a priori : largeur de colonne.

Recommandation : (b), car c'est la règle déjà utilisée par `findings show` et elle reste sûre (portée limitée à la session, refus si ambigu).

**Tests nécessaires.** Préfixe unique (résolu) ; préfixe ambigu (refus avec liste) ; préfixe hors session (refus) ; UUID complet (inchangé) ; hex sans `FD-` (règle choisie).

---

### 3.A3 — Le « 0 » du rapport pour `192.168.57.7`

**Traçage [C].**
1. Événement observé : `sentinel/monitor.py` / `sentinel_manager.py` (`new_port`).
2. Enregistré : `sentinel_save_event` (DB). Si `new_port`, `save_finding` **avant** la décision d'affichage (§9.2 : Finding « ✅ si non whitelisté »).
3. Décision d'affichage : `NotificationWindow.emit` (`sentinel/notifications.py`) écrit dans `details.notification` : `state` (`confirmed`, `masked`, `preparing`, `uncertain`), `emitted_at`, `decided_at`.
4. Récupéré : `reports/sentinel_report.py` l.48 : `hosts=sorted(host_summary(data['events'], now).values(), ...)`, `now` = **heure de génération**.
5. Transformé : `host_summary` (`notifications.py`) compte `displayed` = événements `confirmed` dont `emitted_at` est dans les 60 dernières minutes ; `masked` idem avec `decided_at`. **Le filtre ne regarde pas le type d'événement** : tout événement de l'hôte compte.
6. Affiché : `reports/templates/sentinel_status.html` l.28-29, section « Voir plus — quotas par hôte à la génération (60 dernières minutes) », colonne **« Affichées »**.

**Reproduction (`preuves/repro_a3.py`).** Un `new_port` confirmé il y a 2 h → `displayed: 0`, `available: 3`, état « disponible ». Ajout d'un `host_not_observed` récent → `displayed: 1`, sans lien avec le port.

**Niveau de divergence.** Le rapport est **exact sur la donnée qu'il affiche** (quota de notification par hôte sur 60 min à la génération). Il est **trompeur** s'il est lu comme « nombre de nouveaux ports ». La divergence est donc **de sémantique d'affichage**, pas de données perdues : le Finding et l'événement existent en base.

**Cause racine.** Réutilisation de `host_summary` (conçu pour le quota) comme indicateur d'événements, avec un libellé qui ne précise pas le type ni la fenêtre glissante.

**Correction minimale (en attente).** Libellé explicite (« Notifications affichées sur 60 min (quota) »), et si besoin une section séparée « Événements de la session » filtrée par type. Pas de changement de données.

**Tests.** Rapport avec `new_port` ancien (> 60 min) : la ligne doit afficher le libellé de fenêtre ; `new_port` récent : compté. Test de non-régression sur `host_summary` (déjà présent : `tests/` 1 fichier).

**Vérification restante [H].** Confirmer sur le rapport réel que le `0` pour `192.168.57.7` vient bien de cette colonne et non d'un autre champ. Cela exige de lire le rapport produit, pas `~/.netlab`.

---

### 3.B1 — « Rescan findings » absent

**Équivalent existant [C].** `netlab findings rescan --session <id> [--finding <id>]` (`cli.py` l.1351). Confirmation `typer.confirm` (défaut non). Appelle `_run_verify` (`cli.py` l.1500) sur la **session d'origine**. Ne crée pas de session et ne découvre pas d'hôte.

**Éligibilité.** `OPEN` et `VERIFIED`, hors `device_fingerprint`. `_verify_control` : `tcp_scan` et `udp_scan` contrôlent le port ; `misconfig_detection.*` ont leurs contrôles ; **`sentinel.*` et autres modules → PARTIAL « Unsupported module »**.

**Tests [C].** `tests/test_verify.py` l.412, 500 couvrent `findings rescan`.

**Documentation [C].** README.md l.50, 64, 89, 132-136 ; `docs/IMPLEMENTATION-TRACKING.md` T17.

**Cause du malentendu.** Le nom de la commande est `findings rescan`, pas `rescan findings`. La documentation ne l'indique pas assez en tête de section (à vérifier).

**Distinction à maintenir (proposition).** (1) **Nouveau scan réseau** : `netlab scan` / `netlab sentinel` ; crée une session, confirmation réseau. (2) **Réévaluation de Findings existants** : `findings rescan` ; pas de trafic nouveau, seulement VERIFY sur la session d'origine.

**Point ouvert.** Findings `sentinel.*` en PARTIAL : une réévaluation de Finding Sentinel n'est pas possible aujourd'hui. Décision propriétaire : faut-il un contrôle dédié pour `sentinel.*` (par exemple vérifier le port de `new_port` en réévaluant la session Sentinel), ou accepter PARTIAL ?

**Correction proposée.** Aucune nouvelle commande. Décider du sort des Findings Sentinel (ci-dessus). Éventuellement un alias `findings rescan` dans l'aide, sans nouvelle commande.

---

### 3.B2 — `creds_check` : « no compatible candidates » et coffre

#### 3.B2.a SSH
**Reproduction [R] (`preuves/repro_b2.py`, `repro_b2b.py`).**
- `prepare_candidates(None, ['ssh'], None)` → `An explicitly selected service has no compatible candidates`.
- Même résultat avec `profile='legacy'`.
- `ftp` seul → OK ; `ssh+ftp` → refus (échec atomique, voulu).
- `SUPPORTED` = `{smb, ftp, snmp, ssh}`. Le catalogue `legacy` = `{ftp, snmp}`.
- Les profils contenant SSH : **uniquement** `dell-idrac-legacy-root` (`knowledge/default_credentials.json`).

**Cause racine [C][R].** Le catalogue par défaut ne contient **aucun candidat SSH générique**. `prepare_candidates` (`detect/credential_dictionary.py` l.200-215) refuse à juste titre l'absence de candidat pour un service explicitement demandé. Le message est exact, mais **n'indique pas la cause** (absence de catalogue SSH) ni la marche à suivre (`--dict` ou un profil).

**Faits.** Le périmètre V1 inclut « SSH-password » (`ARENA.md` §5 : T22 scope V1 FTP, SNMP, SSH-password, SMB, verrouillé). Donc **l'absence de candidat SSH par défaut est une lacune du catalogue**, pas une erreur d'usage, mais la réponse à donner est un choix produit (ajouter un catalogue SSH, ou exiger `--dict`).

**Hypothèse à vérifier [H].** `--profile dell-idrac-legacy-root --service ssh` fonctionne. Non testé, pour éviter de charger un profil sur une cible.

**Correction proposée (en attente de décision).**
1. Message : indiquer « aucun candidat SSH dans le catalogue sélectionné ; fournir `--dict` ou un profil qui couvre SSH ».
2. Produit : décider si un catalogue SSH générique est ajouté (et qui le valide : les identifiants par défaut sont une donnée sensible, à valider par le propriétaire).

**Tests.** Message contient la cause ; `--service ssh` avec `--dict` valide passe ; sans candidat → refus.

#### 3.B2.b Création du coffre (phrase de passe)
**Code [C].** Règle de création (`core/credential_vault.py`, `open_vault` ~l.240-321) : refus si `len < 20` ou `len(set(phrase)) < 8` ou `len > 1024`, avec le message affiché « Use a long non-trivial vault passphrase (20-1024 characters). ». **Le message ne mentionne pas la règle des 8 caractères distincts.** Une phrase de plus de 20 caractères avec moins de 8 caractères distincts est donc refusée avec un message qui semble faux.

**Non vérifié [H].** Le secret n'a pas été demandé ni reproduit. Le constat repose sur la lecture de la règle. Vérification isolée possible avec une phrase synthétique dans un coffre temporaire (non faite, pour ne pas toucher au coffre réel).

**Correction minimale (en attente).** Message qui énumère les deux règles réelles (longueur 20-1024 ; au moins 8 caractères distincts). Aucun changement de règle sans décision.

#### 3.B2.c Emplacement du coffre sous `sudo`
**Code [C].** `default_vault_path()` (`core/credential_vault.py` l.34-35) = `Path.home() / '.netlab' / 'credentials' / 'vault.enc'`. Les bases utilisent `_real_user_home()` (`core/database.py` l.56-80), qui lit `SUDO_USER` puis `SUDO_UID`, et refuse de basculer vers `/root` si les métadonnées sudo sont présentes mais non résolues.

**Reproduction [R] (`preuves/` : simulation avec `SUDO_USER=user`, `HOME` temporaire).** Coffre sous le `HOME` courant ; base sous `/home/user`. **Divergence confirmée.**

**Cause racine.** `default_vault_path` n'a pas été aligné sur `_real_user_home()`.

**Conséquence.** Sous `sudo`, le coffre peut être créé sous `/root/.netlab/credentials/`, alors que les bases sont sous l'utilisateur réel. Données de credentials séparées de leurs bases, et lisibles selon les droits de `/root`. **Risque de sécurité : moyen** (pas de fuite démontrée, mais placement incohérent d'un secret).

**Correction minimale.** Utiliser `_real_user_home()` (ou la même logique) pour le coffre, avec le même refus en cas de métadonnées sudo non résolues.

**Tests.** `SUDO_USER` valide → chemin utilisateur ; `SUDO_USER` inconnu → refus ; sans sudo → inchangé.

---

### 3.B3 — `smb_enum` : « no shares or domain info » alors que enum4linux-ng répond

**Chemin [C].** `smb_enum` (`detect/smb_enum.py` l.94) → `_resolve_tool_path` → `_run_enum4linux_ng` (l.138) : commande `ENUM4LINUX_NG_PYTHON ENUM4LINUX_NG_SCRIPT -A --json <ip>` (l.150 et l.183), `timeout=120`, `check=False`, **code de retour ignoré**, `stdout + stderr` concaténés. Sortie vide → `None` → « No output ». `normalize_smb_output` : `json.loads` sur la sortie complète ; échec → `_normalize_text_output`.

**Reproduction [R] (`preuves/repro_b3.py`, faux binaire `fake_enum4linux_ng.py` qui rejette `--json` comme argparse, rc=2).**
- Commande exécutée : `[python, fake, '-A', '--json', '192.168.57.3']`.
- Sortie : « SMB enumeration complete — no shares or domain info on 192.168.57.3. », **0 finding**.
- Le code de retour 2 et le message d'erreur ne sont jamais remontés.

**Repli texte [R] (`preuves/repro_b3.py`, `normalize_smb_output` sur « Account: alice »).** `users=()`. Le compte n'est pas lu. Cause : regex `Account:\\\\s*(\\\\S+)` doublement échappée (dans `_normalize_text_output`) : elle ne capture rien. Aucun test ne couvre le repli texte pour les comptes.

**Point majeur — documentation amont [H, fort].** La documentation d'enum4linux-ng ne référence pas `--json` ; l'export JSON se fait par `-oJ FICHIER` (la même doc liste `-oY` et `-oA`). **À vérifier avec la version réellement installée** (`enum4linux-ng --help`) : c'est une lecture locale du binaire, sans scan.

**Tests existants [C].** `tests/test_smb_enum.py` l.122 fige la commande fausse (`-A --json <ip>`). Les tests d'erreur (l.143-184) simulent `TimeoutExpired` et `OSError` ; **aucun ne simule un code non nul avec sortie non JSON**. Les tests de sortie utilisent des fixtures déjà au format attendu.

**Relation avec `netlab doctor`.** `core/dependencies.py` vérifie l'outil par `ENUM4LINUX_NG_PYTHON ENUM4LINUX_NG_SCRIPT --help` (l.118-135). Un `--help` réussi **ne prouve pas** que les options utilisées existent : le doctor n'a pas détecté le problème. Les chemins par défaut sont codés en dur sur `/home/anonymous/enum4linux-ng/…` (l.48-49), surchargés par variables d'environnement.

**Cause racine (confirmée en isolation pour le mécanisme ; hypothèse forte pour le déclencheur).**
1. Option `--json` probablement inexistante → rc≠0 ;
2. code de retour ignoré → l'échec est lu comme une absence de résultat ;
3. sortie d'erreur mélangée à la sortie utile → `json.loads` échoue → repli texte, qui ne lit pas les comptes.

**Conséquence.** **Faux négatif sur un outil de sécurité** : l'utilisateur conclut à l'absence de partage alors que l'outil n'a pas tourné. C'est le cas que la mission demande d'éviter (« ne pas conclure absence de partage »). Pas de scan hors périmètre, pas de corruption, pas de fuite.

**Correction minimale proposée (en attente).**
1. Traiter tout code de retour non nul comme **échec de l'outil**, distinct de « aucun résultat » : message d'erreur explicite, pas de finding.
2. Utiliser la syntaxe vérifiée de la version installée (`-oJ` ou lecture de stdout selon la version), après vérification par `--help`.
3. Séparer stdout et stderr ; ne parser que stdout.
4. Corriger la regex du repli texte (échappement).
5. Étendre `netlab doctor` pour vérifier les options utilisées (et non seulement `--help`).

**Alternative.** Garder `--json` en ajoutant un test d'option au démarrage. Plus simple, mais dépend encore d'une version.

**Tests nécessaires.** Faux binaire rc=2 → échec explicite, aucun « no shares » ; sortie JSON propre ; sortie texte avec « Account: alice » → `users=('alice',)` ; JSON précédé de texte parasite → lu ; doctor : option absente → signalé.

---

### 3.B4 — Timeouts OS Nmap et « no usable fingerprint »

**Chemin [C].** `recon/device_fingerprint.py` : `fingerprint` (l.64) → Pass 1 `_run_nmap_ping` (`nmap -sn -oX - <target>`, timeout par défaut 300 s) → Pass 2 `_run_nmap_os` (l.181-196 : `nmap -O --osscan-guess -oX - <ip>`, **timeout=60 s codé en dur**) par hôte, **séquentiel**. `_run_nmap` (l.199-233) :
- rc≠0 → affiche et retourne `None` (« OS detection unavailable ») ;
- `TimeoutExpired` → `DiscoveryFailed` → capturé dans `fingerprint` → `os_xml = None` ;
- XML valide sans `osmatch` → `_has_os_match` (l.368) faux → « OS detection returned no usable fingerprint ».

**Arrêt et sortie partielle [C].** `core/process_control.py` (`run_process`, `_stop_child`) : à l'échéance, le processus est arrêté (`terminate` puis `kill` après 5 s) et **la sortie partielle est perdue** (`TimeoutExpired` levée, pas de retour de sortie). Le contrôle de processus est correct.

**Faits.**
- Le délai de 60 s est codé en dur, sans configuration.
- La détection OS est faite hôte par hôte, en série : N hôtes × 60 s au maximum.
- `nmap -O` nécessite des privilèges raw : la docstring le dit (`_run_nmap_os`, « Requires root/sudo »). Sans privilège, nmap échoue (rc≠0 probable) → « unavailable », pas « no usable fingerprint ». **Les deux messages ont donc des causes distinctes.**

**Causes candidates, non confirmées [H].**
- H1 : privilèges insuffisants (rc≠0) → message « unavailable ». À confirmer par `nmap -O` sur une cible **de test contrôlée** (ou exécution locale sans réseau) — non fait ici.
- H2 : hôte lent ou filtré : `-O` dépasse 60 s, sortie jetée. Plausible pour des hôtes qui répondent peu. À mesurer.
- H3 : `-O --osscan-guess` ne trouve pas de correspondance (appareil peu identifiable) → « no usable fingerprint ». Comportement attendu de nmap, pas un bug.

**Ce qu'il ne faut pas faire.** Augmenter le timeout seul : sans mesure, on allonge l'attente sans savoir si H2 est la cause, et la sortie reste jetée à l'échéance.

**Correction proposée (en attente).**
1. Mesurer (isolé, fixtures ou cible autorisée) la durée de `-O` par type de cible.
2. Rendre le timeout configurable, avec valeur par défaut documentée.
3. Distinguer dans le message : privilèges manquants / timeout / pas de correspondance OS.
4. Option : conserver la sortie partielle à l'échéance (si nmap a déjà écrit du XML) — à évaluer.

**Tests.** Faux binaire : rc=1 → message « privilèges » ; délai dépassé → message « timeout » ; XML sans osmatch → message « pas de correspondance » ; les trois ne produisent aucune conclusion OS.

**Tests existants.** `tests/` contient des tests `osscan`/`-O` (2 fichiers) et `timed out` (1 fichier) : à lire pour compléter le détail.

---

### 3.B5 — Ports 512/513/514 classés `info`, `CONFIRMED`, « CVSS 5.0 »

**Chemin [C].**
1. `detect/tcp_scan.py` `_parse_tcp_xml_with_states` (l.444) crée un Finding pour chaque port `open` : `severity=Severity.INFO` (l.~508, « scored after CVE lookup »), `confidence` via `_extract_service` (l.609) : `method="probed"` → **CONFIRMED**.
2. `detect/service_detection.py` `enrich_findings` / `_apply_cve` (l.343) : enrichit **si une entrée de `knowledge/cve_db.json` correspond**. Aucune entrée 512/513/514 n'existe dans `cve_db.json`, `ports.json` (512-514 = `None`), `vulnerabilities.json`, ni dans le code (recherche complète).
3. `core/risk_scorer.py` `calculate_score` (l.109) : sans `cvss_score`, `base = base_severity[info] = 5` (`config.yaml`). Score = 5 × 1,00 (CONFIRMED) × 1,00 (INTERNAL) = **5,00**.

**Constat de nommage [C].** Le « CVSS 5.0 » observé est donc le **`risk_score`** du scoring interne, **pas un CVSS**. Le mot « CVSS » est faux.

**Constat de scoring [C].** `get_global_score` (l.207) retient le maximum des Findings `OPEN`, confiance ≥ 0,7, hors `device_fingerprint`. **Un port ouvert `info` CONFIRMED entre dans le score global** (5,0). Aucun port ouvert n'est donc « neutre » pour le score : ouvrir 22 seul donne déjà 5,0.

**Constat de confiance [C].** `CONFIRMED` signifie « port ouvert et service identifié par sonde » (`method=probed`). Ce n'est **pas** une confirmation de vulnérabilité. Le même mot désigne deux choses.

**Faits sur les ports.** RSH/RLOGIN/REXEC (512-514) sont des services hérités, en clair, à authentification par confiance d'hôte. Un risque réel existe **si** le service est ouvert, mais aucune règle ne le décrit. Aucune règle ne doit transformer chaque port ouvert en vulnérabilité.

**Cause racine.** Modèle à une seule sévérité par défaut (`info`) pour tout port ouvert, sans table de services à risque. Le libellé « CVSS » est une étiquette de rapport erronée. Le score global peut donc être dominé par des ports ouverts informatifs.

**Correction proposée (en attente, décision produit).**
1. Renommer le libellé : « score de risque (interne) », jamais « CVSS », sauf si `cvss_score` est présent.
2. Décider si un port ouvert `info` doit compter dans le score global (proposition : non, il relève de l'inventaire, comme `device_fingerprint`).
3. Si un risque est voulu pour rsh/rlogin/rexec : règle explicite (`misconfig_detection` ou KB dédiée), avec source et sévérité justifiées, validée par le propriétaire.

**Tests.** Port `info` CONFIRMED : pas de libellé CVSS ; score global exclu si décision ; règle dédiée (si ajoutée) pour 512-514 avec confiance justifiée. Tests existants : aucun pour 512-514 (grep négatif).

---

### 3.C — Réseau `192.168.57.0/24` surveillé de façon inattendue

**Distinction des notions (proposition, à valider).**
- **Réseau connecté** : routes locales détectées (`ip route`, `sentinel/baseline.py` l.182-254 : `detect_network_identity`, `_gateway_for_connected_route`). Ne décide de rien seul.
- **Réseau choisi** : CIDR passé à `netlab sentinel start --target` (`cli.py` l.1675-1680 : **obligatoire**, « CIDR obligatoire du réseau autorisé à surveiller »).
- **Réseau surveillé** : réseau dont une session Sentinel est active, identifié par `network_id` (`sentinel/baseline.py` l.51-63 : SHA-256 de `CIDR|gateway_ip|gateway_mac`, tronqué à 12 hex). Base : `~/.netlab/sentinel/<network_id>.db`.
- **Réseau scanné** : plages effectivement envoyées à Nmap (ping `-sn`, TCP) pour la cible surveillée.

**Faits [C].** Le monitor ne choisit pas un CIDR : il surveille celui fourni à `--target`. Le `network_id` dépend de la passerelle et de la MAC : deux passerelles différentes sur le même CIDR donnent deux `network_id`, donc deux historiques. `sentinel status` liste les réseaux connus (`_resolve_status_network_id` l.702 ; message « Multiple Sentinel networks are available » l.714).

**Ce qui ne peut pas être établi sans lire `~/.netlab`.** Savoir si `192.168.57.0/24` a été démarré explicitement, s'il s'agit d'une session encore active, ou d'un réseau enregistré à partir d'une ancienne commande. Lire ou modifier `~/.netlab` est interdit pendant l'audit.

**Hypothèses [H] à vérifier par le propriétaire (commandes en lecture seule à lancer par lui).**
- H1 : une session `sentinel start --target 192.168.57.0/24` a été lancée (volontairement ou non) et est toujours active. Vérifier : `netlab sentinel status` (liste et état).
- H2 : une identité réseau différente (passerelle changée) a créé un second `network_id` sur le même CIDR. Vérifier : liste des `network_id` et leurs gateways.
- H3 : la surveillance est un reliquat d'un lancement précédent (verrou non libéré). Vérifier : `netlab sentinel status` et les processus.

**Niveau.** P1 provisoire. **Escalade P0** si H1 ou H3 est confirmé et que le démarrage n'a pas été voulu par le propriétaire : le scan d'un réseau non voulu est un scan hors périmètre.

**Correction proposée (en attente).** Aucune modification de code avant diagnostic. Ensuite : affichage explicite au démarrage du **CIDR choisi**, de la **passerelle** et du `network_id` ; commande de liste des sessions actives avec leur CIDR ; ne jamais fusionner des historiques de `network_id` différents.

**Tests.** Deux `network_id` sur le même CIDR restent séparés ; `status` affiche chaque réseau surveillé avec son CIDR.

---

## 4. Dérives documentaires et Skills (constats)

Constats vérifiés (lecture, pas de modification) :
- `docs/IMPLEMENTATION-TRACKING.md`, `docs/MASTER-REFERENCE.md` (§2, §6.4) et `.kiro/skills/impl-tracking.md` déclarent HEAD `3657498`. Les commits `63e1a7b`, `b1ab727`, `e4f3f9e`, `9034f01` ne sont pas consignés (les trois premiers relèvent des travaux des tickets 3 et 4 de l'historique de session ; à confirmer dans le dépôt).
- `CONFIDENCE-CLI` est déclaré « commit en attente » alors que `85870ac feat(cli): add confidence column to findings tables` existe (`git log` du clone `9034f01`).
- `MASTER-REFERENCE.md` §2 indique `/home/anonymous/sentinelX` (chemin d'un autre poste).
- `.cursor/rules/sentinelX.mdc` pointe vers `.kiro/steering/sentinelx.md` (minuscules). Le fichier réel est `.kiro/steering/sentinelX.md`. Référence cassée sous Linux (sensible à la casse).
- Docs et Skills renvoient à `ARENA.md` (téléchargement propriétaire, révision 13). Chemin réel : `/home/user/uploads/ARENA.md`.

**Inventaire réel des Skills [C].**

| Fichier | Copies | SHA-256 (identique entre copies) |
|---|---|---|
| `.kiro/skills/impl-tracking.md` | `/home/user/sentinelX-impl/`, `/home/user/ci-audit-sentinelx-20261110/`, `/tmp/audit-sentinelX/` (`9034f01`) | `2d8037a837d29545e6175459fd58d750af7617f5ee00a6e38065c1fb17b7c60c` |
| `.cursor/rules/sentinelX.mdc` | `/home/user/sentinelX/`, `sentinelX-impl/`, `sentinelX-reference/`, `ci-audit-sentinelx-20261110/`, `sentinel-cli-help-netlab/`, `sentinel-host-silence-monitor-report/`, `sentinel-lifecycle-fix/`, `sentinel-persistence-fix/`, `t23b-work/sentinelX-t23b/`, `/tmp/audit-sentinelX/` | `65f3caa21383fa56a54a962f2bf5f809c4a1fa5ee727834008cf3ed7a56cd0f0` |

- **Aucun Skill nommé « Arena » n'existe** dans l'espace de travail. Le fichier `ARENA.md` est un document de référence, pas un Skill.
- `/home/user/sentinelX/.kiro/skills/` **n'existe pas** dans le dépôt de travail (le Skill Kiro n'y figure pas), alors qu'il est présent dans `sentinelX-impl`.

---

## 5. Points non résolus (à trancher par le propriétaire)

1. `filtered` : événement distinct, ou identique à `port_not_open` (A1).
2. Compteurs d'absence après redémarrage : restaurer ou non (silence de §9.8) (A1).
3. Résolution des identifiants Sentinel : option (a), (b) ou (c) (A2).
4. Libellé et sémantique du rapport (A3).
5. Findings `sentinel.*` en réévaluation (B1).
6. Catalogue SSH par défaut : ajouter, ou exiger `--dict`/profil (B2).
7. Emplacement du coffre sous `sudo` (B2).
8. Sortie de `enum4linux-ng` : version installée et syntaxe retenue (B3).
9. Timeouts OS : valeur, configuration, message (B4).
10. Port `info` dans le score global ; libellé « CVSS » (B5).
11. Origine du réseau `192.168.57.0/24` (C), **à établir en priorité**.
12. Sort des modifications non commitées dans les trois clones locaux et de `/tmp/audit-sentinelX` (à supprimer sur demande).

---

## 6. Preuves

Répertoire : `/home/user/AUDIT-SentinelX-global/preuves/`.

| Fichier | Objet | Résultat constaté |
|---|---|---|
| `fake_enum4linux_ng.py` | Faux binaire : rejette `--json` (rc=2) | — |
| `repro_b3.py` | B3 : `smb_enum` avec faux binaire ; repli texte | `RC: 2`, `FINDINGS: 0`, « no shares or domain info », `users=()` |
| `repro_b2.py` | B2 : `prepare_candidates` SSH/FTP | SSH → « no compatible candidates » ; FTP OK |
| `repro_b2b.py` | B2 : profils et services du catalogue | `legacy` = ftp, snmp ; SSH seulement dans `dell-idrac-legacy-root` |
| `repro_a1.py` | A1 : transitions (`_compute_port_transitions`) | `filtered` = fermé ; `None` remet à zéro ; `[]` → port_not_open |
| `repro_a3.py` | A3 : `host_summary` | `new_port` de 2 h → `displayed: 0` |
| `stub_portalocker.py` | Stub isolé (module absent du Python système, non utilisé par la logique testée) | — |

Exécution : Python système (`/usr/local/bin/python3`), `HOME` temporaire, `SUDO_*` retirés. `~/.netlab` : 4744 entrées avant/après.

**Non fait (volontairement) :** scan Nmap réel, enum4linux-ng réel, test de credential, lecture ou modification de `~/.netlab`, saisie du secret du coffre, `git` d'écriture, exécution de la suite de tests complète (non nécessaire aux constats ; le propriétaire peut la lancer via `ci-audit-20261110/iso-pytest.sh`).

---

## 7. Décision demandée

Ce rapport et le plan (`PLAN-correction.md`) sont soumis à la revue de Nova. **Aucune correction ne doit être implémentée avant validation explicite du propriétaire.** Les propositions de Skills et de documentation sont dans `skills-proposees/` et restent **en attente de décision du propriétaire**.
