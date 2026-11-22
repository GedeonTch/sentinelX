# SPEC-A1 consolidée — politique TCP approuvée (formalisation)

> **DOCUMENT HISTORIQUE — NON NORMATIF.**
> La référence normative des critères d'acceptation A1 est `SENTINEL-TCP-STATES.md`, notamment son §9. Les anciennes numérotations de critères de ce document ne doivent plus être utilisées pour planifier ou valider une implémentation.

**Statut** : spécification pour ticket futur. **Aucune implémentation.** **Réconciliée le 2026-11-12** avec les décisions du propriétaire (statuts ci-dessous) ; reste une proposition tant que son emplacement canonique (DEC-01) n'est pas tranché. Version de référence proposée : `docs-proposees/SENTINEL-TCP-STATES.md`. Lecture seule ; aucun code, test, Skill, document maître, base ni `~/.netlab` modifié ; aucun scan réseau réel.
**Référence de code** : `origin/a4-arena` = `9034f01` (clone de lecture `/tmp/audit-global-ref`, HEAD `9034f01`, statut vide ; `/tmp/audit-spec-ref` absent).
**Documents liés** : `PROPOSITION-A1-formalisation-TCP.md` (détail des tables, corrigé) ; `RAPPORT-verification-A1-chaine-production.md` (preuves et verdicts V1-V21) ; `RAPPORT-complement-A1-transitions-ports.md` (constats A1-1 à A1-8).
**Preuves** : `preuves/a1/a1_chain_verify.py` (harnais production), `.log`, `.json`, `a1_chain_details_sample.txt` ; `preuves/a1/a1_model_spec.py` (modèle de spécification, pas une preuve de conformité).

Légende : **[APPROUVÉ]** règle acquise par décision du propriétaire. **[PROPOSITION]** recommandation non tranchée. **[OUVERT]** décision non prise, à soumettre (Nova → propriétaire).

---

## 1. Règles approuvées (spécification)

| Réf. | Règle | Statut |
|---|---|---|
| R1 | `open` = port ouvert. | [APPROUVÉ] |
| R2 | `closed` confirmé seulement après **2 observations TCP complètes et consécutives** indiquant explicitement `closed`. | [APPROUVÉ] |
| R3 | `filtered` = état incertain : aucune fermeture déclarée, compteur de fermeture non incrémenté, **interrompt** une succession de 2 `closed`. | [APPROUVÉ] |
| R4 | `open\|filtered` : aucune conclusion de fermeture. | [APPROUVÉ] |
| R5 | États inconnus ou invalides : aucune conclusion de fermeture. | [APPROUVÉ] |
| R6 | Hôte entièrement filtré : aucune fermeture de masse. | [APPROUVÉ] |
| R7 | Compteurs intermédiaires d'absence non restaurés après redémarrage. | [APPROUVÉ] |
| R8 | Libellé D1 : distinction approuvée (nouveaux événements avec preuve / événements historiques sans preuve, §10). Libellé exact (« Port N closed » ou conditionnel) : **non approuvé, non tranché**. | [APPROUVÉ] forme ; [OUVERT] libellé |

**Interprétation de « consécutives » (R2)** : une observation TCP complète `closed` suivie d'un cycle sans observation TCP complète (hôte absent, ping KO sans ARP utile, scan dégradé) **n'est pas** consécutive à la suivante. Le comportement actuel (hôte absent : compteur conservé) ne respecte pas cette lecture. Voir §5.4 (V4 approuvé : remise à zéro).

---

## 2. Modifications minimales (parsing, observations, transitions)

Principe : changer le moins possible de signatures publiques. Un appelant qui ne veut que les ports ouverts conserve son comportement.

### 2.1 Parsing — `detect/tcp_scan.py`

- `_parse_tcp_xml_with_states` (l.444) construit déjà `states[port]` (affectation l.493). Le résultat doit être exposé sous forme d'objet d'observation : `status ∈ {COMPLETE, INCOMPLETE}` et `states: Dict[int, PortState]`, `PortState ∈ {OPEN, CLOSED, FILTERED, UNCERTAIN}`.
- `parse_sentinel_open_ports` (l.558) ne renvoie que les `open` et **jette** `states` : il reste la fonction de compatibilité pour l'apprentissage et les appelants existants.
- `_recorded_port_states` (l.337) ne lit jamais `extrareasons ports=` : l'attribution `<extraports>` est à ajouter (règles §3).
- `_run_nmap_tcp_strict` (l.251) : pas de changement attendu.
- `_check_tcp_xml` (l.354) : complétude inchangée (table partielle, doublon, nombre incohérent → INCOMPLETE).

### 2.2 Observations — `sentinel/monitor.py`

- `_get_open_ports` (l.264, appel l.276-282) : passer l'observation complète au manager. Toute exception reste traduite en « inconnu » (`None`) ; ce comportement est sûr pour les fermetures mais masque les erreurs de programmation (à signaler dans le ticket).
- `closed` et `filtered` ne doivent plus être perdus entre `monitor` et `sentinel_manager` (constat A1-1 : aujourd'hui identiques).

### 2.3 Transitions — `sentinel/sentinel_manager.py`

- `_compute_port_transitions` (l.460-505) : remplacer « absent de `known_open` ⇒ +1 » par la table §3.
- Remise à zéro sur `ScanFailedError` : bloc `except ScanFailedError` l.629-636, vidage `host_absent_count` l.632 et `port_absent_count` l.633 (conserver).
- `ScanDegradedError` partiel : les hôtes à `ports=None` sont traités comme INCOMPLETE (§3, ligne « scan incomplet ») ; les hôtes complets continuent normalement (mesuré : S4).
- `NetworkState.port_absent_count` (l.291) : à renommer en `closed_streak` **ou** à conserver avec sémantique documentée. Recommandation : conserver le nom pour limiter le diff.
- `_rebuild_transition_state` (l.300-362) : `port_absent_count` n'est pas restauré (R7, déjà le cas). Ne pas le restaurer.

### 2.4 Hors périmètre A1

- `sentinel/alerting.py` (`NO_FINDING_TYPES` l.67 contient `port_not_open` : confirmé ; `process_changes` l.149 inchangé), `sentinel/whitelist.py` (aucune exception `port_not_open`), `reports/sentinel_report.py`, `sentinel/baseline.py` (voir §9 : dépendance partagée).

---

## 3. Comportement cible des compteurs (par port `P` connu ouvert)

Compteur unique : `closed_streak[P]` = nombre d'observations `closed` complètes consécutives.

| Observation pour P | Effet sur `closed_streak[P]` | Événement |
|---|---|---|
| `closed` (scan complet) | +1 ; à 2 : retrait de `known_open`, remise à 0 | `port_not_open(P)` une fois par épisode |
| `open` | remise à 0 | si P n'est pas dans `known_open` : `new_port(P)` |
| `filtered` | remise à 0 (interrompt) | aucun |
| `open\|filtered`, `unfiltered`, absent, invalide, `bogus` (UNCERTAIN) | remise à 0 | aucun |
| Scan INCOMPLETE (`None`, hôte à `ports=None`) | remise à 0 pour tous les ports de l'hôte | aucun |
| Hôte **absent du cycle** (aucune observation TCP) | **[APPROUVÉ] V4** : remise à 0 (décision propriétaire) ; actuellement conservé (écart, S5) | aucun |
| `ScanFailedError` (aucune observation exploitable) | remise à 0 pour tous les hôtes | aucun |

Séquences (cycles 1…n, port 80 suivi, 22 `open` au départ) :

| Séquence | Attendu (spec) | Production mesurée |
|---|---|---|
| closed, closed | `port_not_open` c2 | c2 (S1, conforme) |
| closed ×2, open, closed ×2 (S1) | c2 `port_not_open` ; c3 `new_port` ; c5 `port_not_open` ; c6 aucun | S1 conforme |
| closed, filtered, closed, closed | `port_not_open` c4 | **non mesuré** (le modèle le couvre ; S-chaîne absente) |
| filtered ×2 | aucun | **c2 `port_not_open`** (S7, NON CONFORME, A1-1) |
| open\|filtered ×2 | aucun | **c2 `port_not_open`** (S8, NON CONFORME, A1-3) |
| closed, None (ScanFailed), closed, closed (S6) | `port_not_open` c4 | c4 (S6, conforme) |
| None, closed, closed (modèle, cas 5b) | `port_not_open` c3 | non mesuré en chaîne |
| closed, RESTART, closed, closed (cas 22) | `port_not_open` c4 (retard d'un cycle) | S2 (redémarrage avant c2) : `port_not_open` c3, conforme au retard |
| closed ×4, RESTART avant chaque cycle | aucun événement (non convergence) | S3 : aucun événement, conforme à R7, risque noté |
| A absent c2 : closed c1, absent c2, closed c3, closed c4 | `port_not_open` c4 (V4 approuvé) | c3 (S5, **NON CONFORME**, V4) |
| 80 non listé, groupe `closed` ×2 | `port_not_open` c2 | à mesurer après correction de parsing |
| 80 non listé, groupe `filtered` ×2 | aucun | modèle : aucun (`a1_model_spec.py`) |

Pas de réémission : après `port_not_open`, le port quitte `known_open` ; une réouverture produit `new_port`, un nouveau `closed` produit un nouvel épisode.

---

## 4. Représentation des états incertains

Quatre cas doivent rester distincts, y compris dans la signature de parsing :

| Représentation | Sens | Peut conclure « fermé » ? | Aujourd'hui |
|---|---|---|---|
| `None` | scan INCOMPLETE : complétude non prouvée | non | `None` (existant) |
| `[]` | scan COMPLETE sans port `open` : **dérivé**, pas une preuve de fermeture | non | `[]` (existant) ; confondu avec `filtered` (A1-1) |
| `PortState.UNCERTAIN` (par port) | état explicite non concluant (`open\|filtered`, `unfiltered`, sans état, invalide, attribution contradictoire) | non | **n'existe pas** : `states` jeté |
| `PortState.FILTERED` (par port) | état explicite `filtered` ; interrompt la succession | non | **n'existe pas** |

Règles :
- Le `[]` ne doit jamais servir de preuve de quoi que ce soit en dehors de « aucun `open` ».
- Un état incertain **n'est pas** un scan incomplet : un `None` invalide tout l'hôte ; un `UNCERTAIN` n'invalide que le port.
- Mesure : `a1_chain_verify` P9 (`[]` pour scan complet) et P10 (`None` pour table partielle) distinguent bien les deux cas au niveau de la fonction.

### 4.1 Attribution `<extraports>` (XML Nmap)

Le DTD officiel (https://nmap.org/book/nmap-dtd.html, lu) impose seulement un schéma : `count` requis, `ports` optionnel, `state` en CDATA libre. **Le contenu réel n'est pas prouvé** (aucun scan réel).

| Cas | Règle proposée | Statut |
|---|---|---|
| État explicite dans `<port>` `open`, `closed` ou `filtered` | état direct | [PROPOSITION] (sûr) |
| État explicite autre (`open\|filtered`, absent, inconnu) | `UNCERTAIN` | [APPROUVÉ] (R4, R5) |
| Groupe avec `ports=` cohérent (union = complément exact des explicites, `count = len(ports)`, pas de chevauchement, dans le périmètre) | état du groupe si `closed` ou `filtered` | [PROPOSITION] |
| Groupe `ports=` incohérent (count ≠ liste, chevauchement, hors périmètre, union ≠ complément) | scan INCOMPLETE | [PROPOSITION] |
| Groupe sans `ports=`, seul groupe non attribué | état du groupe si `count` = nombre exact des ports non explicites | [PROPOSITION] |
| Plusieurs groupes sans `ports=` | aucune attribution individuelle : `UNCERTAIN` | [PROPOSITION] |
| Groupe `state="open"` | **jamais** de `open` déduit : `UNCERTAIN` | [APPROUVÉ] (règle structurelle) |
| Groupe `state` inconnu | `UNCERTAIN` | [APPROUVÉ] (R5) |
| Doublon `<port>` | INCOMPLETE (existant) | existant |

Mesures (harnais, parse) : P1 (80 à deux attributions), P3 (count incohérent), P4 (deux groupes non attribués), P11 (chevauchement explicite/groupe), P12 (port hors périmètre) donnent aujourd'hui `prod=[22]`, `valid=True`. **La production accepte ces cas** ; la spec exige `UNCERTAIN` ou INCOMPLETE. Écart à corriger.

---

## 5. Prévention des fermetures massives

### 5.1 Approuvé (R6)

Hôte entièrement filtré : aucune fermeture de masse. Mécanisme : R3 (un `filtered` n'incrémente pas) et garde explicite : sur scan complet sans `open` ni `closed` pour aucun port, aucun compteur n'est incrémenté et aucun `port_not_open` n'est émis.

### 5.2 Constat production (confirmé en chaîne)

- **A1-2 confirmé sur le chemin de production (S11)** : hôte baseline `22, 80` entièrement `filtered` pendant dix cycles → `port_not_open` 22 et 80 au **cycle 2**. Aucun cycle ultérieur. Conséquence : deux événements `port_not_open` pour un hôte entièrement filtré, en violation de R6.
- Le quota (`LIMIT = 3`, `WINDOW = 60 min`, `notifications.py` l.7-8) n'est **pas** une protection : il masque l'affichage, pas la fermeture (S9 : B, 17 masqués).

### 5.3 [APPROUVÉ] Tous les ports connus `closed` (cas 11)

Un hôte dont tous les ports connus sont `closed` complets deux fois donne une fermeture par port (22 et 80). R2 le permet à la lettre, mais la situation peut être un hôte réinitialisé ou un pare-feu qui répond RST. **Décisions du propriétaire** : fermetures individuelles autorisées quand tous les ports connus sont explicitement `closed` deux fois (G-a) ; **aucun seuil global arbitraire** (G-b écartée) ; agrégation visuelle (G-c) **reportée**, hors A1. Options d'origine :
- **G-a** : [APPROUVÉ] fermetures individuelles après deux `closed` explicites pour chaque port connu.
- **G-b** : seuil de fermetures par cycle : [ÉCARTÉ] (aucun seuil global arbitraire).
- **G-c** : agrégation de présentation (un message « N ports fermés sur hôte X »), comptage par port inchangé : [REPORTÉ], hors A1.

### 5.4 [APPROUVÉ] Hôte absent du cycle (V4)

Mesure S5 : A absent au cycle 2 (aucune observation TCP) ; la production conserve le compteur et émet `port_not_open` au cycle 3. La lecture stricte de « consécutives » (R2) impose le cycle 4. **Décision propriétaire : remise à zéro du compteur quand un hôte est absent d'un cycle.**

---

## 6. Modifications de présentation après le ticket 3

Référence : `TICKET3-EVENT-PRESENTATION-v2.diff` (présent dans `/home/user`).

1. **Mécanisme introduit par le ticket 3** : `presentation_detail(change)` (`sentinel/monitor_view.py` l.52-61) transforme `port N not open` en `Port N closed` pour **tout** `port_not_open`. Appelé par la vue live (`monitor_view.py`, méthode `emit` l.236, construction de la ligne `row`) et par les lignes terminal (`sentinel/alerting.py` l.19 et l.28).
2. **Effet de A1** : un `filtered` ou `open|filtered` ne produit plus d'événement → plus de libellé « Port N closed » pour un état incertain. Le défaut A1-1 disparaît **par construction** après correction.
3. **Limite** : le libellé persisté (`port N not open`, `events.details.detail`) et le rapport HTML (`reports/sentinel_report.py` l.27-35, `detail` brut) restent inchangés. Le libellé « Port N closed » reste imposé à tout `port_not_open`, y compris un ancien événement issu d'un `filtered` (indiscernable, voir §10).
4. **D1 : distinction approuvée ; libellé [OUVERT]** : changer le libellé exige de modifier `tests/test_sentinel_event_display.py` l.76-82 (impose « Port 80 closed » pour tout `port_not_open`) et `_PORT_NOT_OPEN_DETAIL` (`monitor_view.py` l.49). Tant que D1 n'est pas tranché : **aucun changement de libellé**.
5. **Aucune présentation « filtered »** : D5-B ne persiste que la preuve de fermeture ; rien ne soutient un affichage « filtered » (pas de support persisté).

---

## 7. Critères d'acceptation et tests de non-régression

### 7.1 Critères (implémentation future)

> **DOCUMENT HISTORIQUE — NON NORMATIF.** Les numéros CA ci-dessous sont anciens : utiliser `SENTINEL-TCP-STATES.md` §9.

- **CA-1** : `filtered` ×2 sur un port `open` → aucun événement ; `closed_streak` ne progresse pas.
- **CA-2** : `closed`, `filtered`, `closed` → aucun événement au 3e cycle ; un 4e `closed` → `port_not_open`.
- **CA-3** : `open|filtered`, `unfiltered`, absent, invalide, `bogus` → aucun événement de fermeture (×2 et plus).
- **CA-4** : `None` interrompt la succession (None, closed, closed → événement au cycle 3).
- **CA-5** : hôte entièrement `filtered` sur dix cycles → aucun événement, aucun compteur positif (**S11 doit passer**).
- **CA-6** : redémarrage après un `closed` → aucun compteur restauré ; événement après deux nouveaux `closed` (S2, S3).
- **CA-7** : un `new_port` après fermeture (second épisode) reste émis une fois ; pas de réémission de `port_not_open` pour le même épisode (S1, S10).
- **CA-8** : un `open` listé dans `<port>` reste reconnu ; un groupe `<extraports state="open">` ne crée jamais `open`.
- **CA-9** : `[]` d'un scan complet sans `open` n'est jamais interprété comme fermeture.
- **CA-10** : aucun changement de signature publique pour les appelants qui n'utilisent que les ports ouverts (`parse_sentinel_open_ports` conservé).
- **CA-11** : libellé persisté et libellé affiché inchangés (D1 ouvert).
- **CA-12** (nouveau) : P1, P3, P4, P11, P12 produisent `UNCERTAIN` ou INCOMPLETE, jamais une fermeture.
- **CA-13** (nouveau) : S7 et S8 ne produisent aucun événement sur la chaîne de production.
- **CA-14** (nouveau) : L1 (80 `filtered` à l'apprentissage puis `open`) donne `new_port` tant que D6 n'est pas tranché ; L2 inchangé (C1).
- **CA-15** (nouveau, sous réserve V4) : absence d'hôte au cycle intermédiaire → interruption de la succession (S5 au cycle 4).

### 7.2 Tests de non-régression

| Test | Fichier | Couvre | Action |
|---|---|---|---|
| Parsing : `filtered`, `open\|filtered`, `unfiltered`, sans état, `bogus` | `tests/test_tcp_scan.py` (ajout) | R3-R5, CA-3, CA-8 | ajout |
| Attribution `<extraports>` (`ports=` présent / absent / contradictoire / multi-groupes) | `tests/test_tcp_scan.py` (ajout) | §4.1, CA-12 | ajout |
| Fixture `filtered` unique (annotée « sortie réelle nmap 7.95 » : non prouvée, V6) | `tests/test_tcp_scan.py` l.291-315 | non-régression | inchangé |
| `filtered` → `[]` (retour de `_parse`) | `tests/test_tcp_scan.py` l.442-455 | CA-9 | inchangé |
| Sortie annotée « Real nmap 7.95 » (V6 : non prouvée comme sortie réelle) | `tests/test_tcp_scan.py` l.897-909 (`test_real_nmap_*`) | CA-10 | inchangé |
| Séquences §3 (table complète) | `tests/test_sentinel_manager.py` (ajout) | CA-1 à CA-7 | ajout |
| Hôte entier `filtered` ×10 (S11) | `tests/test_sentinel_manager.py` (ajout) | CA-5, CA-13 | ajout |
| Redémarrage avec compteur (S2, S3) | `tests/test_sentinel_manager.py` (ajout) | CA-6 | ajout |
| `port_absent_count` (sémantique change) | `tests/test_sentinel_manager.py` l.427-440, l.593-597 | — | **réviser**, ne pas affaiblir |
| Arrêt pendant scan | `tests/test_sentinel_stop_during_scan.py` l.196-199 | — | vérifier |
| Libellé « Port N closed » | `tests/test_sentinel_event_display.py` l.76-82 | CA-11 | inchangé (D1 ouvert) |

Exécution : HOME et base temporaires, fixtures XML, comme les reproductions A1. Aucun scan réel.

---

## 8. Tableau des transitions avant / après

« Avant » = production `9034f01`, mesurée par `a1_transitions.py` (rc 0) et `a1_chain_verify.py` (chaîne, partie B). « Après » = spécification (`a1_model_spec.py`, à confirmer par tests après implémentation).

| # | Séquence (cycles) | Avant | Après | Changement |
|---|---|---|---|---|
| 1 | closed ×2 | `port_not_open` c2 | `port_not_open` c2 | identique |
| 2 | filtered ×2 | `port_not_open` c2 (S7) | aucun | **supprimé** (A1-1) |
| 3 | open\|filtered ×2 | `port_not_open` c2 (S8) | aucun | **supprimé** (A1-3) |
| 4 | None ; None ×2 | aucun | aucun | identique |
| 5 | None, closed, closed | `port_not_open` c3 | `port_not_open` c3 | identique |
| 6 | filtered, open | aucun | aucun | identique |
| 7 | closed, open | aucun (1→0) | aucun (1→0) | identique |
| 8 | closed, filtered | `port_not_open` c2 | aucun | **supprimé** |
| 9 | closed ×2, open, filtered ×2 | `port_not_open` c2, `new_port` c3, `port_not_open` c5 | `port_not_open` c2, `new_port` c3 | **c5 supprimé** |
| 10 | hôte entier filtré ×2 | 22 et 80 c2 (S11) | aucun | **supprimé** (A1-2) |
| 10b | hôte entier filtré ×10 | 22 et 80 c2, puis rien (S11, mesuré) | aucun | **supprimé** (A1-2) |
| 11 | hôte entier closed ×2 | 22 et 80 c2 | 22 et 80 c2 | identique, **[APPROUVÉ] G-a ; G-b écartée** |
| 12 | 80 sans `<state>` ×2 | `port_not_open` c2 | aucun | **supprimé** |
| 13 | open stable ×2 | aucun | aucun | identique |
| 14 | open → unfiltered ×2 | `port_not_open` c2 | aucun | **supprimé** |
| 15 | open → bogus ×2 | `port_not_open` c2 | aucun | **supprimé** |
| 16 | closed, filtered, closed, closed | n/m | `port_not_open` c4 | nouveau test |
| 17 | 80 attribué closed ×2 | n/m | `port_not_open` c2 | nouveau test |
| 18 | 80 attribué filtered ×2 | n/m | aucun | nouveau test |
| 19 | 80 groupes non attribués ×2 | n/m | aucun | nouveau test (P4) |
| 20 | 80 groupe `open` ×2 | n/m | aucun | nouveau test |
| 21 | 22 bogus, 80 closed ×2 | n/m | `port_not_open` c2 (80) | nouveau test |
| 22 | closed, redémarrage, closed, closed | n/m | `port_not_open` c4 | nouveau test (retard, A1-6) |
| 23 | A absent c2 (closed c1, c3, c4) | `port_not_open` c3 (S5) | c4 | **[APPROUVÉ] V4** |

Bilan : **8 scénarios** (2, 3, 8, 9, 10, 12, 14, 15) et **9 événements** `port_not_open` faux supprimés (le scénario 9 en compte un au c5, le scénario 10 en compte deux, 22 et 80). Les cas `closed` purs (1, 5b, 11, 13) restent identiques.

---

## 9. Fichiers, fonctions, risques, dépendances

### 9.1 Fichiers et fonctions

| Fichier | Fonctions / lignes (réf. `9034f01`) | Nature |
|---|---|---|
| `detect/tcp_scan.py` | `_recorded_port_states` l.337 ; `_parse_tcp_xml_with_states` l.444 (états l.493) ; `parse_sentinel_open_ports` l.558 ; `_check_tcp_xml` l.354 (inchangé) | **modifié** |
| `sentinel/monitor.py` | `_get_open_ports` l.264 (appel l.276-282) | **modifié** (transmission de l'observation) |
| `sentinel/sentinel_manager.py` | `NetworkState.port_absent_count` l.291 ; `_rebuild_transition_state` l.300-362 ; `_compute_port_transitions` l.460-505 ; `ScanFailedError` l.629-634 | **modifié** (cœur) |
| `sentinel/baseline.py` | `learn_baseline` l.431 ; `parse_sentinel_open_ports` appelé l.481-484 | **dépendance** (voir §9.3) |
| `sentinel/monitor_view.py` | `presentation_detail` l.52-61 | inchangé (effet indirect) |
| `sentinel/alerting.py` | `NO_FINDING_TYPES` l.67 (contient `port_not_open`) ; `process_changes` l.149 ; `evidence` non persistée | inchangé (D5 le concerne) |
| `reports/sentinel_report.py` | l.27-35 | inchangé (D1) |
| `core/database.py` | `events` l.263 ; `sentinel_replace_baseline` l.1503-1543 (`services` écrit `"{}"`) | inchangé sans D5/D6 |
| `sentinel/whitelist.py` | `is_whitelisted` l.224-262 (aucune exception `port_not_open`) | inchangé |

### 9.2 Risques de régression

1. **Perte de détection « service passé derrière un pare-feu »** : `closed` → `filtered` ne produit plus d'événement. C'est le compromis de R3. **Acceptation explicite requise** (propriétaire).
2. **Sémantique de `port_absent_count`** : les tests `test_sentinel_manager.py` l.427-440 et l.593-597 supposent « absent ⇒ +1 ». À réviser, non affaiblir.
3. **Parsing `<extraports>`** : la règle d'attribution par `ports=` repose sur une hypothèse non vérifiée sur sortie réelle. Si nmap omet `ports=`, le cas tombe en `UNCERTAIN` (conservateur) : moins d'alertes, pas de fausse alerte.
4. **Groupe `extraports state="open"`** : non vérifié sur sortie réelle. Traité en `UNCERTAIN`.
5. **Redémarrages répétés** : si l'intervalle entre redémarrages est inférieur à deux cycles, une fermeture n'est jamais confirmée (S3). Conséquence directe de R7, documentée (non soumise à arbitrage).
6. **Quota** : une fermeture masquée n'est jamais réaffichée (`notifications.py` l.128-131). Un `new_port` réel sur le même hôte peut être masqué (S9 : B5 masqué).
7. **Baseline (D6)** : tant que D6 n'est pas tranché, l'apprentissage continue d'accepter les ports `filtered` absents de la baseline (L1 : `new_port` plus tard).

### 9.3 Dépendances

- **A1 ne dépend ni de D5 ni de D6**, sous réserve du point suivant.
- **Dépendance partagée** (validation commune [APPROUVÉ]) : `parse_sentinel_open_ports` est utilisé par l'apprentissage (`baseline.py` l.481-484). Une validation plus stricte (attribution `<extraports>`, §4.1) change **aussi** l'apprentissage : un apprentissage qui réussit aujourd'hui peut échouer (scan INCOMPLETE → refus tout-ou-rien). **Décision propriétaire : même validation pour les deux.** Monitor seul avec un second chemin de parsing n'est pas retenu.
- **TICKET3** : base de la présentation (§6). **TICKET4** (numérotation d'hôtes) : ne touche pas ce chemin.
- **D1** : libellé et tests `test_sentinel_event_display.py`.

---

## 10. D5 — Persistance additive des états TCP observés et des preuves [APPROUVÉ : D5-B]

Objectif : conserver l'état observé par port et la preuve d'une fermeture, sans réécrire l'historique ni migrer destructivement.

| Option | Description | Avantages | Risques |
|---|---|---|---|
| **D5-A** | Table additive `sentinel_tcp_observations(network_id, ip, port, cycle_ts, state, scan_status, session_id)`, `CREATE TABLE IF NOT EXISTS` | Historique complet, requêtable ; prépare D6 et une alerte « filtré » future | Volume : ports × hôtes × cycles (1030 ports) ; politique de rétention à écrire avant |
| **D5-B** | Clé additionnelle dans `events.details` (JSON libre) : `proof = {observed, consecutive, scan, run}` | Aucune migration de schéma ; faible risque ; traçabilité des fermetures confirmées | Rien n'est persisté pour `filtered` (pas d'événement) ; `details` alimente le budget (compatibilité, voir ci-dessous) |
| **D5-C** | Ne rien persister de plus | Aucun changement | Pas de preuve auditable ; A1-8 (`evidence` non persistée) reste |

**Compatibilité D5-B** (vérifiée par lecture) : lecteurs de `details` : reprise au démarrage (`sentinel_manager.py` l.331-355 : `ip`, `port`, `initial_ports`, `initial_ports_known`), quota (`notifications.py` l.32, 54-60 : `ip`, `whitelisted`, `notification`), rapport (`reports/sentinel_report.py` l.27-35 : `ip`, `detail`, `whitelisted`). **Aucun ne rejette une clé inconnue.** À valider par test.

**Distinction ancien / nouveau événement** : par **absence** de la clé `proof`. Limite : une absence prouve « antérieur à la correction », pas l'état observé à l'époque. Les anciens `port_not_open` issus d'un `filtered` sont indiscernables de ceux issus d'un `closed` ; leur libellé doit rester neutre.

**Décision propriétaire : D5-B** (preuve minimale dans `events.details`, sans nouvelle table ni réécriture historique). D5-A et D5-C ne sont pas retenues. Ne jamais réécrire les lignes existantes de `events`.

---

## 11. D6 — Politique des ports filtrés à l'apprentissage initial de la baseline [PÉRIMÈTRE APPROUVÉ : ticket indépendant hors A1 ; politique OUVERTE]

### 11.1 Constats mesurés (chaîne de production, partie C)

| Cas | Résultat production | Référence |
|---|---|---|
| L1 : 80 `filtered` à l'apprentissage, puis `open` | `learn_baseline` True ; baseline `{192.0.2.10: [22]}` ; `new_port(80)` | `a1_chain_verify.log` |
| L2 : hôte entièrement `filtered` à l'apprentissage, puis 22 et 80 `open` | `learn_baseline` True ; baseline `{192.0.2.10: []}` ; `new_port` 22 et 80 | idem |
| Modèle `a1_model_spec.py` (cas b) | **refus** (« aucune observation open ni closed ») | **divergence** : la production accepte |

**Correction de la proposition** : la section D6 de `PROPOSITION-A1-formalisation-TCP.md` (modèle : « refusé ») ne correspond **pas** au code. La production accepte l'hôte entièrement filtré avec une baseline vide.

Autres constats :
- Un port `filtered` au moment de l'apprentissage est **absent** de la baseline (`parse_sentinel_open_ports` ne renvoie que les `open`). S'il s'ouvre plus tard, `new_port` HIGH (A1-7, confirmé L1).
- `baseline.services` est toujours écrit `"{}"` (`core/database.py` l.1543, seul écrivain actif). Aucun lecteur logique trouvé (grep, non exhaustif). Utiliser `services` pour D6-B = concevoir un contrat, pas une simple écriture.
- L'apprentissage est **tout-ou-rien** : un hôte sans TCP complet fait refuser tout le réseau (`learn_baseline` l.484-489, mesuré par lecture seulement).

### 11.2 Options

| Option | Description | Conséquence vérifiée | Verdict |
|---|---|---|---|
| **D6-A** statu quo | Seuls les `open` vont en baseline | L1, L2 : `new_port` pour chaque port ouvert ensuite, y compris un port simplement non observé | Comportement actuel, bruyant mais simple |
| **D6-B** drapeau « incertain » | Ports incertains stockés avec un drapeau | `services` inerte aujourd'hui, mais sans contrat ; migration à concevoir | Décision propriétaire, contrat à écrire |
| **D6-C** refus d'apprendre si aucun `open`/`closed` | Tel que formulé dans la proposition précédente : **refuse tout le réseau** si implémenté comme l'apprentissage actuel (tout-ou-rien) : un seul hôte toujours filtré bloquerait la surveillance de tous les hôtes | Coût élevé | **Recommandation précédente retirée** |
| **C1** (pour A1) | Statu quo + avertissement d'apprentissage (« hôte entièrement filtré : baseline vide ») | Aucun changement de comportement | **Recommandation pour A1** |
| **C2** exclusion par hôte | Hôte entièrement filtré exclu de la baseline et signalé ; son apparition ultérieure est un `new_host` (MEDIUM) et non `new_port` | Réduit le bruit ; change la sévérité | À arbitrer (ticket D6 séparé) |
| **C3** accepter avec drapeau (D6-B) | Ports incertains stockés, drapeau dans la preuve du `new_port` | Contexte visible | À arbitrer après contrat |

**Décision propriétaire : D6 est un ticket indépendant, hors A1.** Pour A1 : politique C1 (la politique des ports `filtered` à l'apprentissage ne change pas). La validation XML commune (§9.3) refuse seulement les XML ambigus ; elle ne modifie pas cette politique. Choix C2 ou C3 : à soumettre (Nova → propriétaire).

---

## 12. Points à soumettre au propriétaire (via Nova)

| # | Point | Type | Recommandation |
|---|---|---|---|
| 1 | D1 : distinction preuve / historique | [APPROUVÉ] | Appliquée |
| 1b | D1 : libellé exact (« Port N closed » ou conditionnel) | [OUVERT] | Non approuvé ; trancher avant toute modification de libellé (DEC-03) |
| 2 | D5 : D5-B | [APPROUVÉ] | D5-B |
| 3 | D6 : ticket indépendant hors A1 ; politique C2 ou C3 | périmètre [APPROUVÉ] ; politique [OUVERT] | Nova soumet C2/C3 au propriétaire |
| 4 | V4 : hôte absent du cycle | [APPROUVÉ] | Remise à zéro (fait) |
| 5 | Garde de masse : G-a approuvée ; G-b écartée ; G-c reportée | [APPROUVÉ] | Aucun seuil global |
| 6 | Aucune fermeture confirmée sur `closed` → `filtered` | [APPROUVÉ] | Conséquence à consigner (§13) |
| 7 | Validation XML commune monitor / apprentissage (§9.3) | [APPROUVÉ] | Même validation pour les deux |
| 8 | Redémarrages répétés sans fermeture confirmée (S3) | [APPROUVÉ] R7 ; réserve | Non restauré ; réserve à signaler |

---

## 13. Limites

- Aucun scan réel. Toutes les mesures sont faites sur fixtures XML synthétiques et sondes remplacées (ping, ARP, MAC, nmap).
- `a1_model_spec.py` est une **spécification exécutable**, pas le code de production. Écarts connus avec la production : S5, S7, S8, S11, L2 (§3, §5, §11). Le modèle n'est pas une preuve de conformité.
- Non vérifié : structure réelle Nmap des `extrareasons` hors fixtures ; `extraports state=open` (DTD : CDATA libre, sémantique non prouvée) ; comportement de `ScanDegradedError` en production au-delà des cas mesurés ; passage `closed` → `filtered` dans un cycle de vie réel ; absence de lecteur de `baseline.services` (grep non exhaustif) ; révision ARENA.md 12 ou 13 ; `tcp_scan.py` l.251 (définition de `_run_nmap_tcp_strict` confirmée, comportement non testé).
- Hypothèse de cycle : le harnais ne lance pas le monitor en continu ; un cycle = un appel de `_do_check`.

---

## 14. Intégrité

Empreintes SHA-256 et état Git : voir `SHA256SUMS-A1-verification.txt` et `RAPPORT-verification-A1-chaine-production.md` §11.
