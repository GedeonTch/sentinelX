# Proposition A1 — formalisation de la politique TCP (états `open` / `closed` / `filtered` / incertains)

**Statut** : proposition de spécification, lecture seule. **Réconciliée le 2026-11-12** avec les décisions du propriétaire (§0). Remplacée comme spécification de référence par `SPEC-A1-consolidee.md` (réconciliée) et `docs-proposees/SENTINEL-TCP-STATES.md`. **Aucune implémentation.** Aucun code, test, Skill, document maître, base ni `~/.netlab` modifié. Aucun scan réseau réel.
**Référence de code** : `origin/a4-arena` = `9034f01` (clone de lecture `/tmp/audit-global-ref`, HEAD `9034f01`, status vide ; `/tmp/audit-spec-ref` absent).
**Rapport d'audit associé** : `RAPPORT-complement-A1-transitions-ports.md` (constats A1-1 à A1-8). Le présent document ne le remplace pas.
**Mise à jour de vérification finale** : voir `RAPPORT-verification-A1-chaine-production.md` (harnais de chaîne, parties B et C) et `SPEC-A1-consolidee.md`. Corrections appliquées : D6 (§11, modèle ≠ production), remise à zéro `ScanFailedError` (l.629-636), comptage §5, DTD lu (§1.2, §13).
**Preuves** : `preuves/a1/a1_model_spec.py` (modèle de spécification), `.json`, `.log` (rc 0). Empreintes dans `SHA256SUMS-A1-formalisation.txt`.

Légende : **[APPROUVÉ]** = règle acquise par décision du propriétaire. **[PROPOSITION]** = recommandation non tranchée. **[OUVERT]** = décision non prise, bloquante ou non. **[ÉCARTÉ]** / **[REPORTÉ]** = options fermées par décision (voir §0).

---

## 0. Séparation approuvé / ouvert

| Élément | Statut |
|---|---|
| `open` = port ouvert | [APPROUVÉ] |
| `closed` confirmé seulement après 2 observations TCP complètes **et consécutives** indiquant explicitement `closed` | [APPROUVÉ] |
| `filtered` = incertain : aucune fermeture déclarée, compteur de fermeture non incrémenté, interrompt une succession de 2 `closed` | [APPROUVÉ] |
| `open\|filtered` : aucune conclusion de fermeture | [APPROUVÉ] |
| États inconnus ou invalides : aucune conclusion de fermeture | [APPROUVÉ] |
| Hôte entièrement filtré : aucune fermeture de masse | [APPROUVÉ] |
| Compteurs intermédiaires d'absence non restaurés après redémarrage | [APPROUVÉ] |
| D1 : distinction entre nouveaux événements avec preuve et événements historiques sans preuve | [APPROUVÉ] |
| Libellé D1 (« Port N closed » ou conditionnel) | **[OUVERT]** — non approuvé, non tranché (DEC-03) |
| D5-B : preuve minimale dans `events.details`, sans nouvelle table ni réécriture historique | [APPROUVÉ] |
| D5-A (table additive) et D5-C | non retenues |
| D6 : ticket indépendant, hors A1 | [APPROUVÉ] (périmètre) |
| D6 : politique des ports filtrés à l'apprentissage (C2 ou C3) | **[OUVERT]** — à soumettre (Nova) |
| Garde « tous les ports connus fermés sur un hôte » : fermetures individuelles autorisées après deux `closed` explicites pour tous les ports connus (G-a) | [APPROUVÉ] |
| Aucun seuil global arbitraire (G-b) | [ÉCARTÉ] |
| Agrégation visuelle d'un hôte entièrement `closed` (G-c) | [REPORTÉ], hors A1 |
| Aucune fermeture confirmée sur `closed` → `filtered` | [APPROUVÉ] |
| Validation XML commune monitor / baseline | [APPROUVÉ] |
| Hôte absent du cycle : remise à zéro du compteur (V4) | [APPROUVÉ] — comportement actuel mesuré (S5) : compteur conservé (écart à corriger) |
| Compteurs intermédiaires non restaurés après redémarrage (R7) | [APPROUVÉ] (réserve S3 à consigner) |

Nova soumettra à présent les seuls points restants : libellé D1 et politique D6 (C2 ou C3). Ce document ne décide rien de ce qui est approuvé ci-dessus.

---

## 1. Spécification technique des règles approuvées

### 1.1 Entrée : observation par cycle

Une observation de cycle pour un hôte est soit :
- **`Scan(status=INCOMPLETE)`** : le scan n'est pas prouvé complet (timeout, hôte down, `exit` ≠ success, table partielle, XML vide ou invalide, port dupliqué, plusieurs hôtes, `services` différent du périmètre, nombre de ports non cohérent). Ce cas correspond à `None` dans le code actuel.
- **`Scan(status=COMPLETE, states)`** : `states` associe à **chaque port du périmètre** (`SENTINEL_TCP_PORTS`, 1030 ports) un état parmi `open`, `closed`, `filtered`, `uncertain`.

`uncertain` regroupe : `open|filtered`, `unfiltered`, état absent, état invalide, attribution contradictoire.

### 1.2 Attribution d'état par port

| Source XML (scan complet) | État attribué |
|---|---|
| `<port>` avec `<state state="open\|closed\|filtered">` | l'état listé |
| `<port>` avec un autre état ou sans `<state>` | `uncertain` |
| port non listé dans `<port>`, couvert par `<extraports state=S>` dont `<extrareasons ports="…">` attribue ce port | `S` si `S ∈ {closed, filtered}` ; `uncertain` si `S` vaut autre chose (y compris `open`) |
| port non listé, groupe `<extraports>` sans attribution `ports=` | si un seul groupe non attribué couvre tous les ports non listés : son état ; sinon `uncertain` |
| port listé dans deux attributions | `INCOMPLETE` (attribution contradictoire) |

Règle structurelle : un groupe `<extraports>` n'établit **jamais** `open`. Un port `open` doit être listé explicitement dans `<port>`.

**Constat de vérification** : `ports="…"` dans `<extrareasons>` apparaît dans la fixture annotée « Real nmap 7.95 » du groupe `closed` (étiquette de test : non prouvée comme sortie réelle, V6) (`tests/test_tcp_scan.py` l.236-262, `ports="2000-2100"`), et dans d'autres fixtures de test (l.154-156, 197-199, 212-214). En revanche, la fixture « Real nmap 7.95 » du port filtré unique (l.291-315) liste le port explicitement dans `<port>` et ne comporte aucun `<extraports>`. Nmap n'est pas installé dans l'environnement d'audit. Le DTD officiel a été lu (https://nmap.org/book/nmap-dtd.html) : il valide le schéma seulement, pas le contenu réel des sorties. Les attributions par `ports=` pour des groupes `filtered` ou multiples ne sont donc pas vérifiées sur sortie réelle.

### 1.3 Compteurs par port (pour chaque port `P` connu ouvert)

Un seul compteur par port : `closed_streak[P]` = nombre d'observations `closed` complètes consécutives.

| Observation pour P | Effet sur `closed_streak[P]` | Événement |
|---|---|---|
| `closed` | +1 ; si la valeur atteint 2 : retrait de `known_open`, remise à 0 | `port_not_open(P)` (une fois par épisode) |
| `open` | remise à 0 | — (si P n'est pas dans `known_open` : `new_port(P)`) |
| `filtered` | remise à 0 (**interrompt la succession**) | aucun |
| `uncertain` | remise à 0 | aucun |
| Scan `INCOMPLETE` (`None`) | remise à 0 pour tous les ports | aucun |
| Hôte absent du cycle (aucune observation TCP) | **[APPROUVÉ] V4** : remise à 0 ; actuellement conservé (mesuré S5) | aucun |

Le compteur n'est jamais incrémenté par `filtered` ni `uncertain`.

### 1.4 Hôte entièrement filtré

Si, sur un scan complet, aucun port du périmètre n'est `open` ni `closed` (toutes les observations sont `filtered` ou `uncertain`), alors :
- aucun compteur de fermeture n'est incrémenté pour aucun port ;
- aucun `port_not_open` n'est émis ;
- le cycle est traité comme une observation sans preuve de fermeture.

Ce cas est couvert par la règle `filtered` ; la garde explicite sert de filet de sécurité contre une régression future.

### 1.5 Compteurs après redémarrage

Les compteurs `closed_streak` ne sont pas restaurés depuis la base. Les ensembles `known_open` et `notified` (ports déjà notifiés) sont restaurés comme aujourd'hui. Conséquence (constat A1-6) : un port fermé avant redémarrage ne déclenche qu'après deux nouvelles observations `closed` ; il y a retard d'un cycle et **pas** de fausse alerte.

---

## 2. Représentation des états incertains

Trois cas doivent rester distincts dans le code :

| Représentation | Sens | Peut conclure « fermé » ? |
|---|---|---|
| `None` (scan `INCOMPLETE`) | scan non prouvé complet | non |
| `[]` (scan `COMPLETE`, aucun port `open`) | aucun port ouvert observé ; **ne signifie pas** fermé | non |
| Observation par port `uncertain` / `filtered` | état explicitement non concluant | non |

Changement proposé : la fonction de parsing ne renvoie plus seulement `List[int]` (ports ouverts) mais un objet d'observation contenant `status` et `states: Dict[int, PortState]`. Les ports ouverts en sont dérivés (`[]` redevient la valeur dérivée « aucun open » quand le scan est complet). `PortState` = enum `{OPEN, CLOSED, FILTERED, UNCERTAIN}`.

Le `[]` seul ne doit plus être utilisé comme preuve de quoi que ce soit en dehors de « pas de `open` ».

---

## 3. Modifications minimales (parsing, observations, transitions)

Principe : changer le moins possible de signatures publiques. Un appelant qui ne veut que les ports ouverts conserve son comportement.

1. **Parsing** (`detect/tcp_scan.py`) : `_parse_tcp_xml_with_states` (l.444) construit déjà `states[port_num]` (l.493). Exposer un objet d'observation. Ajouter l'attribution des groupes `<extraports>` (absente aujourd'hui). `parse_sentinel_open_ports` (l.558) garde sa signature et renvoie `open` seulement ; une variante renvoie l'observation complète.
2. **Observations** (`sentinel/monitor.py` l.276-282 ; `sentinel/baseline.py` l.454-481) : le monitor utilise l'observation complète ; la baseline (D6) reste sur le comportement actuel tant que D6 n'est pas tranché.
3. **Transitions** (`sentinel/sentinel_manager.py`, `_compute_port_transitions` l.460-505) : remplacer la logique « absent de `known_open` ⇒ +1 » par la table §1.3. Remise à zéro sur échec : `sentinel_manager.py` l.632-633 vident `port_absent_count` pour `ScanFailedError` (« no exploitable observation »). **Non vérifié** : le chemin `ScanDegradedError` / observations partielles (l.636 et suivantes), qui peut transporter des ports `None` ; à relire avant implémentation. Le harnais A1 a observé la remise à zéro pour les cas `None` testés (`incomplet→closed` : compteur repart de zéro), mais il n'a pas tracé le chemin de code exact.
4. **État** (`NetworkState.port_absent_count`, l.291 ; `_rebuild_transition_state`, l.300-362) : renommer en `closed_streak` **ou** conserver le nom et documenter la nouvelle sémantique. Recommandation : conserver le nom pour limiter le diff, documenter. Ne pas restaurer le compteur au redémarrage.

Hors périmètre de cette proposition : `alerting.py`, `whitelist.py` (aucune exception `port_not_open` n'existe), rapports.

---

## 4. Comportement cible des compteurs : séquences

Résultats du modèle `preuves/a1/a1_model_spec.py` (rc 0, toutes les sorties attendues vérifiées). **Divergences modèle/production mesurées** : S5, S7, S8, S11 (partie B) et L2 (partie C), voir `RAPPORT-verification-A1-chaine-production.md`. Les fixtures sont synthétiques, en mémoire, sans réseau. Le port 80 est suivi ; 22 est `open` au départ.

| Séquence (cycles 1…n) | Événements après | Compteur 80 après chaque cycle |
|---|---|---|
| closed, closed | `port_not_open(80)` au cycle 2 | 1, 0 |
| filtered, filtered | aucun | 0, 0 |
| open\|filtered ×2 | aucun | 0, 0 |
| None, None | aucun | 0, 0 |
| None, closed, closed | `port_not_open(80)` au cycle 3 | 0, 1, 0 |
| filtered, open | aucun | 0, 0 |
| closed, open | aucun | 1 → 0 |
| closed, filtered | aucun | 1 → 0 |
| closed, filtered, closed, closed | `port_not_open(80)` au cycle 4 | 1, 0, 1, 0 |
| closed, closed, open, filtered, filtered (second épisode) | `port_not_open` c2, `new_port` c3, aucun ensuite | 1, 0, 0, 0, 0 |
| filtered ×10 (hôte entier filtré) | aucun | 0 |
| bogus, closed, closed (22 bogus, 80 closed) | `port_not_open(80)` au cycle 2 | 1, 0 |
| closed, RESTART, closed, closed | `port_not_open(80)` au cycle 4 (retard d'un cycle) | 1, 0, 1, 0 |
| 80 non listé, attribué à un groupe `closed` ×2 | `port_not_open(80)` au cycle 2 | 1, 0 |
| 80 non listé, attribué à un groupe `filtered` ×2 | aucun | 0, 0 |
| 80 non listé, groupes non attribués `closed` et `filtered` ×2 | aucun | 0, 0 |
| 80 non listé, groupe `open` (hypothèse) ×2 | aucun | 0, 0 |

Pas de réémission après événement : après `port_not_open`, le port quitte `known_open` ; une réouverture produit `new_port`.

---

## 5. Tableau des transitions avant / après

« Avant » = comportement mesuré du dépôt `9034f01` (`preuves/a1/a1_transitions.py`, rc 0). « Après » = modèle de spécification. Les scénarios 16 à 22 n'ont pas de mesure « avant » dans le harnais A1 ; ils sont marqués `n/m`.

| # | Séquence | Avant (dépôt) | Après (spécification) | Changement |
|---|---|---|---|---|
| 1 | closed ×2 | `port_not_open` c2 | `port_not_open` c2 | identique |
| 2 | filtered ×2 | `port_not_open` c2 | aucun | **supprimé** (corrige A1-1) |
| 3 | open\|filtered ×2 | `port_not_open` c2 | aucun | **supprimé** (corrige A1-3) |
| 4a | None | aucun | aucun | identique |
| 4b | None ×2 | aucun | aucun | identique |
| 5a | None, closed | aucun c2 | aucun c2 | identique |
| 5b | None, closed, closed | `port_not_open` c3 | `port_not_open` c3 | identique |
| 6 | filtered, open | aucun | aucun | identique |
| 7 | closed, open | aucun (1→0) | aucun (1→0) | identique |
| 8 | closed, filtered | `port_not_open` c2 | aucun | **supprimé** (filtered interrompt, n'incrémente pas) |
| 9 | second épisode (closed ×2, open, filtered ×2) | `port_not_open` c2, `new_port` c3, `port_not_open` c5 | `port_not_open` c2, `new_port` c3 | **c5 supprimé** |
| 10 | hôte entier filtré ×2 | `port_not_open` 22 et 80 c2 | aucun | **supprimé** (corrige A1-2) |
| 10b | hôte entier filtré ×10 | 22 et 80 c2, puis rien (S11, mesuré en chaîne) | aucun | nouveau test ; **supprimé** (A1-2) |
| 11 | hôte entier closed ×2 | `port_not_open` 22 et 80 c2 | `port_not_open` 22 et 80 c2 | identique, **voir §6** |
| 12 | 80 sans `<state>` ×2 | `port_not_open` c2 | aucun | **supprimé** (corrige A1-3) |
| 13 | open stable ×2 | aucun | aucun | identique |
| 14 | open → unfiltered ×2 | `port_not_open` c2 | aucun | **supprimé** (corrige A1-3) |
| 15 | open → bogus ×2 | `port_not_open` c2 | aucun | **supprimé** (corrige A1-3) |
| 16 | closed, filtered, closed, closed | n/m | `port_not_open` c4 | nouveau test |
| 17 | 80 attribué closed ×2 | n/m | `port_not_open` c2 | nouveau test |
| 18 | 80 attribué filtered ×2 | n/m | aucun | nouveau test |
| 19 | 80 groupes non attribués ×2 | n/m | aucun | nouveau test |
| 20 | 80 groupe open (hypothèse) ×2 | n/m | aucun | nouveau test |
| 21 | 22 bogus, 80 closed ×2 | n/m | `port_not_open` c2 (80) | nouveau test |
| 22 | closed, redémarrage, closed, closed | n/m | `port_not_open` c4 | nouveau test (retard d'un cycle, A1-6) |

Résumé (modèle de spécification, pas la chaîne de production) : 8 scénarios de fausse fermeture (2, 3, 8, 9, 10, 12, 14, 15) disparaissent, soit 9 événements `port_not_open` faux (scénario 9 : 1 au c5 ; scénario 10 : 22 et 80). Les cas `closed` purs restent identiques (1, 5b, 11, 13).

---

## 6. Prévention des fermetures massives

**Approuvé** : hôte entièrement filtré → aucune fermeture de masse. Mécanisme : §1.3 (filtered n'incrémente pas) + §1.4 (garde explicite). Le quota par hôte (A3 : `LIMIT = 3`) n'est pas la protection ; ne pas s'appuyer dessus. **Constat de vérification** : sur le chemin de production, un hôte entièrement `filtered` (baseline 22 et 80) produit `port_not_open` 22 et 80 au cycle 2 (S11, `preuves/a1/a1_chain_verify.log`) : A1-2 confirmé en chaîne, violation de cette règle approuvée à corriger.

**[APPROUVÉ]** : hôte où tous les ports connus sont `closed` complets deux fois de suite (cas 11) : fermetures individuelles, sans seuil global (G-a). Le modèle émet alors une fermeture par port (ici 22 et 80). La règle approuvée ne couvre que `filtered` ; ce cas est conforme à la lettre de la règle `closed` mais peut correspondre à un hôte réinitialisé ou à un pare-feu qui répond RST. Décision demandée : garde de masse (ex. ne pas conclure à plus de N fermetures par cycle) ou acceptation explicite. **Non implémenté.**

---

## 7. Présentation

Les modifications de présentation après le ticket 3 (`TICKET3-EVENT-PRESENTATION-v2.diff`) sont :

1. **Effet direct** : `presentation_detail` (`sentinel/monitor_view.py` l.52-61) n'affichera plus « Port N closed » pour un `filtered`, puisque l'événement n'est plus émis. Le défaut de présentation A1-1 disparaît par construction.
2. **Libellés** : le libellé terminal « closed », le libellé persisté `port N not open` et le rapport HTML (`reports/sentinel_report.py` l.27-35, `port N not open` brut) restent en l'état. Harmoniser est la question D1, **[OUVERT]**. Ne pas changer le libellé persisté sans décision : `_PORT_NOT_OPEN_DETAIL` (l.49) et les tests `test_sentinel_event_display.py` l.76-82 en dépendent.
3. **Aucune nouvelle présentation « filtered »** n'est proposée : un état filtré n'a pas de support persisté pour l'afficher (D5-B ne persiste que la preuve de fermeture).

---

## 8. Critères d'acceptation

Une implémentation future sera acceptée si :

- **CA-1** : `filtered` ×2 sur un port `open` → aucun événement ; `closed_streak` ne progresse pas.
- **CA-2** : `closed`, `filtered`, `closed` → aucun événement au 3e cycle ; un 4e `closed` → `port_not_open`.
- **CA-3** : `open|filtered`, `unfiltered`, état absent, état invalide, `bogus` → aucun événement de fermeture (×2 et plus).
- **CA-4** : `None` interrompt la succession (séquence None, closed, closed → événement au cycle 3 seulement).
- **CA-5** : hôte entièrement `filtered` sur dix cycles → aucun événement, aucun compteur positif.
- **CA-6** : redémarrage après un `closed` → aucun compteur restauré ; événement seulement après deux nouveaux `closed`.
- **CA-7** : un `new_port` après fermeture (second épisode) reste émis une fois ; pas de réémission de `port_not_open` pour le même épisode.
- **CA-8** : un port `open` listé dans `<port>` reste reconnu ; un groupe `<extraports state="open">` ne crée jamais `open`.
- **CA-9** : la sortie `[]` d'un scan complet sans `open` n'est jamais interprétée comme fermeture.
- **CA-10** : aucun changement de signature publique pour les appelants qui n'utilisent que les ports ouverts.
- **CA-11** : le libellé persisté et le libellé affiché des événements existants ne changent pas (libellé D1 non tranché).

### Tests de non-régression proposés (non écrits)

| Test | Fichier cible | Couvre |
|---|---|---|
| Parsing : `filtered`, `open\|filtered`, `unfiltered`, sans état, `bogus` | `tests/test_tcp_scan.py` (ajout) | §1.2, CA-3, CA-8 |
| Attribution `extraports` (`ports=` présent / absent / contradictoire) | `tests/test_tcp_scan.py` (ajout) | §1.2, CA-8, CA-9 |
| Séquences §4 (table complète) | `tests/test_sentinel_manager.py` (ajout) | CA-1 à CA-7 |
| Hôte entier filtré ×10 | `tests/test_sentinel_manager.py` (ajout) | CA-5 |
| Redémarrage avec compteur | `tests/test_sentinel_manager.py` (ajout) | CA-6 |
| Existants : `test_tcp_scan.py` l.442-455 (`filtered` → `[]`) et l.897-909 (`test_real_nmap_*`, fixtures annotées) | inchangés | non-régression du retour `[]` |
| Existants : `test_sentinel_manager.py` l.427-440, l.593-597 (`port_absent_count`) | à réviser (sémantique change) | — |
| Existant : `test_sentinel_stop_during_scan.py` l.198 | à vérifier | — |
| Existant : `test_sentinel_event_display.py` l.76-82 | inchangé (libellé D1 non tranché) | CA-11 |

Hypothèse de tests : les tests de séquences doivent être exécutés dans un HOME et une base temporaires, sur fixtures XML, comme les reproductions A1 (`ci-audit-20261110/iso-pytest.sh`).

---

## 9. Fichiers et fonctions concernés, risques, dépendances

| Fichier | Fonctions / lignes (réf. `9034f01`) | Nature |
|---|---|---|
| `detect/tcp_scan.py` | `_check_tcp_xml` l.354 (complétude : **pas de changement attendu**), `_parse_tcp_xml_with_states` l.444 (états, l.493), `parse_sentinel_open_ports` l.558 | modifié |
| `sentinel/monitor.py` | l.276-282 (appel), | appelant, adaptation |
| `sentinel/baseline.py` | l.454-481 | appelant, **non modifié** tant que D6 ouvert |
| `sentinel/sentinel_manager.py` | `NetworkState.port_absent_count` l.291, `_rebuild_transition_state` l.300-362, `_compute_port_transitions` l.460-505, remise à zéro `ScanFailedError` l.629-636 (vidage l.633 ; chemin `ScanDegradedError` partiel mesuré, voir RAPPORT-verification §1) | modifié (cœur) |
| `sentinel/monitor_view.py` | `presentation_detail` l.52-61 | effet indirect |
| `sentinel/alerting.py` | `NO_FINDING_TYPES` l.67 ; `evidence` non persistée l.173 | inchangé (D5 le concerne) |
| `reports/sentinel_report.py` | l.27-35 | inchangé (D1) |
| `core/database.py` | `events` l.263 ; précédent de migration additive `sentinel_control` l.1859-1863 | inchangé sans D5 |
| `sentinel/whitelist.py` | `is_whitelisted` l.224-262 : traite `new_port`, `new_host`, `mac_change` ; **aucune exception pour `port_not_open`** | inchangé |

**Dépendances** : D5 et D6 dépendent de la décision sur les états stockés. A1 ne dépend ni de D5 ni de D6. Le ticket 4 (numérotation d'hôtes, `TICKET4-HOST-NUMBERING-v2.diff`) ne touche pas ce chemin.

**Risques de régression** :

1. **Perte de détection « service passé derrière un pare-feu »** : un port qui passe de `closed` à `filtered` ne produira plus d'événement. C'est le compromis de la règle approuvée. Il doit être accepté explicitement. Atténuation possible via D5 (événement d'information, non approuvé).
2. **Sémantique de `port_absent_count`** : les tests existants qui supposent « absent ⇒ +1 » vont changer (`test_sentinel_manager.py` l.427-440, l.593-597). Il faut les réviser, pas les affaiblir.
3. **Parsing des groupes `<extraports>`** : l'attribution par `ports=` repose sur une hypothèse non vérifiée sur sortie réelle (§1.2). Si nmap omet `ports=` pour certains groupes, le cas tombe en `uncertain` (conservateur) : moins d'alertes, pas de fausse alerte. À vérifier sur un scan réel autorisé avant mise en production.
4. **Hypothèse `extraports state=open`** : nmap ne devrait pas produire ce groupe, non vérifié. Traité en `uncertain`.
5. **Baseline (D6)** : tant que D6 n'est pas tranché, la baseline continue d'apprendre sous filtrage (constat A1-7).

---

## 10. D5 — Persistance additive des états TCP observés et des preuves ([APPROUVÉ] : D5-B)

Objectif : conserver l'état observé par port et la preuve d'une fermeture, sans réécrire l'historique ni migrer destructivement.

| Option | Description | Avantages | Risques |
|---|---|---|---|
| **D5-A** | Nouvelle table additive `sentinel_tcp_observations(network_id, ip, port, cycle_ts, state, scan_status, session_id)`, créée par `CREATE TABLE IF NOT EXISTS` | Historique complet, requêtable, prépare D6 et une alerte « filtré » future | Volume : 1030 ports × hôtes × cycles ; nécessite une politique de rétention (non tranchée) ; migration additive uniquement |
| **D5-B** | Ajouter la preuve dans `events.details` (JSON libre, clé additionnelle `proof = {observed, consecutive, scan, run}`, alignée sur `SPEC-A1-consolidee.md` §10) | Aucune migration de schéma ; contenu déjà persisté ; faible risque | Rien n'est persisté pour les états `filtered` (pas d'événement) ; `details` alimente le budget d'événements |
| **D5-C** | Ne rien persister de plus | Aucun changement | Pas de preuve auditable ; A1-8 (`evidence` non persistée) reste |

**Précédent de migration** : `core/database.py` l.1859-1863 ajoute des colonnes à `sentinel_control` avec `ALTER TABLE … ADD COLUMN … DEFAULT 0`, de façon additive. D5-A suit le même principe.

**Décision propriétaire : D5-B** (faible risque, aucune migration, traçabilité des fermetures confirmées). D5-A n'est pas retenue. Ne jamais réécrire les lignes existantes de `events`.

---

## 11. D6 — Politique des ports filtrés à l'apprentissage initial de la baseline ([PÉRIMÈTRE APPROUVÉ : hors A1] ; politique [OUVERT])

Constat : aujourd'hui la baseline est apprise à partir de `parse_sentinel_open_ports` (`sentinel/baseline.py` l.481). Un port `filtered` au moment de l'apprentissage est donc **absent** de la baseline. S'il s'ouvre plus tard, il produit un `new_port` HIGH (constat A1-7).

Résultats du modèle (`a1_model_spec.json`, section D6) :

| Cas | Résultat du modèle |
|---|---|
| a. 22 open, 443 closed, 80 filtered | stocké ; `open=[22]`, 80 incertain |
| b. hôte entièrement filtré | **refusé** par le modèle. **Divergence** : la production l'accepte avec baseline `[]` (L2, mesuré) |
| c. 22 open, reste closed (témoin) | stocké ; `open=[22]` |
| suite de a : 80 s'ouvre | `new_port(80)` avec `uncertain_at_learning = true` |

| Option | Description | Avantages | Risques |
|---|---|---|---|
| **D6-A** | Statu quo : seuls les ports `open` vont dans la baseline ; ports incertains absents | Aucun changement | `new_port` HIGH possible pour un port simplement non observé à l'apprentissage ; baseline peu fiable |
| **D6-B** | Enregistrer les ports incertains dans la baseline avec un drapeau (ex. dans `services`, JSON par port : `"state": "uncertain"`) | Un `new_port` ultérieur peut être contextualisé (« non observé fermé à l'apprentissage ») | Format de `services` à vérifier (consommateurs non audités) ; dépend partiellement de D5 pour l'historique |
| **D6-C** | Refuser d'apprendre la baseline si l'observation est insuffisante (ex. aucun `open` ni `closed`), réessayer au cycle suivant | Baseline fiable ; évite d'apprendre un hôte entièrement filtré | Risque d'hôte **jamais** appris si toujours filtré : il faut définir le comportement du monitor pour cet hôte (non défini) |

**Décision propriétaire** : D6 est un ticket indépendant hors A1. **Pour A1 : politique C1 = D6-A** (statu quo et avertissement). La validation XML commune refuse seulement les XML ambigus ; elle ne change pas la politique des ports filtrés. **D6-C est retiré** : appliqué comme l'apprentissage actuel (tout-ou-rien), il refuserait tout le réseau pour un seul hôte entièrement filtré. Choix ultérieur entre C2 et D6-B dans un ticket séparé. Décision de sévérité du `new_port` contextualisé : **propriétaire**.

**Conséquences sur `new_port` futurs** : sans D6, un port filtré à l'apprentissage et ouvert plus tard alerte comme une nouveauté, ce qui peut être correct (port réellement nouveau) ou bruyant (port déjà existant derrière un filtre). Avec D6-B, l'alerte reste émise mais porte le contexte.

**Fiabilité de la baseline** : D6-C améliore la fiabilité en refusant les apprentissages vides ; il ne corrige pas un apprentissage partiel (cas a), que D6-B rend visible.

---

## 12. Questions ouvertes (à soumettre au propriétaire via Nova)

1. **D1 : libellé exact** (« Port N closed » ou conditionnel). Non tranché (DEC-03). La distinction preuve / historique est approuvée.
2. **D6 : politique des ports filtrés à l'apprentissage** (D6-A, D6-B ou D6-C ; correspondance avec `SPEC-A1-consolidee.md` §11 : D6-A = C1 ; D6-B = C3 ; C2 = exclusion d'hôte, propre à la spec). Non tranché. Hors A1, à soumettre par Nova.

Points précédemment ouverts, désormais **approuvés** : D5 (D5-B) ; garde de masse (G-a, G-b écartée, G-c reportée) ; V4 (remise à zéro) ; perte de détection `closed` → `filtered` (acceptée) ; validation XML commune ; compteurs non restaurés (réserve à consigner).

---

## 13. Limites de cette proposition

- Aucun scan réel. Toutes les séquences sont des fixtures synthétiques ou des hypothèses de modèle.
- Le modèle (`a1_model_spec.py`) est une **spécification exécutable**, pas le code de production. Son `derive()` reprend la sémantique proposée et n'a pas été comparé octet à octet au parsing du dépôt.
- Les comportements « avant » proviennent du harnais A1 (`preuves/a1/a1_transitions.py`) et non d'un test du dépôt.
- Non vérifié : `extrareasons ports=` sur des groupes `filtered` ou multiples en sortie réelle (la seule preuve réelle est un groupe `closed`, l.236-262 de `test_tcp_scan.py`) ; groupe `extraports state=open` ; format et consommateurs de `services` ; comportement RST/filtré d'une cible autorisée ; chemin partiel `ScanDegradedError` de `sentinel_manager.py` (§3).
- Nmap n'est pas installé dans l'environnement. Le DTD officiel a été lu (schéma seulement).
- La clé `ports=` absente dans certaines fixtures de test n'a pas été analysée au-delà des cas listés.
