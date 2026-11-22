# SentinelX Future — Demo
## Dossier de conception maître

**Version** 1.0 · **Date** 12 novembre 2026 · **Statut** conception soumise à validation — **aucune implémentation commencée**
**Référence produit unique** : `a4-arena` @ `9034f01` (11/11/2026) — 16 177 lignes source, **2 083 tests verts**, **91 %** de couverture.
L'audit de `main` (604 tests, 80 %) reste historique et n'est **jamais** utilisé ici : aucun chiffre des deux branches n'est mélangé.
**Dépôt SentinelX** : intact. Aucun commit, aucun push, aucun fichier modifié (`git status` vide sur les deux clones).

---

# Sommaire

0. Comment lire ce dossier
1. Résumé exécutif et engagements non négociables
2. Les dix décisions du propriétaire, telles qu'appliquées
3. Vérifications factuelles et corrections
4. Constats produit retenus
5. Inventaire des écrans (inventaire, navigation, interactions)
6. Architecture, arborescence, garde-fous
7. Modèle de données
8. Moteur : horloge, monde, cycles, contrôles
9. Scénarios S1 à S8
10. Sentinel Monitor : comportements détaillés
11. Assistant déterministe
12. Direction visuelle et maquettes
13. Découpage en lots et plan de tests
14. Incertitudes et décisions demandées
15. Ce que cette démonstration ne prouve pas
16. Annexes : glossaire, table des sources, traçabilité des corrections

---

# 0. Comment lire ce dossier

Ce document est **autonome** : il contient l'intégralité du contenu normatif de la conception. Les fichiers séparés qui l'ont précédé (`00_INDEX_ET_DECISIONS.md` à `10_INCERTITUDES.md`) restent dans le dossier pour la traçabilité de la rédaction, mais **ne sont pas nécessaires à la compréhension** : tout ce qui engage la conception est ici.

Trois niveaux de lecture :

| Vous voulez… | Lisez |
|---|---|
| Décider si le projet part dans la bonne direction | **§1**, **§2**, **§14** (30 min) |
| Vérifier la fidélité au produit | **§3**, **§4**, **§7**, **§10** |
| Autoriser le démarrage | **§5**, **§13** (+ réponses §14) |

**Conventions**
- Les **termes officiels** du produit sont conservés en anglais et invariables : `Finding`, `Inventory Observation`, `Worst Current Threat`, `CONFIRMED`, `PROBABLE`, `POSSIBLE`, `OPEN`, `VERIFIED`, `REMEDIATED`, `ACCEPTED`, `PARTIAL`, `SUCCESS`, `FAILED`.
- Les références de code (`core/risk_scorer.py:101`) pointent vers `a4-arena` @ `9034f01`.
- Les énumérations sont citées **verbatim**, jamais reformulées.
- Une **affirmation produit est toujours accompagnée de sa preuve** (fichier, ligne, sortie de commande). Sans preuve, elle est marquée « non documenté ».

**Ce que ce dossier n'est pas** : un cahier des charges de développement. C'est une conception : elle décrit ce qui sera construit, pourquoi, et comment on saura que c'est correct. Le code viendra après validation, lot par lot.

---

# 1. Résumé exécutif et engagements non négociables

## 1.1 En dix lignes

SentinelX Future — Demo est une **application de cybersécurité autonome et hors ligne** qui rejoue le fonctionnement réel de SentinelX sur un **monde fictif**. Elle ne sonde rien : les hôtes, ports, services et communications sont des **données en base**. Le moteur applique **exactement** les règles du produit — barème de risque, Worst Current Threat, huit types d'événements Sentinel, quota de notifications de 3 par couple réseau/IP sur 60 minutes glissantes, budgets de credentials, statuts de Finding — et ajoute, clairement étiquetées comme absentes du produit, trois capacités de démonstration : un contrôle `VERIFY` à trois issues, une remédiation simulée, et un assistant contextuel déterministe. Aucun appel réseau, aucun sous-processus, aucun modèle de langage. Le prototype est **l'application elle-même** (navigation, fiches, tableaux, notifications, transitions), pas un tableau de bord décoratif. Chaque écran porte **deux étiquettes distinctes** : l'état réel dans le produit, et le niveau de réalisation dans le prototype. La démonstration ne vaut **jamais** preuve d'avancement sur la roadmap V2/V3.

## 1.2 Les cinq engagements non négociables

| # | Engagement | Comment il est tenu | Comment il est vérifié |
|---|---|---|---|
| **E1** | **Zéro réseau.** Aucune socket sortante, aucun sous-processus, aucune résolution DNS, aucun CDN. | Socket client neutralisée, `subprocess` bloqué, CSP `default-src 'self'`, aucun `http://` dans `web/` | `test_safety.py` + `tools/check_no_network.py` |
| **E2** | **Fidélité stricte au produit** (Q3). Les règles ne sont ni corrigées, ni « améliorées », ni contournables par un réglage. | Findings Sentinel non scorés, `port_not_open` sans effet sur le Worst Current Threat, quota non modifiable, page des règles en lecture seule | `test_scoring`, `test_verify`, `test_sentinel_events`, M-07 (refus explicite) |
| **E3** | **Aucune conclusion automatique.** Un changement n'est pas une correction ; un contrôle partiel ou échoué n'est jamais enregistré comme réussi ; `REMEDIATED` n'est jamais automatique. | Trois issues `VERIFY` obligatoires, transition `VERIFIED` conditionnée à `SUCCESS` + confirmation humaine, justification écrite exigée | `test_verify`, scénarios S4/S6/S7 |
| **E4** | **Étiquetage permanent** produit ≠ prototype. | Deux attributs distincts sur chaque surface, affichés sur deux lignes séparées ; matrice complète dans l'écran Périmètre | `test_api_contract::test_scope_labels_complete` |
| **E5** | **Aucun score global.** Pas de jauge, pas de moyenne, pas de « niveau de sécurité ». | Worst Current Threat = maximum filtré ; indicateurs affichés séparément, jamais agrégés | `test_api_contract::test_no_global_score` |

## 1.3 Ce qui distingue ce prototype d'une maquette

| Une maquette | Ce prototype |
|---|---|
| Montre des écrans | Applique des règles et produit des états conséquents |
| Données décoratives | Données qui se contredisent si le moteur est faux |
| Navigation cliquable | Navigation + transitions d'état + journal d'audit |
| « Ça a l'air fini » | « On peut vérifier que c'est cohérent » |

---

# 2. Les dix décisions du propriétaire, telles qu'appliquées

| # | Votre décision | Application concrète | Où c'est spécifié |
|---|---|---|---|
| **Q1** | **A** — Aperçu V2+V3, étiquetage strict | Deux attributs par surface : `état produit` ∈ {`EXISTE`, `ABSENT`, `HORS PÉRIMÈTRE V1`, `CONSTAT À EXAMINER`} et `réalisation prototype` ∈ {`RÉEL SIMULÉ`, `NON COUVERT`}. Jamais fusionnés. Une capacité du prototype ne valide aucune roadmap. | §5, §13 |
| **Q2** | **C** — Assistant hybride, déterministe par défaut | Une seule implémentation : `DeterministicExplainer`. Interface `Explainer` prête pour un adaptateur, **aucun adaptateur écrit**. LLM local documenté (§11.8), non intégré. | §11 |
| **Q3** | **A** — Fidélité stricte | Findings Sentinel : `risk_score = None`, exclus du Worst Current Threat. Explication absente : « non documentée dans la Knowledge Base ». **Aucune bascule cachée** ; page des règles en lecture seule ; trois refus explicites (M-07). | §7.5, §10.7, §10.9 |
| **Q4** | **A** — Un rôle, identifiants préremplis | Écran de connexion réel, compte fictif `analyst`, aucun mot de passe vérifié, session locale opaque, aucun secret stocké. | §5.2 (P-00) |
| **Q5** | **A** — Trafic : observation seule | Écran P-11 : communications fictives, 5-tuple, volumes, extraits bruts. **Aucune création de Finding, aucune contribution au score.** Rattachement manuel possible, marqué « lien déclaré par l'analyste ». `HORS PÉRIMÈTRE V1`. | §5.2 (P-11) |
| **Q6** | **B** — Python stdlib + SPA sans build | `http.server` lié **exclusivement à `127.0.0.1`**, sans option `--host`, sans exposition réseau. Aucun npm, aucun CDN, aucune police distante. | §6 |
| **Q7** | **A** — Nom « SentinelX Future — Demo » | Nom affiché en permanence ; les noms de composants officiels (`netlab`, `sentinel`, `Finding`…) restent utilisés **à l'intérieur**. | §12.3 |
| **Q8** | **Oui** — REMEDIATE simulé | Proposition → explication → diff avant/après → confirmation explicite → modification du **monde fictif** → contrôle obligatoire. Marqué `ABSENT (V2+)`. | §8.9, P-12 |
| **Q9** | **Oui** — trois issues VERIFY | `SUCCESS` : `VERIFIED` possible, sur confirmation. `PARTIAL` : statut inchangé. `FAILED` : statut inchangé. `REMEDIATED` jamais automatique. Les trois cas sont des **critères d'acceptation** (S5, S6, S7). | §8.8, §9 |
| **Q10** | **Français intégral, vocabulaire produit conservé** | Interface en français ; termes officiels en anglais ; inventaire d'écrans **par nature** (pages / fiches / panneaux / modales), le « 14 écrans » est **abandonné**. | §5 |

---

# 3. Vérifications factuelles et corrections

Trois affirmations de ma première rédaction étaient fausses. Elles sont corrigées ici, avec leur preuve. Ce tableau est la partie la plus importante du dossier pour juger du sérieux de la conception.

## 3.1 `Severity.CRITICAL` existe, et est produite par le produit

| Preuve | Contenu |
|---|---|
| `core/finding.py:34` | `CRITICAL = "critical"` dans `Severity` |
| `knowledge/cve_db.json` | 11 entrées : **7 `critical`**, 2 `high`, 2 `medium` |
| `detect/service_detection.py:12` | « Upgraded severity (INFO → LOW/MEDIUM/HIGH/CRITICAL) » |
| `cli.py:1932` | `Severity.CRITICAL: 0` — compteur d'affichage |

**Conclusion** : `CRITICAL` est une valeur officielle de première classe. La conception l'utilise sans restriction et n'invente aucune autre valeur.

## 3.2 Les Inventory Observations ne sont pas une entité

| Élément | Réalité |
|---|---|
| Nature | Ce sont des **`Finding`** de la table `findings` |
| Signature | `module = "device_fingerprint"`, `category = NETWORK`, `severity = INFO` (`recon/device_fingerprint.py:317`) |
| Séparation | **De présentation et de scoring seulement** : `risk_scorer.INVENTORY_MODULES = frozenset({"device_fingerprint"})` (`core/risk_scorer.py:101`) ; `cli._INVENTORY_MODULE` (`cli.py:1941`) |
| Conséquence | **Un seul type d'entité.** Le modèle conserve un `Finding` unique avec un champ **dérivé** `nature` ∈ {`security`, `inventory`}. Aucune page, aucune table, aucun objet « Observation ». |

C'est exactement votre mise en garde (§2.3) : ne pas confondre séparation de présentation et modèle officiel.

## 3.3 Le quota de notifications a **six** états, pas cinq

Vérifié dans `sentinel/notifications.py` et `sentinel/alerting.py` :

| État | Sens exact | Occupe une place ? |
|---|---|---|
| `preparing` | intention d'émettre, écrite **avant** l'affichage | **oui** (`reserved`) |
| `confirmed` | affichage réussi, `emitted_at` présent | **oui** (`displayed`) |
| `masked` | quota indisponible : décision **enregistrée**, aucune émission | **non** |
| `uncertain` | émission interrompue ou contrôle non concluant ; réserve jusqu'à `reserved_until` = now + 60 min | **oui** (`reserved`) |
| `whitelisted` | changement autorisé **ou** type silencieux : hors quota, jamais notifié | non |
| `unknown` | repli : métadonnées absentes/version inconnue | **oui** (`reserved`) |

`unknown` manquait à ma première liste. Et le comptage n'est **pas** « 3 émissions récentes » :

```
available = LIMIT − displayed − reserved          (LIMIT = 3, WINDOW = 60 min, par couple réseau+IP)
```

## 3.4 Une sévérité `CRITICAL` n'entre pas forcément dans le Worst Current Threat

`detect/service_detection.py` (`_apply_cve`) :

| Situation | Confiance | Effet |
|---|---|---|
| CVE exigeant une confirmation de version **et** aucune version détectée | forcée à `POSSIBLE` (0.60), **sévérité CVE conservée** | **exclu** du Worst Current Threat (0.60 < 0.70) |
| Version requise mais non confirmée (bannière ambiguë) | `POSSIBLE` | exclu |
| Version confirmée | `POSSIBLE → PROBABLE` si nécessaire | éligible |

Conséquence d'interface : un `CRITICAL` peut être absent du Worst Current Threat. L'écran doit afficher **la raison**, pas laisser croire à une anomalie.

## 3.5 Le produit contenait déjà la doctrine Q9, en français

`sentinel/monitor_view.py` — `CHECK_OUTCOMES` :

| Phase | Libellé du produit |
|---|---|
| `attente` | « Contrôle terminé » |
| `dégradé` | « **Contrôle partiel, non enregistré comme réussi** » |
| `erreur` | « **Contrôle en échec, non enregistré comme réussi** » |

La règle « un contrôle partiel ou échoué n'est pas enregistré comme réussi » existait donc dans le produit à l'état de libellé. Le `VERIFY` à trois issues ne l'invente pas : il la rend **visible et actionnable**. C'est un point à porter au crédit du produit.

## 3.6 Licence : point bloquant

| Fait | Preuve |
|---|---|
| `a4-arena` **n'a pas de `LICENSE`** | `git ls-files` ne le liste pas ; `git log --all -- LICENSE` ne renvoie qu'un commit sur `main` |
| `main` contient **GPL-3.0** | `git show origin/main:LICENSE` |
| Les fichiers de connaissance sont suivis, sans mention de licence | `git ls-files knowledge/` ; lecture directe (`_comment`, `_format`, `schema_version`) |

Une branche sans licence n'accorde par défaut **aucun droit de réutilisation** ; une attribution ne suffit pas. La conception retient donc **l'absence de copie** : identifiants, taxonomie et structures repris (faits) ; les 21 textes `what/attack/defense` **rédigés pour la démo** ; les 10 profils de credentials **entièrement fictifs** ; test anti-verbatim par empreintes. Décision à confirmer : §14 (Q-D1).

---

# 4. Constats produit retenus

L'audit a produit 14 constats ; six touchent directement la démonstration. La démo **ne corrige aucun comportement du produit pour faire joli** : elle l'affiche, l'explique, et le marque comme constat.

| Réf. | Constat | Ce que fait la démo |
|---|---|---|
| **C4** | Les Findings Sentinel (`sentinel.new_host`, `.new_port`, `.mac_change`) ont `risk_score = None` et ne sont **jamais** scorés ; aucun document ne l'explique | **Fidélité stricte** (Q3) : conserve le comportement, l'explique à l'écran, n'offre aucune bascule. Marqué `CONSTAT À EXAMINER` |
| **C5** | `new_host`, `new_port`, `mac_change` créent des Findings, mais `vulnerabilities.json` ne contient aucune de ces 3 règles → `explanation = None` ; contredit la règle « pas de Finding orphelin » | Affiche « non documentée dans la Knowledge Base », sans jamais inventer de texte |
| **C6** | Steering §K : `sentinel_max_alerts_per_hour: 3` (« beyond → silent mode ») ; le quota réel est **3 par couple réseau/IP / 60 min glissantes**, et le paramètre ne pilote plus rien | La démo applique **le code**, pas la documentation ; la page des règles affiche la valeur effective et signale l'écart documentaire |
| **C11** | `reports/generator.py:263` recalcule le pire score au lieu de réutiliser `risk_scorer` | Le prototype applique la règle correcte **et signale l'écart** sur la fiche rapport |
| **C12** | `sentinel/baseline.py` et `arp_probe.py` n'implémentent que Linux (`ip route`, `arp -n`) ; README annonce « cross-platform » | La démo n'a aucune dépendance de plateforme (elle lit une base) ; le constat reste affiché |
| **C10** | Licence absente sur `a4-arena` (GPLv3 sur `main` seulement) | Aucune copie de contenu ; voir §3.6 |

---

# 5. Inventaire des écrans

Le « découpage à 14 écrans » est **abandonné**. L'inventaire est établi **par nature** : **19 pages · 13 fiches détaillées · 7 panneaux latéraux · 9 modales**. Ajouter une surface est une décision de conception, pas un ajustement de compteur. Aucune fonctionnalité n'est supprimée pour tenir un nombre.

## 5.1 Deux attributs obligatoires par surface

**Attribut A — `état produit`** (ce qui existe réellement dans `a4-arena`) : `EXISTE` · `ABSENT` · `HORS PÉRIMÈTRE V1` · `CONSTAT À EXAMINER`.

**Attribut B — `réalisation prototype`** : `RÉEL SIMULÉ` (fonctionne sur le monde fictif, avec les règles officielles réellement implémentées) · `NON COUVERT`.

Trois règles :
1. `RÉEL SIMULÉ` ne signifie **jamais** « existe dans le produit ».
2. Une surface `ABSENT` + `RÉEL SIMULÉ` est une **proposition Future**, avec bandeau permanent (pas une infobulle).
3. Aucune surface ne peut porter `EXISTE` sans référence vérifiable (§5.8).

## 5.2 Les 19 pages

Une page occupe la zone principale, porte une entrée de menu et une route propre.

| ID | Page | Route | État produit | Prototype | Rôle |
|---|---|---|---|---|---|
| P-00 | Connexion | `#/login` | `ABSENT` | `RÉEL SIMULÉ` | Point d'entrée, compte fictif prérempli (Q4) |
| P-01 | Tableau de bord | `#/` | `ABSENT` (agrégat) | `RÉEL SIMULÉ` | Situation courante, sans score composite |
| P-02 | Sentinel — Vue d'ensemble | `#/sentinel` | `EXISTE` | `RÉEL SIMULÉ` | Worst Current Threat et son calcul |
| P-03 | Sentinel — Journal d'événements | `#/sentinel/events` | `EXISTE` | `RÉEL SIMULÉ` | Les 8 types, filtres, notifications |
| P-04 | Sentinel — Changements & contrôles | `#/sentinel/changes` | `EXISTE` / `ABSENT` (VERIFY) | `RÉEL SIMULÉ` | Diffs, contrôles, historique |
| P-05 | Évaluations | `#/assessments` | `EXISTE` | `RÉEL SIMULÉ` | Sessions, pipeline, états |
| P-06 | Cibles | `#/hosts` | `EXISTE` | `RÉEL SIMULÉ` | Inventaire d'hôtes observés |
| P-07 | Ports & services | `#/services` | `EXISTE` | `RÉEL SIMULÉ` | Ports, bannières, détection, CVE |
| P-08 | Findings | `#/findings` | `EXISTE` | `RÉEL SIMULÉ` | Liste filtrable, tri, statuts |
| P-09 | Inventory Observations | `#/inventory` | `EXISTE` | `RÉEL SIMULÉ` | Sous-ensemble `device_fingerprint` |
| P-10 | Credentials | `#/credentials` | `EXISTE` (V1) | `RÉEL SIMULÉ` | Périmètre, catalogue fictif, résultats sans secret |
| P-11 | Communications observées | `#/traffic` | `HORS PÉRIMÈTRE V1` | `RÉEL SIMULÉ` | Observation seule (Q5) |
| P-12 | Remédiation | `#/remediation` | `ABSENT` (V2+) | `RÉEL SIMULÉ` | Propositions, diff, contrôle après (Q8) |
| P-13 | Rapports | `#/reports` | `EXISTE` | `RÉEL SIMULÉ` | Rapports générés, aperçu, export |
| P-14 | Assistant | `#/assistant` | `ABSENT` | `RÉEL SIMULÉ` | Conversation déterministe plein écran |
| P-15 | Périmètre | `#/scope` | `ABSENT` | `RÉEL SIMULÉ` | Matrice capacité × produit × prototype × roadmap |
| P-16 | Lexique & règles | `#/glossary` | `EXISTE` (partiel) | `RÉEL SIMULÉ` | Termes officiels, 8 événements |
| P-17 | Règles appliquées (lecture seule) | `#/rules` | `EXISTE` | `RÉEL SIMULÉ` | Poids, seuils, quota, budgets — **non modifiables** |
| P-18 | Journal d'audit de la démo | `#/audit-log` | `ABSENT` | `RÉEL SIMULÉ` | Traçabilité de chaque action |

### P-01 Tableau de bord — le point le plus sensible

Disposition en trois bandes, grille 12 colonnes :

- **Bande 1 — Worst Current Threat** : carte du Finding prioritaire (sévérité, score, confiance, exposition, cible, statut). Si aucun Finding éligible : état vide **explicatif** + renvoi vers les critères d'éligibilité. **Pas de jauge.**
- **Bande 2 — quatre indicateurs séparés, jamais agrégés** :
  1. `Findings par sévérité` (5 barres, comptage brut) ;
  2. `États de contrôle` (`OPEN`/`VERIFIED`/`REMEDIATED`/`ACCEPTED`) ;
  3. `Complétude d'évaluation` (modules exécutés / attendus, hôtes évalués, échecs) ;
  4. `Sentinel — 60 dernières minutes` (événements par type, notifications émises / masquées).
- **Bande 3** : `Derniers changements observés` (5 lignes) + `Activité récente` (journal, 8 lignes).

Mention permanente sous la bande 2 : *« Ces indicateurs ne sont pas agrégés. SentinelX ne calcule pas de score de sécurité global. »*

### P-03 Journal d'événements — quatre règles d'affichage imposées

1. `host_ports_initialized` **n'apparaît jamais** : ni liste, ni filtre, ni notification. Mentionné une seule fois dans le lexique comme *initialisation de référence*, avec la précision « non journalisée comme événement utilisateur ».
2. Les 5 types sans Finding portent un badge `SANS FINDING` et **aucun** lien vers une fiche Finding.
3. Les notifications portent l'un des six états officiels ; `masked` reste **visible**, avec la mention « conservée, non envoyée ».
4. Une ligne `scan_degraded` affiche `INCOMPLET`, jamais `ABSENT`.

### P-04 Changements & contrôles — la distinction structurante

Deux onglets, deux verbes qui ne fusionnent jamais :

| Onglet | Contenu | Bandeau |
|---|---|---|
| **Changements** | diffs baseline → actuel | *« Un changement n'est pas une vulnérabilité. Seul `new_port`, `new_host` et `mac_change` produisent un Finding. »* |
| **Contrôles (VERIFY)** | contrôles demandés, issue, statut résultant | *« Un changement n'est pas une correction. Seul un contrôle réussi peut modifier un statut. »* |

Actions : `Modifier le monde fictif` (change les services simulés, **n'exécute aucun contrôle**) · `Exécuter un contrôle` (ne **modifie pas** le monde). Chacune a sa modale et son entrée d'audit.

### P-09 Inventory Observations — un filtre, pas une collection

Bandeau obligatoire : *« Les Inventory Observations sont des Findings d'inventaire (`category=NETWORK`, `severity=INFO`). Elles ne sont ni des vulnérabilités, ni une entité distincte, et n'entrent jamais dans le Worst Current Threat. »* Aucune écriture possible : un Inventory Observation ne change pas de statut.

### P-10 Credentials — trois zones

1. **Périmètre V1** : FTP, SNMP, SSH (mot de passe), SMB — avec les limites réelles (SMB : aucun candidat intégré, dictionnaire explicite obligatoire).
2. **Catalogue de démonstration** : 10 profils **entièrement fictifs**, mention `PROFIL DE DÉMONSTRATION — AUCUN IDENTIFIANT RÉEL`.
3. **Résultats** : service, compte **masqué** (`demo****`), issue, tentatives consommées / budget. **Aucun secret, aucun hachage, aucun mot de passe**, y compris dans les preuves et les rapports.

### P-17 Règles appliquées — l'anti-bascule

Affiche, **sans aucun contrôle modifiable** : formule du Worst Current Threat, barème `90/70/45/20/5`, multiplicateurs `1.15` / `1.00`, quota `3 / (réseau, IP) / 60 min`, budgets credentials, issues `VERIFY` autorisées, liste des types sans Finding, type silencieux.
Encart : *« Cette page est en lecture seule. Aucune interface de la démo ne permet de modifier ces règles. »*

## 5.3 Les 13 fiches détaillées

Surface de lecture rattachée à une entité, ouverte par route dédiée, quittée avec conservation des filtres.

| ID | Fiche | Route | État produit | Contenu obligatoire |
|---|---|---|---|---|
| F-01 | Finding | `#/findings/:id` | `EXISTE` | Sévérité (dont `CRITICAL`), catégorie, confiance + valeur, exposition, `risk_score` **ou** `—` + raison, statut, module, cible, `session_id`, preuve, explication `what/attack/defense` **ou** « non documentée », CVE, actions de statut |
| F-02 | Cible / Hôte | `#/hosts/:ip` | `EXISTE` | IP, MAC, nom, état (`observé`/`non observé`), ports, Findings, Inventory Observation, historique — **`NOT_OBSERVED ≠ ABSENT`** affiché en clair |
| F-03 | Port & service | `#/services/:ip/:port` | `EXISTE` | Port/protocole, état, bannière, version, indice de détection, CVE, Findings liés |
| F-04 | Événement Sentinel | `#/sentinel/events/:id` | `EXISTE` | Type, horodatage, cible, détail de présentation, `network_id`, Finding produit **ou** « aucun Finding (par conception) », état de notification + raison du masquage |
| F-05 | Changement réseau | `#/sentinel/changes/:id` | `EXISTE` | Diff avant/après, compte `+n/−n`, type d'événement, **ce qui ne change pas** (Findings, Worst Current Threat) |
| F-06 | Contrôle VERIFY | `#/sentinel/changes/verify/:id` | `ABSENT` | Finding contrôlé, méthode, issue, conditions ✅/❌, effet sur le statut, raison si inchangé |
| F-07 | Session d'évaluation | `#/assessments/:session` | `EXISTE` | `session_id`, cible, pipeline par étape, comptes, `network_id` **affiché séparément** et étiqueté « autre espace de noms » |
| F-08 | Observation d'inventaire | `#/inventory/:id` | `EXISTE` | Type d'appareil proposé, indices, confiance, règle `device_fingerprint`, rappel « pas une vulnérabilité » |
| F-09 | Profil de credentials | `#/credentials/:profile` | `EXISTE` (catalogue) / fictif (démo) | Service, famille, versions, **limites**, provenance fictive, tentatives autorisées. **Aucun identifiant affiché** |
| F-10 | Communication observée | `#/traffic/:id` | `HORS PÉRIMÈTRE V1` | 5-tuple, volume, extrait tronqué, « observation seule », liens déclarés |
| F-11 | Proposition de remédiation | `#/remediation/:id` | `ABSENT` | Finding source, action, commande indicative **non exécutable**, diff, risques, contrôle associé |
| F-12 | Rapport généré | `#/reports/:id` | `EXISTE` | Métadonnées, sections, aperçu, **note d'écart** sur le recalcul du pire score (C11) |
| F-13 | Règle de connaissance | `#/glossary/rules/:rule_id` | `EXISTE` | `what`, `attack`, `defense` (textes de la démo), Findings liés, mention d'absence de règle (C5) |

**Règle d'affichage du score (F-01)** — trois cas seulement, jamais fusionnés :

| Cas | Affichage |
|---|---|
| `risk_score` numérique | valeur + formule (`70 × 0.85 × 1.15 = 68.4`) |
| `None` (Sentinel / inventaire) | `—` + badge `NON SCORÉ` + raison textuelle |
| Aucune règle ne produit de score nul | jamais `0` — un `0` signifierait un vrai score nul |

## 5.4 Les 7 panneaux latéraux

S'ouvrent par-dessus la page, ne changent pas la route, ne bloquent pas le fond, se ferment par `Échap`. Un seul à la fois.

| ID | Panneau | Contenu |
|---|---|---|
| S-01 | Assistant contextuel | Contexte hérité automatiquement de la surface ; 7 blocs ; suggère, ne conclut pas |
| S-02 | Centre de notifications | Toutes les notifications, `masked` incluses ; `n/3` par couple réseau+IP ; raison du masquage ; **aucun bouton « renvoyer »** |
| S-03 | Filtres & tri | Filtres propres à la page ; **ne modifient pas les données** |
| S-04 | Preuve (evidence) | `evidence.raw` en monospace, tronqué à 4 kio avec dépliage, badge `EXTRAIT` ; **aucun secret** |
| S-05 | Traçabilité | Chaîne module → indice → règle → Finding ; maillon manquant affiché `NON DOCUMENTÉ` |
| S-06 | Pourquoi ce Worst Current Threat | Candidats, filtres appliqués un par un, maximum retenu, mention « aucun autre score n'est calculé » |
| S-07 | Journal d'activité | 50 dernières actions avec effet observable (`monde modifié`, `statut changé`, `contrôle demandé`) |

## 5.5 Les 9 modales

Bloquent l'interaction, exigent une décision explicite, laissent une trace dans P-18. **Aucune action irréversible ou signifiante par simple clic.**

| ID | Modale | Points obligatoires |
|---|---|---|
| M-01 | Lancer une évaluation | Cible, modules, rappel « simulation locale, aucun paquet émis » |
| M-02 | Exécuter un contrôle (VERIFY) | Finding ciblé, méthode, ce que le contrôle **peut** et **ne peut pas** conclure, rappel « ne modifie pas le monde » |
| M-03 | Résultat de contrôle | Trois variantes exclusives. `SUCCESS` → bouton de confirmation distinct. `PARTIAL` → « statut inchangé, 2 conditions sur 3 ». `FAILED` → « n'établit aucune correction ». **Jamais `REMEDIATED`.** Bouton de passage à `VERIFIED` **absent** hors `SUCCESS` |
| M-04 | Appliquer une remédiation à la simulation | Diff avant/après, portée, avertissement, case « ne modifie aucun système réel », contrôle obligatoire ensuite |
| M-05 | Changer le statut d'un Finding | Statut cible, **justification obligatoire** (≥ 20 caractères) pour `ACCEPTED` et `REMEDIATED`, rappel que `VERIFIED` vient d'un contrôle |
| M-06 | Gérer la whitelist Sentinel | `allow port` / `allow host` / `allow mac` ; portée ; effet `whitelisted` ; **n'agit pas sur les Findings** |
| M-07 | **Action non conforme (refus)** | Explique le refus, cite la règle, propose l'alternative. Trois cas : *calculer un score global*, *scorer un Finding Sentinel*, *faire baisser le Worst Current Threat depuis un `port_not_open`* |
| M-08 | Changer de scénario | S1–S8, avertissement « réinitialise le monde fictif », journal conservé |
| M-09 | Aide clavier | Raccourcis, utilisable au clavier seul |

**M-07 est une exigence, pas un ornement** : l'interface **refuse explicitement** les trois opérations qui contrediraient les règles officielles. C'est la fidélité Q3 rendue observable.

## 5.6 Carte de navigation

```
                    ┌──────────────┐
                    │  P-00 Conn.  │
                    └──────┬───────┘
                           ▼
                 ┌─────────────────────┐
                 │  P-01 Tableau bord  │  ← S-02, S-06, S-07, S-01
                 └───┬─────────┬───────┘
      ┌──────────────┘         └───────────────┐
      ▼                                        ▼
┌───────────────┐                      ┌────────────────┐
│ SENTINEL      │                      │ TECHNIQUE      │
│ P-02 Vue      │→ F-01                │ P-05 Éval.     │→ F-07
│ P-03 Journal  │→ F-04                │ P-06 Cibles    │→ F-02
│ P-04 Changem. │→ F-05, F-06          │ P-07 Ports     │→ F-03
└───────┬───────┘                      │ P-10 Creds     │→ F-09
        │                              └────────┬───────┘
        ▼                                       ▼
┌───────────────┐                      ┌────────────────┐
│ CONSTATS      │                      │ ACTION         │
│ P-08 Findings │→ F-01                │ P-12 Reméd.    │→ F-11
│ P-09 Invent.  │→ F-08                │ P-13 Rapports  │→ F-12
│ P-11 Trafic*  │→ F-10                └────────┬───────┘
└───────┬───────┘                               │
        ▼                                       ▼
┌─────────────────────────────────────────────────────────┐
│ SYSTÈME : P-14 Assistant · P-15 Périmètre ·             │
│           P-16 Lexique → F-13 · P-17 Règles · P-18 Audit│
└─────────────────────────────────────────────────────────┘
        * page présentant une proposition hors périmètre V1
```

## 5.7 Interactions, transitions, accessibilité, rédaction

**Navigation**
- **Route = état** : chaque surface a une URL ; recharger restitue la vue.
- **Retour avec contexte** : quitter une fiche ramène à la liste avec filtres, tri et position conservés.
- **Fils d'Ariane** sur 3 niveaux maximum.
- **Liens croisés systématiques** : Finding → hôte → port → service → CVE → règle ; événement → changement → Finding produit. Un lien vers une entité absente affiche `Cible non observée`, jamais un écran vide.

**États de chaque surface**

| État | Rendu |
|---|---|
| `chargement` | Squelette avec la structure réelle ; jamais de spinner plein écran > 300 ms |
| `vide` | Message expliquant **pourquoi c'est vide** + action utile |
| `dégradé` | Bandeau `INCOMPLET — contrôle non conclusif` (jamais `ABSENT`) |
| `erreur` | Message, code local, action de reprise **sans réseau** |
| `interdit` | M-07 |

**Transitions** : ≤ 160 ms, `ease-out`. Fiche : glissement 12 px + fondu. Modale : fondu + échelle 0.98→1. Panneau : glissement 24 px. `prefers-reduced-motion: reduce` ⇒ **aucune** animation. Aucune animation ne porte d'information seule.

**Clavier et accessibilité** — cible WCAG 2.1 AA : contraste ≥ 4.5:1 (texte), ≥ 3:1 (composants), focus visible 2 px, ordre de tabulation logique, piège de focus dans les modales, `aria` sur les tableaux triables et `aria-live` sur le centre de notifications. Raccourcis : `g d` tableau de bord · `g s` Sentinel · `g f` Findings · `g p` Périmètre · `?` aide · `Échap` fermer · `Ctrl+Espace` assistant · `/` recherche · `j/k` ligne suivante/précédente.

**Rédaction**
- Français intégral ; termes officiels en anglais et invariables.
- **Interdits** : « sécurisé », « protégé », « note de sécurité », « niveau de risque global », « vulnérabilités corrigées automatiquement », « en temps réel », « intrus », « attaque détectée ».
- **Imposés** : « observé » / « non observé » (jamais « absent » sans qualification), « contrôle non conclusif », « non documenté dans la Knowledge Base ».

## 5.8 Références produit par surface `EXISTE`

| Surface | Référence vérifiée |
|---|---|
| P-02, P-03, P-04 | `sentinel/sentinel_manager.py`, `monitor.py`, `monitor_view.py`, `notifications.py`, `alerting.py`, `whitelist.py` ; table `events` |
| P-05 | `core/assessment.py`, `session_id`, pipeline |
| P-06, P-07 | `recon/`, `detect/service_detection.py`, `knowledge/ports.json` (29 ports) |
| P-08 | `core/finding.py` (`to_dict`, `format_finding_id`), CLI `findings list/show/explain/update` |
| P-09 | `recon/device_fingerprint.py:317`, `risk_scorer.py:101`, `cli.py:1941` |
| P-10 | `docs/T22-CREDENTIALS.md`, `detect/default_creds.py`, `knowledge/default_credentials.json` |
| P-13 | `reports/generator.py` (HTML 46 465 octets constatés) |
| P-16, P-17 | `knowledge/vulnerabilities.json` (21 règles), `core/risk_scorer.py` |
| F-13 | `knowledge/knowledge_base.py` (`what`/`attack`/`defense`) |

## 5.9 Surfaces volontairement exclues

| Surface écartée | Raison |
|---|---|
| Carte topologique du réseau | Le produit n'en construit pas ; la simuler créerait une capacité fictive |
| Score / jauge de sécurité globale | Interdit par la décision §H et par votre §2.8 |
| Éditeur de règles de connaissance | Modifierait les règles officielles (Q3) |
| Console de commandes simulée | Suggérerait une exécution réelle ; `remediation_cmd` reste en lecture seule |
| Tableau de bord de conformité (ISO/PCI) | Aucune base dans le produit ; hors périmètre V1 |

---

# 6. Architecture, arborescence, garde-fous

## 6.1 Huit principes

| # | Principe | Conséquence concrète |
|---|---|---|
| A1 | **Aucune opération réseau** | Le processus ne crée aucune connexion sortante, ne résout aucun nom, n'ouvre aucun socket client. Un seul socket : le serveur d'interface, lié à `127.0.0.1`. |
| A2 | **Le monde est une donnée** | Hôtes, ports, services, communications sont des enregistrements. « Scanner » = parcourir une table. |
| A3 | **Règles officielles, une seule implémentation** | Scoring, quota, 8 types, budgets credentials, 3 issues `VERIFY` : implémentés une fois dans `engine/`, consommés par l'interface et l'assistant. Aucun calcul dupliqué en JavaScript. |
| A4 | **L'interface ne calcule rien de signifiant** | Le JS affiche, filtre, met en forme. Tout chiffre vient de l'API : impossible de faire diverger l'affichage et la règle. |
| A5 | **Deux espaces de noms, deux bases** | `session_id` et `network_id` : deux fichiers SQLite, deux modules, deux validateurs. |
| A6 | **Tout est rejouable** | Horloge virtuelle + graine fixe par scénario ⇒ un scénario produit toujours la même séquence. |
| A7 | **Zéro dépendance** | Bibliothèque standard uniquement (`http.server`, `sqlite3`, `json`, `dataclasses`, `enum`, `unittest`). Aucun paquet tiers, même en test. |
| A8 | **Zéro build** | Le navigateur charge les fichiers tels quels : pas de transpilation, pas de bundler, pas de CDN. |

## 6.2 Arborescence complète

```
sentinelx-future-demo/
├── run.py                          # python3 run.py [--scenario S4] [--port 8765]
├── README.md                       # démarrage, garde-fous, ce que la démo n'est pas
├── LICENSE                         # à choisir (Q-D1) — absent tant que non tranché
│
├── app/
│   ├── __init__.py
│   ├── __main__.py                 # python3 -m app
│   ├── server.py                   # ThreadingHTTPServer lié à 127.0.0.1, routage, en-têtes
│   ├── routes.py                   # table déclarative des routes API
│   ├── session.py                  # session locale (cookie opaque, aucun mot de passe stocké)
│   ├── api/
│   │   ├── queries.py              # GET : lecture seule, projections prêtes à afficher
│   │   ├── commands.py             # POST : les 14 commandes du moteur
│   │   ├── serialize.py            # Finding/Event → dict d'affichage (champs officiels + dérivés)
│   │   └── errors.py               # {code, message, regle, alternative}
│   ├── engine/
│   │   ├── clock.py                # VirtualClock
│   │   ├── rng.py                  # Random ensemencé par (scénario, étape)
│   │   ├── world.py                # état fictif (hôtes, ports, services, flux)
│   │   ├── assessor.py             # pipeline d'évaluation en 6 étapes
│   │   ├── scoring.py              # réplique fidèle de core/risk_scorer
│   │   ├── findings.py             # store + transitions de statut autorisées
│   │   ├── inventory.py            # filtre device_fingerprint (nature=inventory)
│   │   ├── remediation.py          # propositions, diff, application au monde fictif
│   │   ├── journal.py              # journal d'audit
│   │   ├── ids.py                  # SessionId / NetworkId, génération et validation
│   │   └── sentinel/
│   │       ├── baseline.py         # capture de référence (host_ports_initialized, silencieux)
│   │       ├── differ.py           # diff baseline ↔ courant → 8 types
│   │       ├── rules.py            # quel type produit quel Finding
│   │       ├── notify.py           # quota + 6 états
│   │       ├── verify.py           # SUCCESS / PARTIAL / FAILED
│   │       └── store.py            # persistance des événements par network_id
│   ├── knowledge/
│   │   ├── loader.py               # chargement + validation de schéma au démarrage
│   │   ├── rules.json              # 21 règles, textes RÉDIGÉS POUR LA DÉMO
│   │   ├── ports.json              # 29 ports
│   │   ├── cve.json                # 11 entrées, identifiants publics, textes originaux
│   │   └── demo_credentials.json   # 10 profils 100 % fictifs
│   ├── scenarios/                  # schema.json + s1…s8
│   ├── assistant/
│   │   ├── explainer.py            # interface Explainer + implémentation déterministe
│   │   ├── context.py              # paquet de contexte
│   │   ├── intents.py              # 9 intentions, règles
│   │   ├── templates.py            # gabarits typés
│   │   └── render.py               # 7 blocs + vérification des sources + lexique interdit
│   ├── safety/
│   │   ├── install_guards.py       # neutralise socket.connect / urlopen / subprocess
│   │   ├── guards.py
│   │   └── invariants.py           # vérifications au démarrage
│   └── storage/
│       ├── schema.sql
│       ├── db.py                   # connexions, transactions, chemins confinés
│       └── seed.py                 # chargement d'un scénario
│
├── web/
│   ├── index.html                  # coquille SPA, <script type="module">
│   ├── css/{tokens,base,layout,components}.css
│   ├── js/
│   │   ├── main.js · router.js · api.js · store.js · format.js · guard.js
│   │   ├── components/{table,badge,drawer,modal,svg-chart,diff,timeline}.js
│   │   └── views/                  # une vue par page (P-00…P-18) et par fiche (F-01…F-13)
│   └── assets/icons.svg
│
├── tests/                          # 11 fichiers, voir §13
├── tools/
│   ├── check_no_network.py         # AST : aucun import réseau, aucune URL absolue
│   ├── check_no_verbatim.py        # empreintes vs _audit/a4 (lecture seule)
│   └── snapshot_scenarios.py       # régénère les états attendus (revue humaine)
├── docs/{architecture,limites,garde-fous}.md
└── runtime/                        # créé à l'exécution, ignoré par git
    ├── session-<session_id>.db
    ├── sentinel-<network_id>.db
    └── app.log
```

**Interdits d'arborescence** : pas de `package.json`, pas de `requirements.txt` (aucune dépendance), pas de `Dockerfile`, pas de `.env`.

## 6.3 Couches et dépendances

```
        ┌──────────────────────────────────────────────┐
        │  web/  (HTML/CSS/JS, aucune logique métier)   │
        └───────────────────────┬──────────────────────┘
                                │ HTTP local, même origine
        ┌───────────────────────▼──────────────────────┐
        │  server.py + routes.py + api/*                │
        └───────────────────────┬──────────────────────┘
                                │ appels Python directs (aucun IPC)
        ┌───────────────────────▼──────────────────────┐
        │  engine/*  (règles, état, calculs)            │
        │  assistant/*  (lecture seule du moteur)       │
        └──────────┬──────────────────────┬─────────────┘
                   ▼                      ▼
        ┌─────────────────────┐  ┌────────────────────┐
        │ storage/ (sqlite3)  │  │ knowledge/ (JSON)  │
        └─────────────────────┘  └────────────────────┘

        safety/*  — coupe transversalement, installé AVANT toute autre initialisation
```

**Règles de dépendance, vérifiées par test** :
`engine/` n'importe jamais `api/`, `server.py` ni `web/` · `assistant/` n'importe jamais une fonction d'écriture · `web/js/**` n'importe aucun module externe (aucune URL absolue) · `knowledge/` ne contient aucun code · `safety/` est importé en premier dans `run.py`.

| Module | Dépend de | Ne dépend jamais de |
|---|---|---|
| `engine.scoring` | `knowledge`, constantes internes | `engine.sentinel`, `api` |
| `engine.sentinel.differ` | `engine.world`, `sentinel.rules` | `engine.scoring` |
| `engine.sentinel.notify` | `engine.clock`, `engine.ids` | `engine.findings` |
| `engine.sentinel.verify` | `engine.world`, `engine.findings`, `engine.clock` | `api` |
| `engine.assessor` | `world`, `scoring`, `findings`, `knowledge` | `sentinel.*` |
| `engine.remediation` | `world`, `findings`, `sentinel.verify` | `api` |
| `assistant.*` | projections de `queries.py` uniquement | toute fonction d'écriture |
| `api.*` | `engine.*`, `storage` | `web/` |

## 6.4 Correspondance avec le produit

Aucun module réel n'est importé. Chaque module de la démo hérite d'un module réel.

| Module démo | Équivalent produit | Reproduit | Change |
|---|---|---|---|
| `engine.scoring` | `core/risk_scorer.py` | Barème, confiance, exposition, plafond 100, `get_global_score` = max filtré | Entrées lues en base ; aucun signal réseau |
| `engine.findings` | `core/finding.py`, table `findings` | Champs, énumérations, `to_dict`, `format_finding_id` | `session_id` fourni par l'évaluation |
| `engine.inventory` | `INVENTORY_MODULES`, `_is_inventory_observation` | Filtre `module == "device_fingerprint"` | Aucun changement de nature |
| `engine.assessor` | `core/assessment.py`, `detect/*`, `recon/*` | Séquence des 6 étapes, noms de modules | Résultats simulés |
| `engine.sentinel.differ` | `sentinel/alerting.py` (`process_changes`) | 8 types, table de correspondance, `SILENT_TYPES` | Diff calculé sur deux états en base |
| `engine.sentinel.notify` | `sentinel/notifications.py` | `WINDOW=60 min`, `LIMIT=3`, 6 états, comptage `displayed`/`reserved` | Horloge virtuelle |
| `engine.sentinel.verify` | **aucun** | — | **Ajout assumé, `ABSENT`**, conforme à Q9 |
| `engine.remediation` | `remediation_cmd` (champ V2) | Le champ existe | Proposition + application simulée : **`ABSENT`** |
| `knowledge/` | `knowledge/*.json` | Structure, identifiants | **Textes réécrits**, credentials fictifs, zéro verbatim |
| `assistant/` | **aucun** | — | `ABSENT` |

## 6.5 Contrat d'API

Serveur local, JSON, `http://127.0.0.1:<port>`. Toute route non déclarée renvoie `404` et n'ouvre aucun fichier arbitraire.

**Lecture (GET, sans effet de bord)**

| Route | Réponse |
|---|---|
| `/api/bootstrap` | réseau, session, scénario actif, horloge virtuelle, drapeaux `guards` |
| `/api/dashboard` | bande 1 (WCT), bande 2 (4 indicateurs séparés), bande 3 |
| `/api/findings`, `/api/findings/<id>` | liste paginée + filtres ; `risk_score` **ou** `null` + `non_scored_reason` ; `explanation_state` |
| `/api/inventory` | sous-ensemble `device_fingerprint` + statistiques |
| `/api/hosts`, `/api/hosts/<ip>` | hôtes, ports, Findings, historique |
| `/api/services`, `/api/services/<ip>/<port>` | ports, bannières, CVE |
| `/api/assessments`, `/api/assessments/<session_id>` | sessions, pipeline |
| `/api/sentinel` | état, compteur de cycles, WCT, exclus |
| `/api/sentinel/events`, `/api/sentinel/changes`, `/api/sentinel/verify` | événements (sans le type silencieux), diffs, contrôles |
| `/api/notifications` | notifications avec état, raison, compteur de quota |
| `/api/credentials`, `/api/traffic`, `/api/remediation`, `/api/reports` | **sans aucun secret** |
| `/api/rules`, `/api/scope`, `/api/journal` | constantes appliquées, matrice produit/prototype, audit |
| `/api/assistant/context`, `/api/assistant/suggestions` | paquet de contexte, questions pertinentes |

**Écriture (POST, une commande = un effet explicite)**

| Commande | Effet | Garde |
|---|---|---|
| `run-assessment` | exécute le pipeline simulé | crée un nouveau `session_id` |
| `mutate-world` | change l'état fictif | **aucun contrôle exécuté** ; journalisé |
| `scan-sentinel` | un cycle : diff + événements + notifications | ne modifie jamais le monde |
| `run-verify` | contrôle VERIFY | **ne modifie jamais le monde** ; renvoie une des 3 issues |
| `apply-finding-status` | transition de statut | table de transitions ; justification exigée ; `VERIFIED` refusé sans `SUCCESS` |
| `whitelist-add` / `whitelist-remove` | whitelist Sentinel | n'agit pas sur les Findings |
| `propose-remediation` / `apply-remediation` | proposition, application simulée | VERIFY obligatoire après application |
| `generate-report` | produit un rapport | lecture seule sur les données |
| `set-scenario` | recharge un scénario | réinitialise le monde, conserve le journal |
| `assistant-ask` | question à l'assistant | **lecture seule** |
| `login` / `logout` | session locale | compte fictif uniquement |

**Modèle de réponse**

```json
{ "ok": true, "data": { … }, "meta": { "virtual_time": "2026-11-12T09:41:00Z", "scenario": "S4" } }
```
```json
{ "ok": false, "error": {
    "code": "STATUS_TRANSITION_FORBIDDEN",
    "message": "Le statut VERIFIED exige un contrôle réussi.",
    "rule": "Q9 / verify.py",
    "alternative": "Exécuter un contrôle (M-02) puis réessayer." } }
```

Codes : `NOT_FOUND`, `VALIDATION_ERROR`, `STATUS_TRANSITION_FORBIDDEN`, `VERIFY_REQUIRED`, `JUSTIFICATION_REQUIRED`, `SCORE_NOT_APPLICABLE`, `GLOBAL_SCORE_NOT_SUPPORTED`, `WRONG_ID_KIND`, `READ_ONLY_SURFACE`, `ASSISTANT_WRITE_FORBIDDEN`, `GUARD_VIOLATION`.

`GLOBAL_SCORE_NOT_SUPPORTED` et `SCORE_NOT_APPLICABLE` sont **normaux** : ils matérialisent M-07.

**Sécurité de surface**
- En-têtes : `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'` · `X-Content-Type-Options: nosniff` · `Referrer-Policy: no-referrer` · `Cache-Control: no-store`.
- Liaison **`127.0.0.1` exclusivement** ; `--host` n'existe pas ; toute autre adresse est refusée au démarrage.
- Aucun cookie journalisé ; aucun accès disque hors `runtime/` (résolution + refus de `..`).

## 6.6 Garde-fous d'exécution

`install_guards.py` s'exécute **avant** tout le reste dans `run.py`.

| Garde-fou | Mise en œuvre | Test |
|---|---|---|
| Pas de socket client | `socket.socket.connect`, `connect_ex`, `create_connection` ⇒ `GuardViolation` | `test_safety::test_no_outbound_socket` |
| Pas de résolution DNS | `getaddrinfo` restreint à `127.0.0.1` / `localhost` | `test_dns_restricted` |
| Pas de sous-processus | `subprocess.Popen/run/call` ⇒ `GuardViolation` | `test_no_subprocess` |
| Pas de code dynamique | `eval`/`exec` interdits (vérification AST) | `test_no_eval_exec` |
| Pas d'accès hors `runtime/` | chemins résolus et confinés | `test_db_path_confined` |
| Pas de HTTP sortant | imports réseau interdits hors `server.py` | `test_no_outbound_http` |
| Pas de secret dans les sorties | masquage à la source dans le sérialiseur | `test_no_secret_leak` |

Les garde-fous sont **actifs en démonstration**, pas seulement en test : un scénario malformé ne peut pas provoquer de connexion sortante.

## 6.7 Déterminisme et rejeu

- **Horloge virtuelle** : démarre à `2026-11-12T09:00:00Z`. Elle n'avance que sur événement explicite (`advance(seconds)`), à l'échelle déclarée (`1 s réelle = 1 min virtuelle` en mode démo, `1 s = 1 s` en mode revue). Toute date affichée est étiquetée `virtuel` si elle diffère de plus de 24 h de l'heure système.
- **Aléa** : `Random(seed)` avec `seed = hash(scénario, étape)`. Aucun `random` global ; aucun `time.time()` dans le moteur (seulement dans `clock.py`).
- **Rejeu** : `--replay` rejoue une séquence enregistrée et compare l'état par empreinte. C'est le mécanisme des tests de scénarios.

## 6.8 Concurrence et durée de vie

`ThreadingHTTPServer` avec **verrou unique** autour du moteur : lectures parallélisables, commandes sérialisées — pas de course sur le monde fictif. Deux connexions SQLite maximum, fermées par `atexit`. Arrêt propre par `Ctrl+C`, suppression optionnelle de `runtime/` (`--clean`).

**Aucune tâche de fond : le cycle Sentinel n'est jamais automatique.** Un cycle se produit uniquement sur commande. Décision de conception : un automatisme rendrait la démonstration imprévisible et empêcherait de rejouer les scénarios.

## 6.9 Ce que l'architecture rend impossible (par construction)

| Tentative | Pourquoi c'est impossible |
|---|---|
| Contacter un hôte réel | Aucun code réseau ; socket sortant neutralisé ; pas de DNS ; le monde est une table |
| Exécuter une commande de remédiation | `subprocess` neutralisé ; `remediation_cmd` n'est qu'une chaîne affichée |
| Calculer un score global | Aucune fonction de ce type ; l'API renvoie `GLOBAL_SCORE_NOT_SUPPORTED` |
| Scorer un Finding Sentinel | `scoring.py` refuse ; la sérialisation renvoie `null` + raison |
| Passer un Finding à `VERIFIED` sans contrôle | `findings.apply_status` consulte le registre VERIFY |
| Écrire `REMEDIATED` automatiquement | Aucun chemin de code ne l'écrit |
| Modifier les règles officielles depuis l'UI | P-17 en lecture seule ; aucune commande de configuration n'existe |
| Faire fuiter un secret | Masquage à la source, avant toute génération de preuve ou de rapport |
| Utiliser la démo comme preuve de roadmap | `/api/scope` renvoie deux attributs distincts, jamais fusionnés |

---

# 7. Modèle de données

Le modèle est **fidèle au produit** : mêmes entités, mêmes noms de champs, mêmes énumérations. Aucune valeur n'est inventée. Les additions sont marquées `[DÉMO]` et correspondent toutes à des capacités `ABSENT`.

## 7.1 Vue d'ensemble

```
Network (network_id) ──┬──< SentinelEvent ──> Notification (imbriquée)
                       └──1 Baseline

Assessment (session_id) ──< Host ──< PortService ──< CveMatch
        │                     │
        └──< Finding >────────┘      Finding ──0..1 Explanation
                    │                     └──1 Evidence
                    ├──< VerifyRun [DÉMO]
                    ├──< RemediationProposal [DÉMO]
                    └──< ReportItem

CredentialProfile (fictif) ──< CredentialAttempt
TrafficRecord [DÉMO] ──0..1 Finding (lien déclaré)
KnowledgeRule ──> Finding (par rule_id)
AuditEntry (transversal, non supprimable)
ScopeCapability (référentiel produit/prototype)
```

**Cardinalités** : un `Network` a *n* événements ; une `Assessment` a *n* `Host` et *n* `Finding` ; un `Finding` a 0 ou 1 `Explanation` ; il peut avoir *n* `VerifyRun`. Un `Finding` **n'a jamais** de `network_id` ; un `SentinelEvent` **n'a jamais** de `session_id`.

## 7.2 Énumérations officielles — verbatim

```python
class Severity(str, Enum):        # core/finding.py:32
    CRITICAL = "critical"         # produit par detect/service_detection.py (base CVE)
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

class Category(str, Enum):        # 5 catégories, toutes fonctionnelles
    CONFIG     = "config"
    SERVICE    = "service"
    NETWORK    = "network"
    CREDENTIAL = "credential"
    TRACE      = "trace"

class Confidence(float, Enum):    # valeurs numériques officielles
    CONFIRMED = 1.00
    PROBABLE  = 0.85
    POSSIBLE  = 0.60

class Exposure(str, Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"

class FindingStatus(str, Enum):
    OPEN       = "open"
    VERIFIED   = "verified"
    REMEDIATED = "remediated"
    ACCEPTED   = "accepted"
```

**Trois précisions qui évitent trois erreurs fréquentes**
1. `CRITICAL` **existe et est produit** (§3.1) : l'interface l'affiche avec un style propre.
2. `Category` et `FindingStatus` sont **deux dimensions indépendantes** : nature fonctionnelle du constat vs état. **Il n'existe aucun cycle de vie à cinq étapes.**
3. `Confidence` est **numérique** : le calcul utilise la valeur, l'affichage le nom. Le seuil `≥ 0.70` exclut donc `POSSIBLE` — conséquence à écrire dans l'interface, pas à corriger.

**Les 8 types Sentinel** — 1 silencieux, 5 sans Finding :

| Type | Finding | Sévérité du Finding | Affiché | Notifié |
|---|---|---|---|---|
| `new_host` | oui | MEDIUM | oui | oui (sous quota) |
| `new_port` | oui | HIGH | oui | oui (sous quota) |
| `mac_change` | oui | HIGH | oui | oui (sous quota) |
| `host_not_observed` | non | — | oui | oui (sous quota) |
| `host_recovered` | non | — | oui | oui (sous quota) |
| `port_not_open` | non | — | oui | oui (sous quota) |
| `scan_degraded` | non | — | oui | oui (sous quota) |
| `host_ports_initialized` | non | — | **jamais** | **jamais** |

**Six états de notification** : `preparing`, `confirmed`, `masked`, `uncertain`, `whitelisted`, `unknown` (§3.3).
**Trois issues de contrôle** `[DÉMO]` : `SUCCESS`, `PARTIAL`, `FAILED`.

## 7.3 Entités

### `Network` — la surveillance

| Champ | Type | Règle |
|---|---|---|
| `network_id` | TEXT PK | **12 hexadécimaux**, dérivé de `CIDR + passerelle IP + passerelle MAC` (hash) |
| `cidr` | TEXT | `192.0.2.0/24` |
| `gateway_ip`, `gateway_mac` | TEXT | composantes de l'identité |
| `label` | TEXT | nom lisible |
| `state` | TEXT | `ACTIF` / `EN PAUSE` / `ARRÊTÉ` |
| `baseline_at` | TEXT | horodatage virtuel de la référence |
| `cycle_count` | INTEGER | cycles exécutés |

### `Assessment` — l'évaluation (session)

| Champ | Type | Règle |
|---|---|---|
| `session_id` | TEXT PK | `sentinel-run-<uuid4>` — format du produit |
| `target`, `started_at`, `finished_at` | TEXT | virtuels |
| `state` | TEXT | `attente` / `en cours` / `terminé` / `dégradé` / `échec` |
| `steps` | JSON | 6 étapes : `{name, state, duration_s, findings_count}` |
| `modules_run` | JSON | modules réellement exécutés (sert à la complétude) |

### `Host`, `PortService`

`Host(ip, session_id, mac, hostname, presence)` — `presence ∈ {observé, non observé}`, **jamais `absent`**.
`PortService(ip, session_id, port, protocol, state, banner, service, version, detection_evidence)` — `state ∈ {ouvert, filtré, fermé, non observé}`.

### `Finding` — l'entité unique

Champs **identiques au produit** (`core/finding.py`), plus un identifiant d'affichage calculé par la même règle (`format_finding_id` → `FD-` + 8 hex).

| Champ | Type | Note |
|---|---|---|
| `id` | TEXT PK | UUID interne |
| `display_id` | TEXT | `FD-1A2B3C4D` (calculé, jamais stocké en dur) |
| `session_id` | TEXT | espace de noms « évaluation » |
| `module` | TEXT | `tcp_scan`, `smb_enum`, `default_creds`, `device_fingerprint`, `sentinel.new_port`… |
| `created_at` | TEXT | virtuel |
| `target_ip`, `target_port`, `target_service`, `service_version` | — | `target_service` reste `""` pour un Finding Sentinel (règle T23-B) |
| `category`, `severity`, `confidence`, `exposure` | ENUM | voir §7.2 |
| `evidence_raw`, `evidence_command` | TEXT | preuve brute, **jamais interprétée**, aucun secret |
| `rule_id` | TEXT NULL | `NULL` ⇒ « non documentée dans la Knowledge Base » |
| `cve_refs`, `cvss_score` | JSON / REAL NULL | valeurs de la base, jamais recalculées |
| `risk_score` | REAL NULL | **NULL si non applicable** (§7.5) |
| `status` | ENUM | 4 valeurs |
| `remediation_cmd` | TEXT | **chaîne affichée, jamais exécutée** |
| `sentinel_event_id` | TEXT NULL `[DÉMO]` | traçabilité vers l'événement d'origine, sans fusion des entités |

**Champ dérivé `nature`** — jamais stocké :
```python
def nature(f: Finding) -> str:
    return "inventory" if f.module in INVENTORY_MODULES else "security"
INVENTORY_MODULES = frozenset({"device_fingerprint"})   # identique à risk_scorer.py:101
```

> C'est le point vérifié au §3.2 : **une entité, un filtre, deux présentations**. Aucune page ne crée d'objet « Observation ».

### `Explanation`

`rule_id` PK · `what`, `attack`, `defense` (textes **rédigés pour la démo**) · `applies_to_modules`.
`Finding.explanation = None` ⇒ l'interface affiche `non documentée dans la Knowledge Base` et **rien d'autre**. Aucun texte générique de remplacement.

### `Baseline`, `SentinelEvent`

`Baseline(network_id, captured_at, hosts, init_silent)` — `init_silent` toujours vrai : la capture émet `host_ports_initialized`, type silencieux.

`SentinelEvent(id, network_id, type, occurred_at, target_ip, target_port, change_kind, detail, finding_id, notification)` :
- `type` : 8 valeurs (la silencieuse est **stockée mais jamais exposée**) ;
- `change_kind` : `apparition` / `disparition` / `modification` / `échec de contrôle` / `initialisation` ;
- `finding_id` : renseigné pour les 3 types producteurs, `NULL` sinon ;
- `notification` : **toujours présent**, `masked` inclus.

### `VerifyRun` `[DÉMO]`

`id`, `finding_id`, `method`, `outcome` ∈ {`SUCCESS`,`PARTIAL`,`FAILED`}, `checks` (`[{label, satisfied}]`), `ran_at`, `status_effect` (`"open→verified"` si `SUCCESS`, `"inchangé"` sinon).

### `RemediationProposal` `[DÉMO]`

`id`, `finding_id`, `action`, `indicative_command` (**non exécutable**), `state` ∈ {`proposée`, `appliquée à la simulation`, `contrôlée`, `abandonnée`}, `diff_before`, `diff_after`, `verify_run_id` (obligatoire après application).

### `CredentialProfile` / `CredentialAttempt`

```
CredentialProfile(profile_id, service, product_family, versions[], limits,
                  provenance{synthetic:true, note}, candidates_count)
CredentialAttempt(attempt_id, session_id, service, account_masked,
                  outcome[succeeds|refused|timeout|not_tested],
                  attempts_used, budget_total, elapsed_s)
```

**Contrainte absolue** : ni l'un ni l'autre ne contient de mot de passe, de hachage ou de secret, **même fictif**. Le compte est masqué (`demo****`). Un test parcourt toutes les réponses et échoue si un motif de mot de passe apparaît.

### `TrafficRecord` `[DÉMO, hors périmètre V1]`

`(id, at, src, dst, protocol, src_port, dst_port, bytes, state, payload_excerpt, linked_finding_id, link_origin)` — `link_origin = "déclaré par l'analyste"`. Le prototype **ne déduit jamais** un lien.

### `Report`, `KnowledgeRule`, `AuditEntry`, `ScopeCapability`

- `Report(id, generated_at, session_id, format, size_bytes, preview_checksum, sections[])`
- `KnowledgeRule` ≡ `Explanation` + provenance (`public_reference`, `rewritten_for_demo: true`)
- `AuditEntry(id, at, actor, surface, action, target, effect_class, detail)` — `effect_class ∈ {lecture, monde_modifié, statut_modifié, contrôle_exécuté}`. **Non supprimable, non modifiable.**
- `ScopeCapability(capability_id, name_fr, surface_ids, product_state, prototype_state, roadmap, notes, evidence_ref)` — source de P-15.

## 7.4 `session_id` ≠ `network_id` : séparation structurelle

| | `session_id` | `network_id` |
|---|---|---|
| Objet | une **évaluation** | une **surveillance continue** |
| Portée | bornée | persistante |
| Format | `sentinel-run-<uuid4>` | 12 hex (hash CIDR + gw IP + gw MAC) |
| Base | `runtime/session-<session_id>.db` | `runtime/sentinel-<network_id>.db` |
| Contenu | Host, PortService, Finding, VerifyRun, RemediationProposal | Baseline, SentinelEvent, Notification |
| Préfixe d'affichage | `SR-` | `NET-` |
| Type Python | `SessionId(str)` | `NetworkId(str)` |
| Validateur | `^sentinel-run-[0-9a-f-]{36}$` | `^[0-9a-f]{12}$` |

**Cinq mécanismes empêchent la confusion**
1. Deux classes distinctes (`NewType`), pas deux `str` : un passage croisé est détectable.
2. Deux bases physiques : `SELECT … FROM findings WHERE network_id = ?` échoue à la compilation SQL.
3. `ids.cross_check(kind, value)` aux frontières de l'API → `WRONG_ID_KIND` (pas un 404 ambigu).
4. F-07 affiche les deux **côte à côte, étiquetés** « autre espace de noms ».
5. Test `test_ids::test_no_cross_reference` refuse toute fonction acceptant les deux types sans `cross_check`.

C'est la situation du produit : Findings en session `sentinel-run-…`, événements en `~/.netlab/sentinel/<network_id>.db`.

## 7.5 Dérivations — aucune n'est stockée en dur

### `risk_score`

```
base       = {CRITICAL:90, HIGH:70, MEDIUM:45, LOW:20, INFO:5}[severity]
confiance  = {CONFIRMED:1.00, PROBABLE:0.85, POSSIBLE:0.60}[confidence]
exposition = {EXTERNAL:1.15, INTERNAL:1.00}[exposure]
risk_score = min(100, base × confiance × exposition)
```

### Quand `risk_score` vaut `None` — trois raisons, trois affichages

| Raison | Cause | Affichage |
|---|---|---|
| `sentinel_non_score` | Finding produit par Sentinel | `—` + badge `NON SCORÉ (Sentinel)` |
| `inventory` | `module == "device_fingerprint"` | `—` + badge `INVENTAIRE` |
| *(aucun cas « zéro »)* | Aucune règle ne produit `0` | jamais affiché |

### Worst Current Threat

```python
def worst_current_threat(findings):
    candidats = [f for f in findings
                 if f.status == FindingStatus.OPEN
                 and f.risk_score is not None
                 and f.confidence >= Confidence.PROBABLE      # 0.85 ≥ 0.70
                 and nature(f) == "security"]
    return max(candidats, key=lambda f: f.risk_score, default=None)
```

Aucune moyenne, aucune somme, aucun agrégat. Si la liste est vide, l'interface dit **pourquoi** (filtres ayant tout éliminé) au lieu d'afficher `0`.

Nuance du §3.4 : une sévérité `CRITICAL` n'assure **pas** l'entrée dans le Worst Current Threat si la confiance est `POSSIBLE`.

### État de notification

```
available = LIMIT − displayed − reserved          (LIMIT = 3, fenêtre 60 min, par couple réseau+IP)

si changement whitelisté ou type silencieux → "whitelisted"     (hors quota)
sinon si available == 0                     → "masked"          (enregistrée, NON émise)
sinon → "preparing" → affichage synchrone → "confirmed"
        (échec d'affichage → "uncertain", place réservée 60 min)
        (métadonnées absentes → "unknown", compté en reserved)
```

`displayed` = `confirmed` avec `emitted_at > now − 60 min` (borne **stricte**). `masked` **n'occupe pas** de place. Un `Finding` est créé **même si** la notification est masquée.

### Effet d'un contrôle `VERIFY`

| Issue | Condition simulée | Effet sur `status` |
|---|---|---|
| `SUCCESS` | toutes les `checks` satisfaites, **et au moins une** | `OPEN → VERIFIED` **autorisé** (confirmation explicite de l'analyste) |
| `PARTIAL` | une partie seulement | **inchangé** |
| `FAILED` | aucune satisfaite **ou** aucune condition évaluable | **inchangé** — « un échec n'établit aucune correction » |

`REMEDIATED` n'est **jamais** produit par un contrôle.

## 7.6 Transitions de statut autorisées

| De | Vers | Condition | Qui |
|---|---|---|---|
| `OPEN` | `VERIFIED` | un `VerifyRun` `SUCCESS` existe **et** confirmation explicite | analyste (M-03) |
| `OPEN` | `ACCEPTED` | justification ≥ 20 caractères | analyste (M-05) |
| `VERIFIED` | `REMEDIATED` | justification ≥ 20 caractères | analyste (M-05) — **jamais automatique** |
| `VERIFIED` | `ACCEPTED` | justification | analyste |
| `ACCEPTED` | `OPEN` | réouverture justifiée | analyste |
| `REMEDIATED` | `VERIFIED` | réouverture justifiée si réapparition | analyste |
| tout autre | — | **refusé** `STATUS_TRANSITION_FORBIDDEN` | — |

Aucune transition n'est déclenchée par un événement Sentinel, un cycle, une remédiation appliquée ou l'assistant.

## 7.7 Invariants (chacun a un test dédié)

| # | Invariant | Test |
|---|---|---|
| I1 | Un Finding n'a jamais de `network_id` ; un événement n'a jamais de `session_id` | `test_ids` |
| I2 | `risk_score` est `None` pour tout Finding Sentinel et tout Inventory Observation | `test_scoring` |
| I3 | Le Worst Current Threat n'inclut que des `OPEN`, scorés, `≥ PROBABLE`, non-inventory | `test_scoring` |
| I4 | Aucun Finding créé par les 5 types non producteurs | `test_sentinel_events` |
| I5 | `host_ports_initialized` absent de toute réponse API et de toute notification | `test_sentinel_events` |
| I6 | Une notification `masked` est conservée et relisible | `test_notifications` |
| I7 | Jamais plus de 3 notifications par (`network_id`, `ip`) sur 60 min glissantes | `test_notifications` |
| I8 | Un `VERIFIED` exige un `VerifyRun` `SUCCESS` | `test_verify` |
| I9 | Aucun `REMEDIATED` sans action humaine justifiée | `test_verify` |
| I10 | `PARTIAL` et `FAILED` ne changent aucun statut | `test_verify` |
| I11 | Aucun secret dans réponse, preuve, journal ou rapport | `test_safety` |
| I12 | Aucune réponse d'API ne contient de score global ni de moyenne | `test_api_contract` |
| I13 | Les deux étiquettes sont fournies pour **toutes** les surfaces de P-15 | `test_api_contract` |
| I14 | Aucun fichier n'est un verbatim d'un fichier de `_audit/a4` | `test_knowledge_no_verbatim` |
| I15 | `explanation is None` ⇒ mention exacte « non documentée dans la Knowledge Base » | `test_api_contract` |

## 7.8 Schéma SQL (extrait normatif)

```sql
-- base session-<session_id>.db
CREATE TABLE assessment (
  session_id TEXT PRIMARY KEY, target TEXT, started_at TEXT, finished_at TEXT,
  state TEXT NOT NULL CHECK (state IN ('attente','en cours','termine','degrade','echec')),
  steps_json TEXT NOT NULL, modules_run_json TEXT NOT NULL);

CREATE TABLE host (
  session_id TEXT NOT NULL REFERENCES assessment(session_id),
  ip TEXT NOT NULL, mac TEXT, hostname TEXT,
  presence TEXT NOT NULL CHECK (presence IN ('observe','non_observe')),
  PRIMARY KEY (session_id, ip));

CREATE TABLE port_service (
  session_id TEXT NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL,
  protocol TEXT NOT NULL CHECK (protocol IN ('tcp','udp')),
  state TEXT NOT NULL CHECK (state IN ('ouvert','filtre','ferme','non_observe')),
  banner TEXT, service TEXT, version TEXT, detection_evidence TEXT,
  PRIMARY KEY (session_id, ip, port, protocol));

CREATE TABLE finding (
  id TEXT PRIMARY KEY, session_id TEXT NOT NULL, module TEXT NOT NULL, created_at TEXT NOT NULL,
  target_ip TEXT NOT NULL, target_port INTEGER, target_service TEXT, service_version TEXT,
  category TEXT NOT NULL, severity TEXT NOT NULL, confidence REAL NOT NULL, exposure TEXT NOT NULL,
  evidence_raw TEXT NOT NULL DEFAULT '', evidence_command TEXT NOT NULL DEFAULT '',
  rule_id TEXT, cve_refs_json TEXT NOT NULL DEFAULT '[]', cvss_score REAL,
  risk_score REAL,                      -- NULL = non applicable (Sentinel / inventaire)
  status TEXT NOT NULL CHECK (status IN ('open','verified','remediated','accepted')),
  remediation_cmd TEXT NOT NULL DEFAULT '', sentinel_event_id TEXT,
  CHECK (severity IN ('critical','high','medium','low','info')),
  CHECK (confidence IN (1.0, 0.85, 0.6)));

CREATE TABLE verify_run (
  id TEXT PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES finding(id),
  method TEXT NOT NULL, outcome TEXT NOT NULL CHECK (outcome IN ('SUCCESS','PARTIAL','FAILED')),
  checks_json TEXT NOT NULL, ran_at TEXT NOT NULL, status_effect TEXT NOT NULL);

-- base sentinel-<network_id>.db
CREATE TABLE network (
  network_id TEXT PRIMARY KEY CHECK (length(network_id) = 12),
  cidr TEXT NOT NULL, gateway_ip TEXT NOT NULL, gateway_mac TEXT NOT NULL,
  label TEXT, state TEXT NOT NULL, baseline_at TEXT, cycle_count INTEGER NOT NULL DEFAULT 0);

CREATE TABLE baseline (network_id TEXT PRIMARY KEY REFERENCES network(network_id),
  captured_at TEXT NOT NULL, hosts_json TEXT NOT NULL);

CREATE TABLE sentinel_event (
  id TEXT PRIMARY KEY, network_id TEXT NOT NULL REFERENCES network(network_id),
  type TEXT NOT NULL CHECK (type IN ('new_host','new_port','mac_change','host_not_observed',
       'host_recovered','port_not_open','scan_degraded','host_ports_initialized')),
  occurred_at TEXT NOT NULL, target_ip TEXT NOT NULL, target_port INTEGER,
  change_kind TEXT NOT NULL, detail_json TEXT NOT NULL,
  finding_id TEXT,                      -- NULL pour les 5 types sans Finding
  notification_json TEXT NOT NULL);     -- toujours présent, masked inclus

CREATE TABLE audit_entry (
  id TEXT PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, surface TEXT NOT NULL,
  action TEXT NOT NULL, target TEXT, effect_class TEXT NOT NULL, detail_json TEXT);
```

**Vérifications SQL qui rendent les invariants exécutables**
- `SELECT count(*) FROM finding WHERE module LIKE 'sentinel.%' AND risk_score IS NOT NULL` → **0**.
- `SELECT count(*) FROM sentinel_event WHERE type IN ('new_host','new_port','mac_change') AND finding_id IS NULL` → **0**.
- Tout événement dont `notification_json` n'a pas de clé `state` → **0**.

## 7.9 Volumétrie de référence (scénario S5)

| Entité | Cible |
|---|---|
| Hôtes | 6 |
| Ports / services | 34 |
| Findings | 27 (9 `security` scorés, 3 Sentinel non scorés, 5 `inventory`, 10 non éligibles) |
| Règles utilisées | 12 / 21 |
| Findings sans explication | 3 (types Sentinel — constat C5) |
| Événements Sentinel (7 jours virtuels) | 19 (dont 0 `host_ports_initialized` exposé) |
| Notifications | 11 demandées, 6 émises, 5 `masked` |
| Contrôles | 4 (2 `SUCCESS`, 1 `PARTIAL`, 1 `FAILED`) |

Ces chiffres sont des **cibles de scénario**, pas des mesures. S'ils diffèrent à l'implémentation, **le scénario est corrigé, pas les règles**.

---

# 8. Moteur : horloge, monde, cycles, contrôles

## 8.1 Les trois verbes, et pourquoi ils ne fusionnent jamais

| Verbe | Ce qu'il change | Ce qu'il ne fait jamais |
|---|---|---|
| **Modifier le monde** (`mutate-world`) | l'état fictif : un port s'ouvre, un hôte apparaît, une MAC change | exécuter un contrôle, changer un statut |
| **Contrôler** (`scan-sentinel`, `run-verify`) | le registre d'événements et de contrôles | modifier le monde, changer un statut sans validation |
| **Décider** (`apply-finding-status`) | un statut de Finding | être déclenché par autre chose qu'un humain |

C'est la séparation du produit (le scan observe, il ne modifie pas la cible) et c'est elle qui rend S4 correct : un `port_not_open` est une **observation**, pas une correction.

## 8.2 Horloge virtuelle

```python
class VirtualClock:
    SCALE_DEMO   = 60   # 1 s réelle = 60 s virtuelles
    SCALE_REVIEW = 1    # 1 s réelle = 1 s virtuelle (tests, revue)

    def now(self) -> datetime          # toujours UTC
    def advance(self, seconds: int)    # explicite
    def set(self, dt)                  # tests et rejeu
```

- Aucun module du moteur n'appelle `datetime.now()` : seul `clock.py` connaît le temps.
- L'horloge **n'avance pas toute seule** : deux exécutions du même scénario produisent les mêmes horodatages.
- Toute date affichée porte `virtuel` si elle diffère de plus de 24 h de l'heure système.
- La fenêtre de notification est exprimée en **minutes virtuelles** : c'est le seul moyen de démontrer le quota en quelques secondes.
- « 7 jours virtuels » se rejouent en ~3 minutes réelles à l'échelle démo. Le bouton `Avancer de 1 h` appelle `advance(3600)`.

## 8.3 Le monde fictif

```json
{
  "network": {"cidr": "192.0.2.0/24", "gateway_ip": "192.0.2.1",
              "gateway_mac": "02:00:5e:00:01:01", "label": "Réseau de démonstration"},
  "hosts": [
    {"ip": "192.0.2.21", "mac": "02:00:5e:00:15:21", "hostname": "demo-nas", "presence": "observé",
     "ports": [
       {"port": 445, "protocol": "tcp", "state": "ouvert", "service": "smb",
        "version": "SMB 1.0 (simulé)", "banner": "…",
        "detection_evidence": "négociation SMBv1 acceptée (simulée)"}
     ]}
  ],
  "traffic": [
    {"at": "T+0", "src": "192.0.2.44", "dst": "192.0.2.21", "protocol": "tcp",
     "dst_port": 445, "bytes": 12840, "state": "établie",
     "payload_excerpt": "----- (extrait tronqué, simulé)"}
  ]
}
```

**Contraintes dures**
- Adresses dans des plages de documentation RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) ou /24 privé explicitement étiqueté « démonstration ». Aucune adresse d'un réseau réel connu, aucun domaine existant.
- Toutes les MAC commencent par `02:` (bit local : non attribuable à un constructeur réel).
- Bannières et versions suffixées `(simulé)`.
- **Aucun paquet n'est construit** : ni `socket`, ni `struct`, ni en-tête IP.

**Six mutations, toutes explicites**

| Mutation | Effet | Événement attendu au prochain cycle |
|---|---|---|
| `open-port(ip, port)` | ajoute un service | `new_port` + Finding HIGH |
| `close-port(ip, port)` | retire le service | `port_not_open`, **aucun Finding** |
| `add-host(ip, mac)` | nouvel hôte | `new_host` + Finding MEDIUM |
| `change-mac(ip, mac)` | modifie la MAC | `mac_change` + Finding HIGH |
| `remove-host(ip)` | hôte injoignable | `host_not_observed`, **aucun Finding** |
| `restore-host(ip)` | hôte de nouveau joignable | `host_recovered`, **aucun Finding** |

## 8.4 Évaluation (`run-assessment`) — pipeline simulé

```
1. découverte            → hôtes visibles (lecture du monde)
2. scan TCP              → ports ouverts par hôte
3. scan UDP              → services UDP (SNMP…)
4. détection de services → service/version + indices ; peut ÉLEVER une sévérité
5. modules applicatifs   → smb_enum, dns_enum, default_creds, device_fingerprint, …
6. scoring               → risk_score par Finding, puis Worst Current Threat
```

- Chaque étape peut être `terminé`, `dégradé` ou `échec`. Une étape dégradée **n'implique jamais** une absence : elle produit `scan_degraded` au cycle suivant, et l'interface affiche `INCOMPLET`.
- Durées **fixes par scénario** : la démonstration est fluide sans être mensongère sur le fait qu'aucune mesure n'a eu lieu.
- Un nouveau `session_id` par exécution ; les sessions précédentes restent consultables. Aucune donnée de session ne fuit vers la base Sentinel.
- L'étape 4 est la seule qui touche à la sévérité : elle reprend la sévérité de l'entrée CVE (`critical` incluse) et ajuste la **confiance**, jamais le `risk_score`. Règle du produit reprise telle quelle : si la version n'est pas confirmée alors que l'entrée CVE l'exige, la confiance est forcée à `POSSIBLE` et le Finding sort du Worst Current Threat **même s'il est `CRITICAL`** (§3.4).

**Credentials (`default_creds`) — périmètre V1 uniquement** : FTP, SNMP, SSH (mot de passe), SMB (dictionnaire explicite obligatoire).

```
pour chaque service ciblé :
    tentatives[service] = 0 ; global = 0
    pour chaque candidat du profil (fictif) :
        si tentatives[service] >= 3     → arrêt service  ("budget de tentatives atteint")
        si tentatives[compte]  >= 2     → candidat suivant
        si global              >= 10    → arrêt global   ("budget global atteint")
        si temps(service)      >= 35 s  → arrêt service  ("budget de temps atteint")
        si temps(tentative)    >  10 s  → issue "délai dépassé" (comptée, jamais ignorée)
        issue ∈ {succès, refusé, délai dépassé, non testé}
```

- SSH : mémorisation d'empreinte (TOFU) simulée ; un changement d'empreinte **bloque** la tentative et produit un constat explicite.
- SNMP : 5 s sans retransmission.
- SMB : sans dictionnaire explicite, le module **ne teste rien** et l'interface affiche `non testé — aucun candidat fourni` (comportement réel du produit, README contredit par endroits : constat C3).
- Budgets épuisés ⇒ pas de Finding, mais « non testé » est **affiché** : absence de résultat ≠ absence de vulnérabilité.
- Aucun secret n'est conservé, y compris pour les profils fictifs : seule l'issue compte.

## 8.5 Cycle Sentinel — les 9 étapes réelles

| # | Étape | Écrit | N'écrit pas |
|---|---|---|---|
| 1 | Si aucune référence : capture (`host_ports_initialized`) | 1 événement, `state="whitelisted"`, `resolved=1` | aucun Finding, aucune notification, **aucun affichage** |
| 2 | Lecture de l'état courant | — | rien sur le monde |
| 3 | Calcul du diff | liste en mémoire | — |
| 4 | Type et cible de chaque écart | — | — |
| 5 | Whitelist ? | `details.whitelisted = true`, `state="whitelisted"` | pas de Finding |
| 6 | Événement persisté | 1 ligne `sentinel_event` | jamais d'écrasement |
| 7 | Type producteur ? | 1 `Finding` (3 types seulement) | aucun Finding pour les 5 autres |
| 8 | Décision de notification | `preparing` → `confirmed`/`masked`/`uncertain` | rien si `whitelisted` |
| 9 | Référence avancée + audit | `cycle_count += 1`, 1 `AuditEntry` | pas de nouveau `session_id` |

Deux points importants : la référence avance **après** le calcul (sinon le même écart serait re-signalé à chaque cycle) et le Finding est créé **avant** la décision de notification (une notification masquée laisse un Finding valide ; inverser ferait perdre des constats).

## 8.6 Diff et table de correspondance

```python
def diff(prev, cur) -> list[Change]:
    changes = []
    for ip in cur.hosts - prev.hosts:            changes.append(Change("new_host", ip))
    for ip in prev.hosts - cur.hosts:            changes.append(Change("host_not_observed", ip))
    for ip in cur.hosts & prev.hosts:
        if prev[ip].mac != cur[ip].mac:          changes.append(Change("mac_change", ip))
        for p in cur[ip].ports - prev[ip].ports: changes.append(Change("new_port", ip, p))
        for p in prev[ip].ports - cur[ip].ports: changes.append(Change("port_not_open", ip, p))
    if controle_inconclusif:                     changes.append(Change("scan_degraded", ip))
    return changes
```

| Type | Finding | `module` | `severity` | `category` | `confidence` | `risk_score` |
|---|---|---|---|---|---|---|
| `new_host` | **oui** | `sentinel.new_host` | MEDIUM | network | PROBABLE | **`None`** |
| `new_port` | **oui** | `sentinel.new_port` | HIGH | network | PROBABLE | **`None`** |
| `mac_change` | **oui** | `sentinel.mac_change` | HIGH | network | PROBABLE | **`None`** |
| `host_not_observed` | non | — | — | — | — | — |
| `host_recovered` | non | — | — | — | — | — |
| `port_not_open` | non | — | — | — | — | — |
| `scan_degraded` | non | — | — | — | — | — |
| `host_ports_initialized` | non | — | — | — | — | — |

Le `risk_score = None` est **le comportement du produit**, pas une limite de la démo. Conséquence assumée : les Findings Sentinel n'entrent jamais dans le Worst Current Threat, et l'écran Sentinel l'écrit noir sur blanc avec la liste des exclus.

## 8.7 Notifications et quota

```python
WINDOW = timedelta(minutes=60)
LIMIT  = 3

def summary(events, now, exclude):            # par hôte (ip)
    for e in events:
        if e.id == exclude: continue
        if e.notification.state == "whitelisted" or e.details.whitelisted is True:
            continue                          # hors quota
        if state == "confirmed" and emitted_at is not None:
            if emitted_at > now - WINDOW: displayed += 1     # borne STRICTE
        elif state == "masked":
            if decided_at > now - WINDOW: masked += 1        # n'occupe pas de place
        elif state == "preparing":   reserved += 1
        elif state == "uncertain":   reserved += 1  (jusqu'à reserved_until)
        else:                        reserved += 1 ; unknown += 1
    available = max(0, LIMIT - displayed - reserved)

def emit(event, change, afficher):
    row = summary(exclude=event.id).get(change.asset_ip)
    if row.available == 0:
        set(event, {"state": "masked", "decided_at": now})       # enregistrée, pas émise
        return False
    set(event, {"state": "preparing", "decided_at": now})        # marqueur durable
    try:
        afficher()                                               # synchrone, pas une file
        set(event, {"state": "confirmed", "decided_at": now, "emitted_at": now})
    except BaseException:
        set_uncertain(event)                                     # réservation 60 min
        raise
    return True
```

| Règle | Conséquence visible |
|---|---|
| `masked` ne consomme **pas** de place | Le compteur affiche `affichées + réservées / 3`, jamais « 3 événements » |
| Borne **stricte** à 60 min | Une émission à `now − 60 min` exactement libère sa place |
| `preparing` occupe une place **avant** l'affichage | Une notification en route ne peut pas être doublée |
| `uncertain` réserve 60 min | Un contrôle dégradé « coûte » une place : repli conservateur assumé |
| Date future / horloge reculée ⇒ place occupée | Comportement du produit, **conservé** et testé |
| `whitelisted` et `host_ports_initialized` hors quota | N'apparaissent jamais dans le compteur |
| Un changement whitelisté est **affiché** mais non notifié | Il reste visible, jamais silencieux |
| Un Finding est créé **même si** masqué | Le quota bride l'alerte, jamais la détection |
| Aucun bouton « renvoyer » | Renvoyer modifierait l'état du produit |

## 8.8 Contrôle VERIFY — trois issues, aucun autre chemin

```python
def run_verify(finding, world, clock) -> VerifyRun:
    checks = build_checks(finding, world)          # conditions dérivées du constat d'origine
    satisfied = sum(c.satisfied for c in checks)

    if len(checks) > 0 and satisfied == len(checks):
        outcome = "SUCCESS"
    elif satisfied > 0:
        outcome = "PARTIAL"
    else:
        outcome = "FAILED"                          # inclut le cas « aucune condition »

    effect = "open→verified (autorisé, confirmation requise)" if outcome == "SUCCESS" else "inchangé"
    return VerifyRun(..., outcome=outcome, status_effect=effect)
```

| Interdit | Mécanisme |
|---|---|
| `PARTIAL` → `VERIFIED` | `apply_status("VERIFIED")` exige `outcome == "SUCCESS"` **et** toutes les conditions satisfaites |
| `FAILED` → quoi que ce soit | aucun effet calculé |
| `REMEDIATED` automatique | aucune fonction du moteur n'écrit cette valeur |
| « réussi » sans condition évaluée | `len(checks) == 0` ⇒ `FAILED`, jamais `SUCCESS` |
| contrôle qui modifie le monde | `run_verify` reçoit une **vue en lecture seule** ; toute écriture lève `GuardViolation` |

Les trois cas sont décrits avec leurs états attendus en §9 (S5, S6, S7).

## 8.9 Remédiation — proposer, appliquer, contrôler

```
proposer(finding) →
    action      : description en langage clair (règle `defense` de la Knowledge Base)
    commande    : indicative, PREVIEW ONLY, préfixe « # indicatif — non exécutable »
    diff        : ce qui changerait dans le monde fictif
    risques     : régression possible, service interrompu, dépendances

appliquer(proposal, confirmation) →
    1. vérifier la case de confirmation + la recopie de l'identifiant du Finding
    2. appliquer la mutation au MONDE FICTIF uniquement
    3. marquer la proposition « appliquée à la simulation »
    4. exiger un contrôle VERIFY (bouton actif, non optionnel)
    5. le statut du Finding N'EST PAS modifié par l'application
```

Le point 5 est essentiel : appliquer une correction ne prouve rien. Seul le contrôle prouve — et encore, seulement en cas de `SUCCESS`. `REMEDIATED` reste une décision humaine, postérieure, justifiée.

## 8.10 Journal d'audit

Chaque commande laisse une `AuditEntry` : `at`, `actor`, `surface`, `action`, `target`, `effect_class`, `detail` (valeurs avant/après).

Non modifiable, non supprimable dans l'interface. La navigation et les filtres ne sont pas journalisés (bruit). Un changement de scénario est journalisé et **conserve** les entrées antérieures, marquées `scénario précédent : Sx`.

## 8.11 Ce que le moteur ne fera jamais — liste opposable

1. Ouvrir une socket, résoudre un nom, émettre un paquet.
2. Lancer une commande, un binaire, un script.
3. Calculer un score global, une moyenne, un pourcentage de santé.
4. Scorer un Finding Sentinel ou un Inventory Observation.
5. Créer un Finding depuis `port_not_open`, `host_not_observed`, `host_recovered`, `scan_degraded`, `host_ports_initialized`.
6. Exposer `host_ports_initialized`.
7. Changer un statut sans action humaine justifiée.
8. Écrire `REMEDIATED` automatiquement.
9. Conserver ou afficher un secret, même fictif.
10. Modifier les règles officielles depuis l'interface.

---

# 9. Scénarios S1 à S8

Un scénario est un **jeu de données + une chronologie**. Aucun chemin d'exécution hors scénario : au démarrage, la démo charge toujours un scénario explicite.

## 9.1 Pourquoi des scénarios plutôt qu'un mode libre

| Raison | Effet |
|---|---|
| Déterminisme | mêmes entrées ⇒ mêmes sorties, donc des tests stables |
| Couverture | chaque règle délicate (quota, `PARTIAL`, `scan_degraded`, type silencieux) a **son** scénario |
| Récit maîtrisé | la démonstration raconte une histoire choisie |
| Vérifiabilité | les états attendus sont écrits **avant** l'implémentation ; un écart est un défaut |

Le mode libre existe (six mutations), mais il est **toujours lancé depuis un scénario** : l'utilisateur part d'un état connu.

## 9.2 Schéma formel

```json
{
  "schema_version": "1.0",
  "id": "S4",
  "title": "Port fermé — la baisse du Worst Current Threat n'est jamais automatique",
  "purpose": "Démontrer que port_not_open ne crée aucun Finding et ne modifie pas le Worst Current Threat ; seul un VERIFY SUCCESS le fait baisser.",
  "tags": ["sentinel", "verify", "Q9", "§2.2"],
  "clock": {"start": "2026-11-12T09:00:00Z", "scale": "demo"},
  "world": { "network": { … }, "hosts": [ … ] },
  "steps": [
    {"at": "T+0m",  "kind": "assessment",   "params": {"target": "192.0.2.0/24", "modules": ["…"]}},
    {"at": "T+5m",  "kind": "sentinel_cycle"},
    {"at": "T+30m", "kind": "mutate",       "params": {"mutation": "close-port", "ip": "192.0.2.21", "port": 445}},
    {"at": "T+32m", "kind": "sentinel_cycle"},
    {"at": "T+40m", "kind": "verify",       "params": {"finding": "FD-1A2B3C4D", "scenario_outcome": "SUCCESS"}},
    {"at": "T+42m", "kind": "apply_status", "params": {"finding": "FD-1A2B3C4D", "to": "verified"}}
  ],
  "expected": {
    "findings": {"total": 9, "scored": 6, "non_scored_sentinel": 2, "inventory": 2},
    "worst_current_threat": {"display_id": "FD-1A2B3C4D", "risk_score": 80.5, "severity": "high"},
    "events": {"new_host": 0, "new_port": 0, "mac_change": 0, "host_not_observed": 0,
               "host_recovered": 0, "port_not_open": 1, "scan_degraded": 0},
    "notifications": {"emitted": 1, "masked": 0, "whitelisted": 0},
    "verify": [{"finding": "FD-1A2B3C4D", "outcome": "SUCCESS", "status_before": "open", "status_after": "verified"}],
    "assertions": ["aucun Finding créé pour port_not_open", "WCT inchangé après port_not_open",
                   "WCT plus bas après VERIFY SUCCESS"]
  }
}
```

**Champs obligatoires** : `id`, `title`, `purpose`, `tags`, `clock`, `world`, `steps`, `expected.assertions`. Un scénario sans assertion est **refusé au chargement**.
**`kind` autorisés** : `assessment`, `sentinel_cycle`, `mutate`, `verify`, `apply_status`, `propose_remediation`, `apply_remediation`, `whitelist_add`, `whitelist_remove`, `advance_clock`, `assert`.
**`params.scenario_outcome`** (uniquement sur `verify`) force l'issue attendue : c'est ce qui rend S5/S6/S7 reproductibles. Sans ce champ, l'issue est dérivée de l'état du monde (comportement par défaut en mode libre).

## 9.3 Tableau d'ensemble

| ID | Titre | Ce que le scénario prouve | Durée virtuelle |
|---|---|---|---|
| S1 | Réseau de référence sain | État initial ; deux natures de constats côte à côte | 1 h |
| S2 | Apparition d'un hôte et d'un port | 3 types producteurs → Findings non scorés ; quota | 2 h |
| S3 | Saturation du quota | 3 max / (réseau, IP) / 60 min **glissantes** ; `masked` conservée | 3 h |
| S4 | Port fermé | **`port_not_open` n'abaisse jamais le WCT** ; seul VERIFY `SUCCESS` le fait | 1 h |
| S5 | Contrôle réussi | `SUCCESS` → `VERIFIED` sur confirmation humaine | 1 h |
| S6 | Contrôle partiel | `PARTIAL` → statut **inchangé**, motif énuméré | 45 min |
| S7 | Contrôle échoué | `FAILED` → statut inchangé ; échec ≠ correction | 45 min |
| S8 | Évaluation dégradée et hôte non observé | `scan_degraded` sans Finding ; `NOT_OBSERVED ≠ ABSENT` | 4 h |

## 9.4 S1 — Réseau de référence sain

**Monde initial**

| IP | Nom | MAC | Ports ouverts | Note |
|---|---|---|---|---|
| `192.0.2.10` | `demo-fw` | `02:00:5e:00:10:01` | 22, 443/tcp | SSH version faible |
| `192.0.2.21` | `demo-nas` | `02:00:5e:00:15:21` | 139, 445/tcp | SMBv1 actif, partage inscriptible |
| `192.0.2.31` | `demo-ap` | `02:00:5e:00:1f:31` | 23/tcp, 161/udp | Telnet ouvert, SNMP `public` |
| `192.0.2.41` | `demo-srv` | `02:00:5e:00:29:41` | 80, 445, 3389/tcp | HTTP sans TLS, RDP exposé |
| `192.0.2.51` | `demo-printer` | `02:00:5e:00:33:51` | 80, 9100/tcp | Empreinte d'inventaire |

**Chronologie** : `T+0` évaluation → `T+5` premier cycle (capture de référence) → `T+60` second cycle.

**États attendus** : 11 Findings (6 `security` scorés, 0 Sentinel, 5 `inventory`) · 0 Finding sans explication · Worst Current Threat = `smb_v1_active` sur `192.0.2.21:445`, HIGH, `CONFIRMED`, `EXTERNAL` → `min(100, 70 × 1.00 × 1.15) = 80.5` · **0 événement exposé** (seul `host_ports_initialized` a eu lieu, silencieux).

**Assertions** : `/api/sentinel/events` renvoie 0 alors que la base contient un événement silencieux · le WCT vaut exactement `80.5` · les 5 `inventory` sont dans `/api/inventory` et absents du calcul.

## 9.5 S2 — Apparition d'un hôte et d'un port

| T | Action | Effet attendu |
|---|---|---|
| T+0 | évaluation | 5 hôtes, 11 Findings |
| T+5 | cycle | référence (silencieux) |
| T+10 | `add-host(192.0.2.61, 02:00:5e:00:3d:61)` + `open-port(192.0.2.61, 8080)` | monde modifié, **aucun contrôle** |
| T+12 | cycle | `new_host` + `new_port` → 2 Findings Sentinel, `risk_score = None` |
| T+15 | `change-mac(192.0.2.21, 02:00:5e:00:15:99)` | monde modifié |
| T+17 | cycle | `mac_change` → Finding HIGH non scoré |

**États attendus** : 3 événements producteurs · 3 Findings Sentinel (`MEDIUM`, `HIGH`, `HIGH`) · `risk_score` `None` · **WCT identique à S1 (80.5)** · 3 notifications (quota 3/3 sur `192.0.2.61`) · explication `null` → « non documentée dans la Knowledge Base » (C5).

**Assertions** : les 3 Findings ont `risk_score IS NULL` · le WCT **ne change pas** (test explicite, pas une observation) · aucun événement `host_ports_initialized` dans la réponse · la fiche d'un Finding Sentinel affiche `NON SCORÉ` et **aucun** bouton de scoring.

## 9.6 S3 — Saturation du quota

5 ouvertures de ports sur **le même hôte**, puis une sur un autre.

| T | Action | Événement | Notification | Compteur `192.0.2.41` |
|---|---|---|---|---|
| T+70 | `open-port(192.0.2.41, 8443)` | `new_port` | `confirmed` | 1/3 |
| T+80 | `open-port(192.0.2.41, 3306)` | `new_port` | `confirmed` | 2/3 |
| T+90 | `open-port(192.0.2.41, 5432)` | `new_port` | `confirmed` | 3/3 |
| T+95 | `open-port(192.0.2.41, 6379)` | `new_port` | **`masked`** | 3/3 (refus) |
| T+100 | `open-port(192.0.2.41, 9200)` | `new_port` | **`masked`** | 3/3 (refus) |
| T+105 | `open-port(192.0.2.31, 8081)` | `new_port` | `confirmed` — **autre IP**, compteur indépendant | 3/3 |
| T+132 | `open-port(192.0.2.41, 8082)` | `new_port` | **`confirmed`** — la place de T+70 est libérée (62 min) | 1/3 |

**États attendus** : 7 événements `new_port` · 5 notifications émises · 2 `masked` **toutes deux lisibles** · **7 Findings créés** (le quota n'empêche pas la création) · WCT inchangé.

**Assertions** : les 2 `masked` sont en base avec `reason="quota"` et `quota_used=3` · aucune notification supprimée ni réémise · compteurs indépendants par IP · fenêtre glissante sans réinitialisation manuelle · un Finding existe pour chaque `new_port`, y compris masqué.

## 9.7 S4 — Port fermé *(scénario corrigé)*

C'est le scénario qui répare l'erreur de la vision révision 2. Il démontre la séquence en **7 étapes**.

### La séquence

```
① baseline : 192.0.2.21:445 ouvert, SMBv1 actif → Finding FD-1A2B3C4D
              HIGH · CONFIRMED · EXTERNAL · score 80.5 · OPEN
② contrôle : le port 445 n'est plus ouvert dans le monde fictif  (close-port)
③ cycle Sentinel : événement port_not_open
      → AUCUN Finding créé
      → FD-1A2B3C4D reste OPEN, INCHANGÉ
      → Worst Current Threat INCHANGÉ (toujours 80.5)
④ l'interface l'affirme : « Un changement n'est pas une correction »
⑤ VERIFY ciblé → 3 conditions :
      (a) le port 445 ne répond plus ............................ satisfaite
      (b) aucune négociation SMBv1 acceptée ..................... satisfaite
      (c) le service SMB est réellement désactivé sur l'hôte .... satisfaite
⑥ issue SUCCESS → M-03 propose la confirmation → l'analyste confirme
      → FD-1A2B3C4D : OPEN → VERIFIED
⑦ recalcul : le Finding VERIFIED est exclu
      → nouveau WCT = rdp_exposed sur 192.0.2.41:3389
        HIGH · PROBABLE · EXTERNAL → min(100, 70 × 0.85 × 1.15) = 68.4
      → la baisse (80.5 → 68.4) est ATTRIBUÉE au contrôle, jamais au port_not_open
```

### Chronologie

| T | Action | État du Finding | WCT |
|---|---|---|---|
| T+0 | évaluation | `OPEN` | `80.5` |
| T+5 | cycle (référence) | `OPEN` | `80.5` |
| T+30 | `close-port(192.0.2.21, 445)` | `OPEN` | `80.5` |
| T+32 | cycle → `port_not_open` | **`OPEN`** | **`80.5`** |
| T+40 | `run-verify` → `SUCCESS` | `OPEN` (aucun effet automatique) | `80.5` |
| T+42 | `apply-status(verified)` | `VERIFIED` | **`68.4`** |

### États attendus

| Élément | Attendu |
|---|---|
| `port_not_open` | 1 événement, `finding_id = NULL`, notification `confirmed` |
| Findings créés par l'événement | **0** |
| WCT à T+32 | **identique** à T+5 (même `display_id`, même score) |
| Contrôle | 1 `VerifyRun`, `SUCCESS`, conditions 3/3 |
| Statut après le contrôle, **avant** confirmation | `OPEN` |
| Statut après confirmation | `VERIFIED` |
| `REMEDIATED` | **jamais attribué** |
| WCT après confirmation | `68.4`, avec la mention « baisse due au contrôle VERIFY » |

### Cinq assertions

1. Le WCT à T+32 **égale** celui de T+5 — test de non-régression sur l'erreur corrigée.
2. Aucun `Finding` n'a `sentinel_event_id` pointant vers l'événement `port_not_open`.
3. `run-verify` ne modifie pas `finding.status` (vérifié avant confirmation).
4. `apply-status(VERIFIED)` échoue avec `VERIFY_REQUIRED` si le `VerifyRun` `SUCCESS` est retiré (test négatif).
5. À aucun moment `status` ne vaut `remediated`.

> Le piège que ce scénario interdit : une implémentation paresseuse « recalculerait » le WCT après tout changement et afficherait une baisse à T+32 — une **fausse preuve de correction**. L'assertion n°1 existe pour l'attraper.

## 9.8 S5 — Contrôle réussi (`SUCCESS`)

Contexte : `smb_v1_active` sur `192.0.2.21:445` (HIGH, `CONFIRMED`, `EXTERNAL`, 80.5, `OPEN`).
Chronologie : `T+0` évaluation → `T+10` proposition → `T+15` application au monde fictif → `T+20` VERIFY → `T+22` confirmation.

| Étape | `status` | `proposal.state` | `outcome` | WCT |
|---|---|---|---|---|
| après application (T+15) | `OPEN` | `appliquée à la simulation` | — | `80.5` |
| après VERIFY (T+20) | `OPEN` | `appliquée à la simulation` | `SUCCESS` (3/3) | `80.5` |
| après confirmation (T+22) | `VERIFIED` | `contrôlée` | `SUCCESS` | `68.4` |

**Assertions** : `SUCCESS` exige 3/3 · le statut ne change qu'après M-03 + confirmation · `REMEDIATED` non attribué · le journal contient `monde_modifié`, `contrôle_exécuté`, `statut_modifié`.

## 9.9 S6 — Contrôle partiel (`PARTIAL`)

Le cas le plus dangereux : une correction **partielle** qui ressemble à une réussite.

Contexte : `ftp_plaintext` sur `192.0.2.41:21` (MEDIUM, `PROBABLE`, `EXTERNAL` → `45 × 0.85 × 1.15 = 44.0`, `OPEN`). L'analyste active FTPS **sur un seul des deux serveurs virtuels**.

| # | Condition | Satisfaite |
|---|---|---|
| 1 | le port 21 répond encore | ✅ |
| 2 | la négociation chiffrée (`AUTH TLS`) est acceptée | ✅ |
| 3 | plus aucun transfert en clair possible sur **toutes** les instances | ❌ |

→ `PARTIAL` (2/3).

| Élément | Attendu |
|---|---|
| `verify.outcome` | `PARTIAL` |
| `finding.status` après M-03 | **`OPEN`** — inchangé |
| WCT | **inchangé** (`44.0` si ce Finding est le maximum éligible) |
| Message | « Contrôle partiel : le statut reste inchangé. 2 conditions sur 3 satisfaites. » |
| Fiche F-06 | conditions ✅/❌ explicites, **aucune conclusion** |
| Bouton « marquer VERIFIED » | **absent** (pas grisé) |

**Assertions** : aucune transition possible depuis cet écran · `apply-status(VERIFIED)` renvoie `VERIFY_REQUIRED` car le dernier contrôle n'est pas `SUCCESS` · WCT identique avant/après.

> Le bouton est **absent**, pas grisé : un bouton grisé laisserait croire qu'un paramètre pourrait le débloquer — contraire à Q3.

## 9.10 S7 — Contrôle échoué (`FAILED`)

Contexte : `rdp_exposed` sur `192.0.2.41:3389` (HIGH, `PROBABLE`, `EXTERNAL` → 68.4, `OPEN`). L'hôte devient injoignable pendant le contrôle (`remove-host`).

Conditions : (1) port 3389 joignable ❌ (2) négociation RDP observée ❌ (3) politique NLA active ❌ → `FAILED` (0/3).

| Élément | Attendu |
|---|---|
| `outcome` | `FAILED` |
| `status` | **`OPEN`** |
| WCT | **inchangé** (68.4) |
| Message | « Le contrôle a échoué. Cela n'établit pas que la vulnérabilité a été corrigée. » |
| Événement concomitant | `host_not_observed` — **aucun Finding**, l'hôte n'est **pas** déclaré absent |
| Affichage de l'hôte | `NON OBSERVÉ` (jamais `ABSENT`) |

## 9.11 S8 — Évaluation dégradée et hôte non observé

| T | Action | Effet attendu |
|---|---|---|
| T+0 | évaluation avec `dns_enum` **en échec** | étape `dégradé`, `modules_run` incomplet |
| T+5 | cycle | `scan_degraded` (1 événement, **0 Finding**), notification `uncertain` |
| T+60 | `remove-host(192.0.2.51)` | monde modifié |
| T+62 | cycle | `host_not_observed` (0 Finding), notification `confirmed` |
| T+120 | `restore-host(192.0.2.51)` | monde modifié |
| T+122 | cycle | `host_recovered` (0 Finding) |

**États attendus** : 3 événements, **0 Finding** · complétude `4 / 5 modules`, badge `INCOMPLET` · `192.0.2.51` affiché `NON OBSERVÉ` avec « cela ne signifie pas que l'hôte est absent » · notification de `scan_degraded` = `uncertain`, jamais `confirmed` · **Findings préexistants sur l'hôte inchangés**, toujours `OPEN`, toujours dans le WCT le cas échéant.

**Assertions** : aucun des trois événements ne crée de Finding · la chaîne `absent` n'apparaît **nulle part** dans les réponses pour `host_not_observed` · un hôte non observé conserve ses Findings · le taux de complétude est calculé, **pas** présenté comme un score de sécurité.

---

# 10. Sentinel Monitor : comportements détaillés

## 10.1 Ce qu'est Sentinel, en une phrase

Sentinel compare **deux photographies** du réseau et **raconte les écarts**. Il ne sonde rien : il lit l'état produit par l'évaluation, le compare à la référence précédente, journalise l'écart, décide s'il mérite une alerte, et — pour trois types seulement — crée un Finding.

Trois conséquences : un écart n'est **pas** une vulnérabilité ; un Finding Sentinel est **non scoré** dans le produit ; Sentinel **ne corrige rien**, **ne score rien**, **n'efface rien**.

## 10.2 Machine à états du réseau

```
        ┌──────────┐  start   ┌──────────┐  pause   ┌──────────┐
        │  ARRÊTÉ  │ ───────► │  ACTIF   │ ───────► │ EN PAUSE │
        └──────────┘          └────┬─────┘ ◄─────── └──────────┘
             ▲                     │        reprise
             │ stop                │ cycle
             └─────────────────────┘
```

| État | Boutons | Ce qui est vrai |
|---|---|---|
| `ACTIF` | `Exécuter un cycle`, `Mettre en pause`, `Gérer la whitelist` | Les cycles produisent des événements |
| `EN PAUSE` | `Reprendre`, `Gérer la whitelist` | Aucun cycle possible ; l'état est figé |
| `ARRÊTÉ` | `Démarrer` | Aucune donnée perdue ; rien n'est supprimé |

- La pause ne crée **aucun** événement : une pause n'est pas un changement du monde.
- À la reprise, le premier cycle compare à la **dernière référence enregistrée**, pas à une nouvelle capture : les changements survenus pendant la pause sont donc détectés. C'est ce qui distingue une pause d'une réinitialisation.
- Un changement de scénario **réinitialise** le réseau : nouvel état, nouvelle référence, journal conservé et marqué.

## 10.3 Les 8 types — fiche complète

| Type | Nature | Finding | Sévérité | Couleur produit (`monitor_view`) | Couleur démo | Détail affiché |
|---|---|---|---|---|---|---|
| `new_host` | apparition | oui | MEDIUM | `yellow` | ambre | « Nouvel hôte observé : 192.0.2.61 » |
| `new_port` | apparition | oui | HIGH | `red` | rouge | « Port 8080/tcp ouvert sur 192.0.2.61 » |
| `mac_change` | modification | oui | HIGH | `red` | rouge | « Adresse MAC modifiée : …:21 → …:99 » |
| `port_not_open` | disparition | **non** | — | `cyan` | sarcelle | « Port 445 fermé » (le produit reformule `port N not open` → `Port N closed`) |
| `host_not_observed` | disparition | **non** | — | `magenta` | violet | « Hôte non observé » — **jamais** « absent » |
| `host_recovered` | apparition | **non** | — | `green` | vert | « Hôte de nouveau observé » |
| `scan_degraded` | incertitude | **non** | — | `bold magenta` | violet pointillé | « Contrôle incomplet » |
| `host_ports_initialized` | initialisation | **non** | — | *(non stylé)* | *aucun* | **rien : jamais affiché, jamais notifié** |

La démo conserve la **distinction** des couleurs du produit, pas les codes ANSI : chaque type garde une teinte propre, la couleur ne portant jamais l'information seule (icône + libellé systématiques).

## 10.4 Sémantique des 8 types — énoncée pour être opposable

| Type | Ce qu'il signifie | Ce qu'il ne signifie **jamais** |
|---|---|---|
| `new_host` | une adresse répond désormais | que l'hôte est légitime, ou malveillant |
| `new_port` | un service est désormais joignable | que le service est vulnérable |
| `mac_change` | l'adresse physique associée à l'IP a changé | qu'il y a usurpation |
| `port_not_open` | le port n'a pas répondu | que la vulnérabilité est corrigée |
| `host_not_observed` | l'hôte n'a pas répondu au contrôle | que l'hôte est éteint, retiré ou absent |
| `host_recovered` | l'hôte répond de nouveau | que la cause de l'indisponibilité est résolue |
| `scan_degraded` | le contrôle n'a pas pu conclure | qu'il n'y a rien à trouver |
| `host_ports_initialized` | référence initiale enregistrée | un événement à signaler à l'utilisateur |

## 10.5 Quota — ce que l'utilisateur voit

Pour chaque couple (réseau, IP) :

```
192.0.2.41 · 3 places sur 3 occupées (2 affichées, 1 réservée)
           → état du couple : « silence (quota/réserve) »
           → 2 notifications masquées conservées, consultables
```

| Champ affiché | Source |
|---|---|
| `affichées` | `confirmed` dont `emitted_at > now − 60 min` |
| `réservées` | `preparing` + `uncertain` (jusqu'à `reserved_until`) + `unknown` |
| `places disponibles` | `max(0, 3 − affichées − réservées)` |
| `masquées visibles` | `masked` dans la fenêtre — **affichées comme lignes**, jamais comptées comme places |
| état du couple | `disponible` / `réserve prudente` / `silence (quota/réserve)` |

**Cas limites, tous testés**

| Cas | Comportement attendu |
|---|---|
| Émission à exactement `now − 60 min` | place **libérée** (comparaison stricte) |
| Horloge reculée après une émission future | place **reste occupée** |
| `preparing` interrompue | devient `uncertain`, réserve 60 min |
| Cycle dégradé sur un hôte au quota plein | `masked` (pas `uncertain`) : la place manque avant la qualité du contrôle |
| Remise à zéro de la whitelist | aucun effet rétroactif |
| Changement de scénario | compteurs réinitialisés avec le réseau ; journal conservé |
| 4ᵉ notification sur un hôte | **toujours enregistrée**, `masked`, jamais supprimée |
| 4ᵉ notification sur un autre hôte | indépendante |

**Ce qui serait une faute** : compter les événements au lieu des émissions · réinitialiser le compteur à chaque cycle (fenêtre de 60 s au lieu de 60 min) · ne pas enregistrer une notification masquée · émettre en retard après expiration · offrir un réglage du quota.

## 10.6 Whitelist

| Forme | Effet | N'agit pas sur |
|---|---|---|
| `allow port <ip> <port>` | les changements de ce port ne produisent pas de Finding | les autres ports |
| `allow host <ip>` | tous les changements de cet hôte | les autres hôtes |
| `allow mac <ip> <mac>` | une association IP/MAC déclarée légitime | une autre MAC |

- Un changement whitelisté **reste un événement** (`resolved=1`) : jamais invisible. Affiché en ligne d'information, non notifié.
- Il ne consomme pas de place dans le quota.
- Il ne crée **aucun** Finding.
- Retirer une entrée n'a **aucun effet rétroactif**.
- La whitelist ne touche **jamais** les Findings existants ni le Worst Current Threat.

Dans la démo, la whitelist est modifiable (M-06) car c'est une **fonction du produit** ; le quota, lui, ne l'est pas. La distinction est délibérée : autoriser un changement est une décision d'analyste, changer la règle de notification n'en est pas une.

## 10.7 Relation avec le Worst Current Threat — énoncé opposable

| Situation | Effet sur le WCT |
|---|---|
| `new_host`, `new_port`, `mac_change` | **aucun** — Finding créé avec `risk_score = None` |
| `port_not_open` | **aucun** — aucun Finding créé |
| `host_not_observed`, `host_recovered`, `scan_degraded`, `host_ports_initialized` | **aucun** |
| Whitelist ajoutée ou retirée | **aucun** |
| Notification masquée | **aucun** |
| **VERIFY `SUCCESS` + confirmation humaine** | **baisse possible** : le Finding passe `VERIFIED` et sort du calcul |
| VERIFY `PARTIAL` / `FAILED` | **aucun** |
| Remédiation appliquée **sans** contrôle | **aucun** |

Deux phrases de l'interface, écrites pour être lues :
- P-02 : *« Les Findings Sentinel ne sont pas scorés dans SentinelX. Ils n'entrent donc jamais dans le Worst Current Threat. »*
- P-04 : *« Un changement n'est pas une correction. Seul un contrôle réussi peut modifier un statut. »*

Une phrase qui **n'existe pas** volontairement : *« Le risque a diminué »*. La baisse est toujours attribuée nommément à un contrôle et à sa date.

## 10.8 Les trois issues — la position du produit

Le VERIFY à trois issues est **absent du produit** ; la démo l'ajoute et l'étiquette. Mais `monitor_view.CHECK_OUTCOMES` contient déjà, en français, « Contrôle partiel, non enregistré comme réussi » et « Contrôle en échec, non enregistré comme réussi » (§3.5). La démo ne fait pas invention doctrinale : elle rend visible et actionnable une distinction déjà présente.

| Issue | Conditions | Statut | Bouton de confirmation | Message |
|---|---|---|---|---|
| `SUCCESS` | toutes satisfaites, **et au moins une** | `OPEN → VERIFIED` sur confirmation | présent | « Contrôle réussi. Le Finding peut passer à VERIFIED. » |
| `PARTIAL` | une partie satisfaite | **inchangé** | **absent** | « Contrôle partiel : le statut reste inchangé. 2 conditions sur 3 satisfaites. » |
| `FAILED` | aucune satisfaite, **ou** aucune évaluable | **inchangé** | **absent** | « Le contrôle a échoué. Cela n'établit pas que la vulnérabilité a été corrigée. » |

## 10.9 Constats produit et traitement dans la démo

Voir §4 (C4, C5, C6, C11, C12). La règle est constante : **la démo ne corrige jamais un comportement du produit pour faire joli**. Elle l'affiche, l'explique, le marque.

## 10.10 Quatre parcours d'utilisation complets

**« Qu'est-ce qui a changé cette nuit ? »** — P-01 → carte *Derniers changements* → P-04 onglet **Changements** → filtrer `24 h` → F-05 (diff avant/après) → S-05 (provenance). À aucun moment un statut n'est modifié.

**« Ce port fermé a-t-il corrigé quelque chose ? »** — P-04 → ligne `port_not_open` → F-05 affiche *« Aucun Finding n'est créé. Le Worst Current Threat est inchangé. »* → `Contrôler le Finding concerné` → M-02 → M-03. Le parcours se termine par une **décision**, pas une conclusion automatique.

**« Pourquoi aucune alerte pour cet hôte ? »** — S-02 → couple `192.0.2.41` en `silence (quota/réserve)` → détail : 2 affichées, 1 réservée, 2 masquées conservées. L'utilisateur comprend qu'il y a eu **5 événements** et **3 places**. Aucune action « renvoyer ».

**« L'hôte a disparu, est-il absent ? »** — P-06 → `192.0.2.51` en `NON OBSERVÉ` → *« Non observé ne signifie pas absent. L'hôte n'a pas répondu au dernier contrôle. »* → F-02 → historique de présence.

## 10.11 Ce que Sentinel ne fait jamais — liste opposable

1. Sonder, pinguer, se connecter, résoudre un nom.
2. Créer un Finding pour les 5 types non producteurs.
3. Afficher ou notifier `host_ports_initialized`.
4. Scorer un Finding Sentinel.
5. Modifier le statut d'un Finding (y compris `port_not_open`).
6. Faire baisser le Worst Current Threat sans VERIFY `SUCCESS`.
7. Supprimer ou réémettre une notification.
8. Rendre un changement whitelisté invisible.
9. Déclarer un hôte « absent ».
10. Conclure quoi que ce soit d'un contrôle partiel ou échoué.
11. Lancer un cycle automatiquement.
12. Permettre de régler le quota.

---

# 11. Assistant déterministe

L'assistant est **hybride dans sa conception, déterministe dans son exécution** (Q2). Un seul moteur est implémenté : le déterministe. Aucun modèle de langage, ni local ni distant.

## 11.1 Trois règles qui précèdent toute réponse

| Règle | Formulation | Mécanisme |
|---|---|---|
| **R1 — Ne rien créer** | Aucun `Finding`, score, statut ou whitelist créé ou modifié | `assistant/*` n'importe aucune fonction d'écriture ; test AST |
| **R2 — Ne rien affirmer sans donnée** | Chaque phrase factuelle porte une source citée ; sans source, la phrase n'existe pas | segments typés avec `source_ref` obligatoire ; le rendu **échoue** si une source manque |
| **R3 — Ne jamais conclure à la place de l'analyste** | Jamais « c'est corrigé », « c'est sain », « le risque a baissé » | bloc 4 « lecture interdite » **obligatoire** ; lexique interdit vérifié par test |

## 11.2 Architecture

```
question + surface courante
        ▼
  context.py  ──► Paquet de contexte (immuable, horodaté)
        ▼
  intents.py  ──► IntentSpec (intention + entité + état)
        ▼
  templates.py ─► Gabarit (segments typés, sources obligatoires)
        ▼
  render.py   ──► 7 blocs + sources + garde-fous de sortie
        ▼
   réponse (déterministe, reproductible octet pour octet)
```

| Module | Rôle | Interdit |
|---|---|---|
| `context.py` | construit le paquet depuis la surface et l'entité | deviner une entité absente |
| `intents.py` | reconnaît l'intention par règles (mots-clés normalisés + entité) | classer par « probabilité » |
| `templates.py` | gabarits **par (intention, type d'entité, état)** | un gabarit générique tous usages |
| `render.py` | assemble, vérifie sources, applique le lexique interdit | produire du texte libre |
| `explainer.py` | interface `Explainer` + `DeterministicExplainer` | tout autre implémenteur |

**Déterminisme vérifié** : deux appels avec le même contexte produisent des **octets identiques**.

## 11.3 Paquet de contexte

```json
{
  "surface": "F-01",
  "entity_kind": "finding",
  "entity_id": "FD-1A2B3C4D",
  "network_id": null,
  "session_id": "sentinel-run-3f6c…",
  "virtual_now": "2026-11-12T09:41:00Z",
  "data_age": {"known": true, "since": "2026-11-12T09:15:00Z"},
  "payload": { "…projection en lecture du Finding…" },
  "related": { "host": "192.0.2.21", "port": 445,
               "rule": "smb_v1_active", "events": ["…"], "verify": [] },
  "constraints": { "scored": false, "scorable": false, "explanation": null,
                   "status": "open", "wct_eligible": false }
}
```

`constraints` est la clé de la fidélité : c'est le **moteur** qui dit « ce Finding n'est pas scoré et ne peut pas l'être », et l'assistant se contente de le **traduire en français**. Aucune règle métier n'est dupliquée dans l'assistant.

Si le contexte est insuffisant, l'assistant **ne répond pas** : il demande de préciser (§11.7).

## 11.4 Les 7 blocs — structure de toute réponse

| # | Bloc | Contenu | Obligatoire |
|---|---|---|---|
| 1 | **Contexte** | surface, entité, âge de la donnée, horizon temporel | oui |
| 2 | **Constat** | ce que les données disent, valeurs exactes (sévérité, score ou `—`, confiance, statut, cible) | oui |
| 3 | **Lecture autorisée** | ce que l'on peut en déduire, prudemment | oui |
| 4 | **Lecture interdite** | ce qu'on **ne peut pas** conclure — et pourquoi | **oui (signature)** |
| 5 | **Actions possibles** | 1 à 3 actions, chacune avec sa surface et sa modale | oui (peut être « aucune ») |
| 6 | **Sources** | identifiants, règles, types d'événements, horodatages | oui, ≥ 1 |
| 7 | **Limites** | ce qui manque, ce que la démo ne peut pas savoir | oui |

Un bloc vide n'est pas supprimé : il affiche « sans objet » avec la raison.

## 11.5 Les 9 intentions

| ID | Intention | Déclencheurs | Contexte requis | Réponse |
|---|---|---|---|---|
| `I1` | Expliquer un constat | « pourquoi », « ça veut dire quoi » sur F-01/F-08 | un `Finding` | `what/attack/defense` **ou** « non documentée » |
| `I2` | État Sentinel | « où en est », « combien d'alertes » | un `Network` | compteurs, WCT, exclus, quota |
| `I3` | Pourquoi pas d'alerte | « aucune alerte », « pourquoi rien » | un hôte + historique | quota, whitelist, type non producteur |
| `I4` | Lire un changement | « qu'est-ce qui a changé » | un événement | diff, effet (0 ou 1 Finding) |
| `I5` | État d'évaluation | « est-ce complet », « qu'est-ce qui a échoué » | une session | complétude, étapes dégradées |
| `I6` | Lire un contrôle | « le contrôle a-t-il réussi » | un `VerifyRun` | issue, conditions, effet réel |
| `I7` | Identifier un hôte | « c'est quoi cet appareil » | un hôte | empreinte, indices, confiance, prudence |
| `I8` | Capacité produit | « est-ce que ça existe dans SentinelX » | aucune entité | les deux attributs + roadmap |
| `I9` | Hors périmètre | question ouverte, prédiction, comparaison externe | — | refus explicite + propositions |

Aucune intention ne produit de texte libre : chaque gabarit a des variantes par état.

## 11.6 Trois réponses complètes, mot pour mot

Ces exemples sont **normatifs** : ils servent de tests dorés. Le texte est généré par gabarit, pas écrit à la main dans le rendu.

### `I1` sur un Finding scoré — `FD-1A2B3C4D`, `smb_v1_active`

> **Contexte** — Vous consultez le Finding `FD-1A2B3C4D` sur `192.0.2.21:445`, produit par le module `smb_enum` lors de l'évaluation `SR-3F6C` du 12/11/2026 à 09:15 (virtuel). Données à jour.
>
> **Constat** — `SMBv1` est actif sur ce service. Sévérité `HIGH`, catégorie `service`, confiance `CONFIRMED`, exposition `EXTERNAL`, statut `OPEN`. `risk_score = 80.5` (barème 70 × confiance 1.00 × exposition 1.15, plafonné à 100). Ce Finding est actuellement le **Worst Current Threat** du réseau.
>
> **Lecture autorisée** — Une négociation SMBv1 a été acceptée et l'information a été obtenue directement du service. Un protocole obsolète est donc bien exposé sur le réseau évalué, ce qui constitue un point d'entrée documenté.
>
> **Lecture interdite** — On ne peut pas en déduire que le réseau est compromis, ni qu'un accès a eu lieu : aucun journal d'authentification n'est collecté par SentinelX, et aucun test d'exploitation n'est exécuté.
>
> **Actions possibles** — (1) `Proposer une remédiation` (P-12, M-04), suivie d'un contrôle obligatoire ; (2) `Exécuter un contrôle` (M-02) si une correction a déjà été appliquée ; (3) `Accepter le risque` (M-05), avec justification obligatoire.
>
> **Sources** — Finding `FD-1A2B3C4D` · règle `smb_v1_active` · `evidence.command` du module `smb_enum` · `core/risk_scorer.py` (barème) · évaluation `SR-3F6C`.
>
> **Limites** — La règle d'explication de cette Knowledge Base est rédigée pour la démonstration. Aucune analyse de configuration réelle de l'hôte n'a été effectuée.

### `I1` sur un Finding Sentinel — `FD-7E4D0A19`, `sentinel.new_port`

> **Contexte** — Vous consultez le Finding `FD-7E4D0A19`, produit par Sentinel le 12/11/2026 à 09:32 (virtuel) sur `192.0.2.61:8080`, réseau `NET-4b1f7c02a9d3`. Données à jour.
>
> **Constat** — Sentinel a observé l'apparition du port `8080/tcp` lors du cycle n°3. Sévérité `HIGH`, catégorie `network`, confiance `PROBABLE`, statut `OPEN`. `risk_score` n'est **pas calculé** : les Findings produits par Sentinel conservent `risk_score = None` dans SentinelX. Explication : **non documentée dans la Knowledge Base** pour ce type.
>
> **Lecture autorisée** — Un service supplémentaire est joignable sur cet hôte depuis la dernière référence. Le changement a été détecté par comparaison d'états, sans interrogation du service.
>
> **Lecture interdite** — On ne peut pas en déduire que ce service est vulnérable : Sentinel compare des états, il n'évalue pas de configuration. Ce Finding **n'entre pas** dans le Worst Current Threat, non par oubli mais par conception ; il ne peut pas non plus être scoré depuis l'interface.
>
> **Actions possibles** — (1) `Lancer une évaluation` (M-01) pour obtenir des constats scorés sur ce service ; (2) `Voir les changements` (P-04) ; (3) `Ajouter à la whitelist` (M-06) si ce port est attendu.
>
> **Sources** — Finding `FD-7E4D0A19` · événement `new_port` du 12/11/2026 09:32 · référence `host_ports_initialized` du cycle n°1 (non affichée) · `sentinel/alerting.py` (table de sévérités) · `core/risk_scorer.py` (exclusion).
>
> **Limites** — L'absence de règle d'explication pour les 3 types Sentinel est un constat documenté du produit (C5), non corrigé par la démo.

*(Le bloc 2 cite l'initialisation de référence comme source sans jamais en faire un événement affichable : la mention « non affichée » est imposée par le gabarit.)*

### `I3` — « Pourquoi aucune alerte pour 192.0.2.41 ? »

> **Contexte** — Vous consultez l'hôte `192.0.2.41` sur le réseau `NET-4b1f7c02a9d3`, fenêtre des 60 dernières minutes virtuelles.
>
> **Constat** — 5 événements `new_port` ont été enregistrés sur cet hôte. 2 notifications ont été affichées, 1 place est réservée, 2 notifications sont **masquées** mais conservées. Le couple (réseau, IP) est en état `silence (quota/réserve)`.
>
> **Lecture autorisée** — Le silence ne vient pas d'une absence de changement : les 5 événements existent et 5 Findings ont été créés. Il vient de la limite de 3 notifications par couple (réseau, IP) sur 60 minutes glissantes.
>
> **Lecture interdite** — On ne peut pas en déduire que ces changements sont moins importants, ni qu'ils ont été ignorés : une notification masquée conserve son événement, son Finding et sa trace. Aucun score n'est calculé : le quota ne hiérarchise rien.
>
> **Actions possibles** — (1) `Consulter les notifications masquées` (S-02) ; (2) `Voir les événements` (P-03, filtre sur cet hôte) ; (3) `Contrôler un Finding` (M-02).
>
> **Sources** — 5 événements `new_port` du 12/11/2026 09:20 à 09:45 (virtuels) · `sentinel/notifications.py` (`LIMIT=3`, `WINDOW=60 min`) · Findings `FD-…`.
>
> **Limites** — Le quota ne peut pas être modifié depuis l'interface : c'est une règle du produit, pas un réglage.

## 11.7 Refus, imprécision, silence

| Situation | Comportement | Exemple |
|---|---|---|
| Question ouverte (« suis-je attaqué ? ») | refus + propositions | « Je ne peux pas répondre : SentinelX n'analyse pas de trafic à la recherche d'attaques, et la démonstration ne contient aucune donnée réelle. Je peux vous montrer les changements observés, l'état des contrôles ou le Worst Current Threat. » |
| Prédiction | refus | « Aucune projection n'est possible : le produit ne modélise pas d'évolution. » |
| Comparaison externe | refus | « Aucune donnée de comparaison externe n'existe dans le produit. La sévérité affichée est celle du barème interne. » |
| Entité absente du contexte | demande de précision | « Je ne vois pas de Finding sélectionné. Ouvrez une fiche (F-01) ou précisez un identifiant `FD-…`. » |
| `Explanation = None` | dit « non documentée », s'arrête | « Aucune règle d'explication n'existe pour ce type. Je ne complète pas cette information. » |
| Donnée ancienne (> 24 h) | le signale en tête | « Attention : ces données datent du 10/11/2026 (virtuel). » |
| Contrôle `PARTIAL`/`FAILED` | refuse toute conclusion | « Le contrôle n'a pas conclu. Aucune conclusion sur l'état du service n'est possible. » |
| Question sur une capacité V2/V3 | répond avec les deux attributs | « Cette capacité est `ABSENTE` du produit. Le prototype en propose une réalisation simulée : cela ne préjuge pas de la roadmap V2/V3. » |

Aucune de ces réponses n'est une excuse vague : chacune dit *pourquoi*, *ce qui manque*, et *ce qui est possible à la place*.

## 11.8 Perspective « modèle de langage local » — documentée, non implémentée

**Forme que cela prendrait**

```
        Explainer (interface)
        ├── DeterministicExplainer   ← seule implémentation active
        └── LocalModelExplainer      ← non implémenté, non installé
                ├── reçoit le MÊME paquet de contexte
                ├── reçoit une liste blanche de faits déjà vérifiés
                ├── produit un texte de mise en forme
                └── passe par le même vérificateur de sortie
```

Le point structurant : **le modèle ne produirait aucun fait**. Il reformulerait des faits extraits du contexte, filtrés par les mêmes garde-fous. Sans cela, ce serait un générateur d'affirmations non sourcées — ce que Q2 interdit.

**Ce que cela apporterait** : réponses plus fluides sur des questions composées ; reformulation adaptée au niveau de l'utilisateur ; meilleure compréhension des formulations variées. **Mais** peu ou pas d'amélioration sur les questions inédites : la limite est la donnée, pas la formulation.

**Ce que cela coûterait**

| Coût | Détail |
|---|---|
| **Perte de déterminisme** | deux appels, deux textes : incompatible avec les tests dorés et avec « comportement déterministe autonome » |
| **Affirmation non sourcée** | risque principal ; atténuable par vérification de sortie, jamais supprimable |
| **Poids et licence** | plusieurs centaines de Mo à plusieurs Go, avec **sa propre licence** : la question de provenance se reposerait |
| **Ressources** | un modèle local impose un téléchargement — donc **une connexion réseau**, interdite |
| **Auditabilité** | un texte généré est plus difficile à défendre qu'un gabarit, dans un outil de sécurité |
| **Surface d'attaque** | prompt injection depuis des données affichées (bannières, extraits) : risque réel |

**Six conditions qui rendraient la chose acceptable** : paquet de contexte et vérificateur de sortie **identiques** au mode déterministe · le modèle ne produit **aucun** fait · un mode strict reste **par défaut** · les tests dorés restent en mode strict, le mode modèle n'a que des tests de propriétés · le modèle est fourni par l'utilisateur, licence vérifiée, aucun téléchargement par la démo · interdiction maintenue de créer un Finding, attribuer un score, changer un statut, proposer une action destructive, conclure à une correction.

**Décision actuelle : aucune intégration.** Le mode déterministe couvre les 9 intentions identifiées.

## 11.9 Ce que l'assistant ne fera jamais

1. Créer, modifier ou supprimer un `Finding`, un statut, un score, un événement, une whitelist.
2. Attribuer un `risk_score` à un Finding Sentinel ou d'inventaire.
3. Calculer un score global ou une moyenne.
4. Conclure à une correction, à une absence, ou à une intrusion.
5. Inventer une explication quand `Explanation = None`.
6. Répondre sans citer au moins une source.
7. Produire du texte identique pour deux contextes différents.
8. Proposer une action qui n'existe pas dans l'interface.
9. Sortir du périmètre des 9 intentions sans le dire.
10. Utiliser un modèle de langage, local ou distant.

---

# 12. Direction visuelle et maquettes

## 12.1 Intentions

| Intention | Traduction | À éviter |
|---|---|---|
| **Densité maîtrisée** | 4 tailles typographiques, 3 niveaux de surface, une seule couleur d'accent | cartes flottantes partout, ombres larges |
| **Sobriété** | fond sombre neutre, couleur réservée au sens | néons, dégradés, effets « hacker » |
| **Preuve visible** | chaque chiffre a une source ou un accès | chiffres orphelins, pourcentages sans dénominateur |
| **Deux étiquettes distinctes** | produit et prototype visuellement séparés | badge composite unique, mention en pied de page |
| **Aucun score global** | barres de comptage, jamais de jauge | anneau de score, « santé réseau », note sur 100 |
| **Le texte porte le sens** | couleur + icône + libellé | couleur seule |

## 12.2 Jetons de design

```css
:root{
  --bg-0:#0B0E11;  --bg-1:#11161B;  --bg-2:#171D24;  --bg-3:#1F2730;
  --line:#25303A;  --line-strong:#36434F;
  --fg-0:#E8EEF4;  --fg-1:#A9B7C4;  --fg-2:#74848F;  --fg-3:#4E5C68;
  --accent:#3EA6D8; --danger:#E5534B; --warn:#F0932B; --ok:#2FA36B; --info:#5B8DEF; --muted:#8A98A5;
  --mono: ui-monospace,"SF Mono","Cascadia Mono",Menlo,Consolas,monospace;
  --ui: system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
}
```

**Sévérités** — teinte + fond très sombre + icône + libellé :

| Sévérité | Texte | Fond | Icône | Libellé |
|---|---|---|---|---|
| `CRITICAL` | `#FF6B6B` | `#2A1416` | ▲▲ | Critique |
| `HIGH` | `#F0932B` | `#2A1D10` | ▲ | Élevée |
| `MEDIUM` | `#E8C34A` | `#262111` | ◆ | Moyenne |
| `LOW` | `#5B8DEF` | `#141D2B` | ● | Faible |
| `INFO` | `#8A98A5` | `#1A2028` | ○ | Information |

**Statuts** : `OPEN` ambre · `VERIFIED` vert · `REMEDIATED` sarcelle · `ACCEPTED` violet — chacun avec une **forme** distincte (contour plein / plein / double contour / pointillé) pour rester lisible sans couleur.

**Étiquettes produit / prototype** — deux formes distinctes, jamais une seule : `EXISTE` contour fin plein · `ABSENT` contour **pointillé** · `HORS PÉRIMÈTRE V1` pointillé + hachure · `CONSTAT À EXAMINER` contour ambre + ⚠ · `RÉEL SIMULÉ` pastille pleine en second plan. Les deux attributs sont affichés sur **deux lignes séparées**.

**Typographie** : aucune police distante (pas de CDN, pas de `@font-face` externe) — la pile système suffit et garantit un rendu immédiat hors ligne. Échelle `11 / 13 / 15 / 19 / 26 / 34 px`. Chiffres et identifiants en mono avec `tabular-nums`.

**Espacement** `4/8/12/16/24/32/48` · **rayons** `2px` (badges), `4px` (cartes), `6px` (modales) · **élévation** : bordures uniquement, une seule ombre réservée aux modales.

## 12.3 Structure d'écran

```
┌──────────────────────────────────────────────────────────────────────────┐
│ TOPBAR 56px : logo · réseau (NET-…) · horloge VIRTUELLE · scénario        │
│                    · cloche (S-02) · historique (S-07) · ? (S-01)        │
├────────────┬─────────────────────────────────────────────────────────────┤
│ SIDEBAR    │ BREADCRUMB · TITRE · ACTIONS PRIMAIRES                      │
│ 236px      │ ┌─────────────────────────────────────────────────────────┐ │
│ 5 groupes  │ │  CONTENU (grille 12 colonnes, gouttière 16px)            │ │
│ repliable  │ └─────────────────────────────────────────────────────────┘ │
└────────────┴─────────────────────────────────────────────────────────────┘
```

- L'horloge indique `virtuelle` en micro-libellé : sans cela, un utilisateur croirait à l'heure réelle — exigence d'honnêteté.
- Menu en 5 groupes (`Surveillance`, `Technique`, `Constats`, `Action`, `Système`), repliable ; état conservé dans l'URL.
- Largeur maximale du contenu : **1600 px**.
- **Barre de statut basse (24 px)** : `Simulation locale — aucune opération réseau` + garde-fous actifs. Seule mention répétée à chaque écran, et voulue.

## 12.4 Composants

| Composant | Règles |
|---|---|
| **Tableau** | densité 32 px ; en-têtes triables avec indicateur ; colonnes numériques à droite ; sévérité première colonne ; pagination `50/100/tout` |
| **Badge** | 4 variantes (sévérité, statut, type d'événement, étiquette produit) ; jamais plus de 3 par ligne |
| **Barre segmentée** | remplace toute jauge : segments proportionnels au **comptage**, valeurs absolues affichées |
| **Frise** | marqueurs distincts par type, date virtuelle en clair |
| **Diff** | deux colonnes, `−` et `+`, aucune couleur seule |
| **Tiroir** | 440 px, ombre latérale, `Échap`, focus **non** piégé (le fond reste utilisable) |
| **Modale** | 600 px, focus piégé, action destructrice en second plan, jamais en accent |
| **État vide** | icône + **explication de la cause** + une action utile |
| **Encart de garde-fou** | bandeau ambre fin, texte court, sans bouton |

## 12.5 Règles de graphiques — opposition explicite aux tableaux de bord

| Interdit | Pourquoi | Remplacé par |
|---|---|---|
| Jauge, anneau, cadran de score | suggère une note de sécurité globale | liste des Findings + comptages |
| Ligne de tendance, projection | suggère une prédiction que le produit ne fait pas | frise d'événements datés |
| Camembert | illisible > 3 parts, agrège abusivement | barres horizontales avec valeurs |
| Pourcentage sans dénominateur | trompeur | `4 / 5 modules`, `3 places sur 3` |
| Échelle normalisée 0–100 | crée une note implicite | axe = nombre de Findings |
| Couleur sans libellé | inaccessible | icône + texte |

**Deux graphiques autorisés, et eux seuls** : barres de comptage par sévérité (5 barres, valeurs absolues) et frise temporelle des événements. Tout le reste est un tableau — dans un outil de constat, un tableau est plus honnête qu'un graphique.

## 12.6 Accessibilité

Contraste texte ≥ 4.5:1, composants ≥ 3:1 · focus `2px solid var(--accent)` jamais supprimé · `prefers-reduced-motion` ⇒ 0 animation · navigation clavier complète, modales piégées · chaque badge porte icône **et** mot (test en niveaux de gris prévu) · `aria-live="polite"` sur le centre de notifications, `assertive` réservé aux refus.

## 12.7 Conventions de rédaction

**Lexique interdit** (vérifié par test sur toutes les chaînes servies) :

| Interdit | Remplacer par |
|---|---|
| « sécurisé », « protégé », « sûr » | « observé », « conforme au contrôle » |
| « score de sécurité », « niveau de risque global » | « Worst Current Threat », « nombre de Findings par sévérité » |
| « vulnérabilité corrigée » (sans contrôle) | « correction proposée », « contrôle réussi », « statut VERIFIED » |
| « absent » sans qualification | « non observé » |
| « intrus », « attaque détectée » | « changement observé » |
| « en temps réel » | « au dernier cycle » |
| « automatique » pour un statut | « sur confirmation » |

**Formulations imposées** : *« Un changement n'est pas une correction. »* (P-04) · *« Non observé ne signifie pas absent. »* (F-02, P-06) · *« Un contrôle partiel ou échoué n'est pas enregistré comme réussi. »* (M-03) · *« Les Findings Sentinel ne sont pas scorés. »* (P-02) · *« Ces indicateurs ne sont pas agrégés. »* (P-01).

## 12.8 Maquettes livrées

`maquettes/index.html` — fichier **autonome** : styles et scripts en ligne, SVG inline, **aucune ressource externe**. Huit écrans navigables : P-01 Tableau de bord · P-02 Sentinel (WCT + exclus) · P-03 Journal d'événements · P-04 Changements & contrôles (parcours S4) · P-08 Findings + F-01 · P-15 Périmètre · module Assistant · modales M-03 (« contrôle partiel ») et M-04 (remédiation).

Ce sont des **références visuelles**, pas l'implémentation : aucune logique métier n'y est dupliquée, les valeurs sont écrites en dur et cohérentes avec §9. Chaque maquette affiche en en-tête le nom de l'écran, la route et **les deux étiquettes** — l'étiquetage fait partie de la maquette, il n'est pas ajouté après.

---

# 13. Découpage en lots et plan de tests

## 13.1 Vue d'ensemble

Huit lots. **Aucune fonctionnalité n'est supprimée pour tenir un nombre de lots** : les lots sont déduits de l'inventaire d'écrans, pas l'inverse. Chaque lot est livrable, démontrable et testé indépendamment.

```
L0 Socle ──► L1 Constats ──► L2 Sentinel ──► L3 Contrôles ──► L4 Remédiation & rapports
                                   │                │                    │
                                   └────────────────┴────────► L5 Transparence
                                                                        │
                                                                        ▼
                                                                  L6 Assistant
                                                                        │
                                                                        ▼
                                                                  L7 Finition
```

| Lot | Titre | Surfaces | Dépend de | Charge |
|---|---|---|---|---|
| **L0** | Socle : serveur local, garde-fous, coquille | P-00, coquille P-01 | — | 1 |
| **L1** | Constats : monde, évaluation, Findings, inventaire | P-01, P-05…P-09 · F-01…F-03, F-07, F-08 · S-03, S-04 | L0 | 3 |
| **L2** | Sentinel : événements, notifications, quota | P-02, P-03, P-04 (changements) · F-04, F-05 · S-02, S-06 | L1 | 3 |
| **L3** | Contrôles : VERIFY, statuts, décisions | P-04 (contrôles) · F-06 · M-02, M-03, M-05, M-07 | L2 | 2 |
| **L4** | Remédiation et rapports | P-12, P-13 · F-11, F-12 · M-04 | L3 | 2 |
| **L5** | Transparence : périmètre, règles, audit, traçabilité | P-15…P-18 · F-13 · S-05, S-07 | L1–L3 | 2 |
| **L6** | Assistant déterministe | P-14 · S-01 | L1–L5 | 2 |
| **L7** | Finition : accessibilité, états, performance, revue | toutes | L6 | 1 |

**L2 dépend de L1** parce qu'un événement Sentinel doit pointer vers un Finding réel créé par une évaluation : sans cela, la démonstration serait une suite d'écrans sans données.

## 13.2 L0 — Socle

**Livrable** : `run.py`, serveur `127.0.0.1`, en-têtes CSP, routes statiques sûres, garde-fous, stockage, coquille (topbar, sidebar, barre de statut), écran de connexion.

**Critères d'acceptation**
1. `python3 run.py` démarre sans dépendance, en < 2 s, et n'écoute **que** sur `127.0.0.1` (vérifié par `ss -ltnp` dans le test).
2. Une tentative de liaison sur une autre adresse échoue au démarrage avec un message explicite.
3. `socket.connect`, `subprocess.*`, `urlopen` lèvent `GuardViolation`.
4. Chaque réponse porte les en-têtes de §6.5 ; aucune URL absolue dans `web/` (test AST).
5. Aucun accès fichier hors `runtime/` (test avec `../../etc/passwd`).
6. `Ctrl+C` arrête proprement ; les deux bases sont refermées.
7. La coquille s'affiche à 1280 px et 1920 px sans débordement horizontal.

## 13.3 L1 — Constats

**Livrable** : `knowledge/*.json` (21 règles, 29 ports, 11 CVE, 10 profils fictifs) · S1 · `engine/{world,assessor,scoring,findings,inventory}` · API de lecture · P-01, P-05…P-09 · F-01…F-03, F-07, F-08 · S-03, S-04.

**Critères d'acceptation**
1. Le tableau de bord affiche **quatre indicateurs séparés** et **aucun** agrégat (test DOM + test d'API refusant `global_score`).
2. Le WCT est calculé par la fonction du moteur, avec trois cas de test (`POSSIBLE` exclu, inventory exclue, Sentinel exclue).
3. `risk_score` est `null` pour tout `sentinel.*` et `device_fingerprint`, avec `non_scored_reason` explicite.
4. Les Inventory Observations sont **des Findings filtrés** : `/api/inventory` est un sous-ensemble strict et aucune écriture n'est possible (`READ_ONLY_SURFACE`).
5. `explanation: null` ⇒ la mention exacte « non documentée dans la Knowledge Base » (test sur la chaîne servie).
6. Aucun secret dans aucune réponse (test de motif sur 100 % des réponses).
7. Les 21 règles et 29 ports sont chargés ; une règle manquante fait **échouer le démarrage** (pas de fallback silencieux).
8. `check_no_verbatim.py` : aucune empreinte identique à `_audit/a4/knowledge/*.json`.

## 13.4 L2 — Sentinel

**Livrable** : `sentinel/{baseline,differ,rules,notify,store}` · S1, S2, S3, S8 · P-02, P-03, P-04 (changements) · F-04, F-05 · S-02, S-06.

**Critères d'acceptation**
1. Les 8 types sont produits ; `host_ports_initialized` est **stocké** et **absent de `/api/sentinel/events`** (test des deux côtés).
2. Les 5 types non producteurs ne créent **aucun** Finding (5 tests, un par type).
3. Les 3 types producteurs créent un Finding avec `risk_score = None` et la sévérité attendue.
4. Quota : 4ᵉ notification ⇒ `masked` conservée ; compteur indépendant par IP ; libération à exactement 60 min ; place maintenue si l'horloge recule (4 tests).
5. Un Finding est créé **avant** la décision de notification (`finding_created_even_when_masked`).
6. Un changement whitelisté reste visible, ne crée pas de Finding, ne consomme pas de quota.
7. `host_not_observed` n'affiche **jamais** « absent » (test de motif).
8. Aucun cycle automatique : sans appel explicite, `cycle_count` ne bouge pas.
9. S1, S2, S3, S8 rejouent leurs états attendus **au chiffre près**.

## 13.5 L3 — Contrôles et statuts

**Livrable** : `sentinel/verify.py`, `engine/findings.py` (transitions), S4, S5, S6, S7 · P-04 (contrôles) · F-06 · M-02, M-03, M-05, M-07.

**Critères d'acceptation**
1. `SUCCESS` seulement si `len(checks) > 0` **et** toutes satisfaites ; `len(checks) == 0` ⇒ `FAILED`.
2. `VERIFIED` refusé sans `VerifyRun` `SUCCESS` (`VERIFY_REQUIRED`).
3. `PARTIAL` et `FAILED` ne modifient **aucun** statut.
4. Aucun chemin n'écrit `REMEDIATED` (analyse AST hors commande utilisateur justifiée).
5. `apply-status` exige une justification ≥ 20 caractères pour `ACCEPTED` et `REMEDIATED`.
6. **S4** : WCT **identique** avant et après `port_not_open` ; il baisse **après** le VERIFY `SUCCESS` + confirmation, et l'écart est attribué.
7. M-03 `PARTIAL` ne contient **aucun** bouton de passage à `VERIFIED` (test de présence DOM).
8. M-07 refuse les trois opérations interdites avec un message citant la règle.
9. `mutate-world` ne crée aucun `VerifyRun` ; `run-verify` ne change aucun port.

## 13.6 L4 — Remédiation et rapports

**Critères d'acceptation**
1. Une proposition contient action, commande **indicative non exécutable** (préfixe présent), diff, risques.
2. `apply-remediation` exige la case de confirmation **et** la recopie de l'identifiant du Finding.
3. Après application, `finding.status` est **inchangé** (test explicite).
4. Un VERIFY est **requis** après application : l'écran ne propose pas de clôturer sans contrôle.
5. Aucune commande n'est exécutable : `subprocess` neutralisé ⇒ `GuardViolation`.
6. Le rapport est un fichier local sans ressource distante, et contient la note d'écart sur le recalcul du pire score (C11).
7. Aucun secret dans le rapport.

## 13.7 L5 — Transparence

**Critères d'acceptation**
1. **Toutes** les surfaces ont `product_state` **et** `prototype_state` (test d'exhaustivité, invariant I13).
2. P-17 ne contient **aucun** contrôle modifiable (absence d'`input`, `select`, bouton de sauvegarde ; aucune route de configuration).
3. La matrice de P-15 cite C4, C5, C11, C12 avec leur référence de fichier.
4. Le journal d'audit est append-only : aucune commande de suppression n'existe.
5. Chaque action modifiant le monde ou un statut produit **exactement une** entrée d'audit avec `effect_class`.
6. S-05 affiche `NON DOCUMENTÉ` quand un maillon manque (au lieu de sauter l'étape).
7. Les 5 formulations imposées de §12.7 sont présentes mot pour mot sur les surfaces indiquées.

## 13.8 L6 — Assistant

**Critères d'acceptation**
1. Deux appels avec le même contexte ⇒ **octets identiques**.
2. Deux surface/entité différents ⇒ textes différents (6 combinaisons testées).
3. Chaque réponse contient les **7 blocs** ; un bloc vide est présent avec « sans objet ».
4. Chaque réponse contient **≥ 1 source** ; le rendu échoue si une source manque.
5. Aucun import d'écriture dans `assistant/*` (AST) ; l'état est identique avant/après une question.
6. Les 8 cas de refus de §11.7 sont couverts par un test chacun.
7. Aucun terme du lexique interdit, ni « corrigé », ni « absent » non qualifié.
8. Les 3 réponses dorées de §11.6 sont reproduites à l'identique.

## 13.9 L7 — Finition

**Critères d'acceptation**
1. Chaque surface de liste a un état vide **explicatif** (revue exhaustive, une par page).
2. Navigation clavier complète ; `Échap` ferme panneaux et modales ; focus visible partout.
3. Contrastes ≥ 4.5:1 (mesure + revue en niveaux de gris).
4. `prefers-reduced-motion: reduce` ⇒ 0 animation.
5. Première peinture < 300 ms ; aucune requête réseau externe.
6. Suite complète verte : `python3 -m unittest discover -s tests` (aucune dépendance).
7. `check_no_network.py` et `check_no_verbatim.py` passent.
8. `docs/limites.md` reprend mot pour mot §15.

## 13.10 Plan de tests

| Catégorie | Fichiers |
|---|---|
| **Unitaire** | `test_scoring`, `test_sentinel_events`, `test_notifications`, `test_verify`, `test_ids` |
| **Scénario (bout en bout)** | `test_scenarios` (8 scénarios, comparaison aux états attendus) |
| **Contrat d'API** | `test_api_contract` (codes, formes, absence d'écriture en GET, absence d'agrégat) |
| **Assistant** | `test_assistant` (déterminisme, contextualisation, sources, refus, dorés) |
| **Sécurité** | `test_safety` (socket, subprocess, DNS, chemins, CSP, secrets) |
| **Conformité du contenu** | `test_knowledge_no_verbatim` + tests de lexique dans `test_api_contract` |
| **Revue humaine** | 8 écrans × 3 questions (§13.11) |

**Traçabilité invariant → test** : I1 `test_ids::test_no_cross_reference` · I2 `test_scoring::test_non_scored` · I3 `test_scoring::test_wct_*` · I4 `test_sentinel_events::test_no_finding_types` · I5 `test_sentinel_events::test_silent_never_exposed` · I6 `test_notifications::test_masked_persisted` · I7 `test_notifications::test_window_boundary` + `test_independent_hosts` · I8 `test_verify::test_verified_requires_success` · I9 `test_verify::test_no_auto_remediated` · I10 `test_verify::test_partial_no_effect` + `test_failed_no_effect` · I11 `test_safety::test_no_secret_leak` · I12 `test_api_contract::test_no_global_score` · I13 `test_api_contract::test_scope_labels_complete` · I14 `test_knowledge_no_verbatim` · I15 `test_api_contract::test_explanation_state`.

## 13.11 Protocole de revue humaine

Pour chaque écran, trois questions, réponses consignées :
1. **Un analyste pourrait-il mal lire ?** (ambiguïté de sévérité, de statut, de fraîcheur)
2. **Les deux attributs sont-ils visibles ?** (produit / prototype, si applicable)
3. **Une phrase interdite est-elle apparue ?** (lexique §12.7)

Plus un test en niveaux de gris sur trois écrans (tableau de bord, journal, fiche) pour vérifier l'indépendance à la couleur.

## 13.12 Définition de fini

Une fonctionnalité est finie quand : (a) son critère d'acceptation est un test vert · (b) son état vide et son état d'erreur existent · (c) l'étiquetage produit/prototype est affiché · (d) une entrée d'audit est produite si elle modifie quelque chose · (e) aucun terme interdit n'est présent.

## 13.13 Ce que la suite de tests ne couvrira jamais

La fidélité de la détection réseau (aucune sonde) · la performance d'un vrai scan · la pertinence de la Knowledge Base · la conformité réglementaire d'un rapport. Ces limites sont écrites dans `docs/limites.md` et reprises en P-15. **Aucun test ne doit être écrit de manière à suggérer le contraire.**

---

# 14. Incertitudes et décisions demandées

Sept points restent ouverts. Pour chacun, la conception retient **l'option par défaut indiquée** (implémentable sans risque juridique ni doctrinal) ; le changement est trivial si vous tranchez autrement.

## Q-D1 — Licence et réutilisation de la Knowledge Base *(bloquant)*

**Fait.** `a4-arena` n'a **aucun** `LICENSE` ; `main` est GPLv3 ; les fichiers de connaissance sont suivis sans mention de licence (§3.6). Une branche sans licence n'accorde par défaut aucun droit de réutilisation.

| Option | Contenu | Conséquence |
|---|---|---|
| **A (retenue)** | **Aucune copie** : identifiants, taxonomie, structures repris ; les 21 textes `what/attack/defense`, les 11 entrées CVE et les 10 profils **rédigés pour la démo**, profils entièrement fictifs | Aucun risque ; coût de rédaction ; test anti-verbatim |
| B | Autorisation écrite de réutiliser `knowledge/*.json` | Colle au produit ; l'autorisation doit couvrir la redistribution |
| C | Placer la démo sous GPL-3.0 par alignement sur `main` | Cohérent si publication ; ne règle pas l'absence de licence sur `a4-arena` |

**Décision demandée** : confirmez A, fournissez une autorisation écrite (B), ou fixez la licence du projet (C). **Bloque L1.**

## Q-D2 — Persistance entre deux lancements

| Option | Effet |
|---|---|
| **A (retenue)** | `runtime/` **effacé à chaque démarrage**, scénario rechargé : état toujours reproductible |
| B | Conservé, avec un bouton « repartir de zéro » (M-08) |
| C | Conservé uniquement si `--keep` |

Recommandation : **A** (C si vous voulez rejouer une session). Une démonstration qui démarre dans un état inconnu est un défaut de crédibilité.

## Q-D3 — Scénarios exposés

| Option | Contenu | Effet |
|---|---|---|
| **A (retenue)** | **4 parcours guidés** (S4 port fermé, S3 quota, S6 contrôle partiel, S8 dégradé) + 4 scénarios techniques masqués utilisés par les tests | Démonstration lisible ; les 8 restent testés |
| B | Les 8 exposés | risque de dispersion |
| C | Un seul scénario + mode libre | perte des démos quota et contrôle partiel |

Recommandation : **A**. Le mode libre (6 mutations) reste disponible dans tous les cas, toujours lancé depuis un scénario.

## Q-D4 — Montrer l'écart du rapport (C11) ou le corriger ?

| Option | Contenu | Effet |
|---|---|---|
| **A (retenue)** | Le prototype **applique la règle correcte** et **signale l'écart** | Fidèle à l'intention, honnête sur le défaut |
| B | Le prototype **reproduit** l'écart | Plus démonstratif, mais affiche un résultat faux |
| C | Pas de rapport dans la démo | Perte d'une capacité `EXISTE` |

Recommandation : **A**. B est défendable pour plaider une correction du produit — dans ce cas, afficher l'écart **côte à côte** avec la valeur correcte, jamais seul.

## Q-D5 — Étendue de la Knowledge Base

| Option | Contenu | Effet |
|---|---|---|
| **A (retenue)** | **21 règles** (mêmes identifiants, textes rédigés), **29 ports**, **11 CVE**, **10 profils fictifs** | Cohérent avec le produit |
| B | 12 règles couvrant les scénarios | P-15 devrait afficher « couverture partielle » |
| C | 21 règles + identifiants CVE réels (faits publics) | Plus réaliste, textes toujours rédigés |

Recommandation : **A**, éventuellement C pour les CVE. Signalement : je **ne reproduis pas** les identifiants constructeur réels du catalogue de credentials — décision indépendante de la licence, elle relève du bon sens.

## Q-D6 — Deux points que la documentation produit ne tranche pas

| Point | Ce qu'on sait | Ce que fait la démo |
|---|---|---|
| Relance après `TIMEOUT` SSH | Les budgets globaux sont fixés (3/service, 2/compte, 10 global, 10 s/tentative, 35 s/service) mais aucune politique de relance n'est spécifiée | Applique les budgets, **ne relance pas**, affiche « non testé — budget épuisé » |
| Effet d'une whitelist sur un Finding **déjà créé** | La whitelist est consultée **au moment de la décision**, pas après | Aucun effet rétroactif, aucune suppression |

Si vous préférez une autre lecture, c'est une ligne à changer — mais il faut alors une source produit, pas une convention.

## Q-D7 — Authentification de démonstration

| Option | Contenu | Effet |
|---|---|---|
| **A (retenue)** | Écran de connexion, identifiants **préremplis** (`analyst`), aucune vérification de mot de passe, session locale opaque | Conforme à Q4 ; aucune surface d'attaque inutile |
| B | Mot de passe fictif vérifié côté serveur | Introduit une gestion de secret sans bénéfice |
| C | Pas d'écran (contredit Q4) | — |

Recommandation : **A**. Un écran qui prétend vérifier un mot de passe fictif enseignerait un mauvais réflexe.

## Récapitulatif des décisions qui bloquent quoi

| Décision | Bloque |
|---|---|
| **Q-D1** licence | **L1** (rédaction de la KB) — **seul point réellement bloquant** |
| Q-D2 persistance | L0 (comportement au démarrage) |
| Q-D3 scénarios exposés | L2 (menu Scénario) |
| Q-D4 rapport | L4 |
| Q-D5 étendue KB | L1 |
| Q-D6 deux détails produit | L1, L2 (documentation si vous tranchez « non documenté ») |
| Q-D7 authentification | L0 |

Sans Q-D1, aucun lot ne peut démarrer. Les six autres ont une valeur par défaut déjà retenue et peuvent être tranchées en cours de route sans réécrire ce dossier.

---

# 15. Ce que cette démonstration ne prouve pas

À reprendre **mot pour mot** dans `docs/limites.md` et dans l'écran P-15.

| Point | Pourquoi |
|---|---|
| Qu'une vraie correction fonctionne | Aucun système réel n'est touché ; `VERIFIED` atteste d'un état **fictif** |
| Que la détection est fiable | Les bannières et réponses sont écrites à la main |
| Que les performances tiennent | Aucune sonde, aucune parallélisation réelle |
| Que la Knowledge Base est pertinente | 21 règles rédigées pour la démo, pas une base de production |
| Qu'une capacité V2/V3 est acquise | S5 à S7 portent sur une fonction **absente** du produit |
| Que le réseau présenté existe | Toutes les adresses sont de documentation (RFC 5737) |
| Qu'un rapport serait conforme | Aucun référentiel réglementaire n'est modélisé |
| Que SentinelX respecte les règles d'un vrai scan | Aucune autorisation, aucune cible, aucun paquet |

**La règle qui les résume** : *ce qui est simulé est étiqueté ; ce qui est réel est sourcé ; ce qui est indéterminé est dit indéterminé.*

---

# 16. Annexes

## 16.1 Glossaire des termes officiels (invariables)

| Terme | Définition courte |
|---|---|
| **Finding** | Constat produit par un module ; seule entité acceptée par le cœur (scoring, base, rapports) |
| **Inventory Observation** | `Finding` d'inventaire (`module=device_fingerprint`, `category=network`, `severity=info`) — **pas une entité distincte** |
| **Worst Current Threat** | Maximum des `risk_score` des Findings `OPEN`, `confidence ≥ 0.70`, hors inventaire. Jamais une moyenne |
| **`OPEN` / `VERIFIED` / `REMEDIATED` / `ACCEPTED`** | Statuts d'un Finding. Aucun n'est automatique |
| **`CONFIRMED` / `PROBABLE` / `POSSIBLE`** | Confiances : 1.00 / 0.85 / 0.60 |
| **`SUCCESS` / `PARTIAL` / `FAILED`** | Les trois issues du contrôle `VERIFY` (ajout de la démo, `ABSENT` du produit) |
| **`new_host`, `new_port`, `mac_change`** | Les 3 types Sentinel qui produisent un Finding — **non scoré** |
| **`port_not_open`, `host_not_observed`, `host_recovered`, `scan_degraded`** | Types sans Finding. Un échec de contrôle n'est pas une absence de changement |
| **`host_ports_initialized`** | Type **silencieux** : stocké, jamais affiché, jamais notifié |
| **`network_id`** | Identifiant de **surveillance** : 12 hex, hash de CIDR + passerelle IP + MAC |
| **`session_id`** | Identifiant d'**évaluation** : `sentinel-run-<uuid>` |
| **Whitelist** | Autorisation d'un changement (port / hôte / MAC) : l'événement reste visible, sans Finding ni notification |
| **Masked** | Notification non émise faute de quota, **conservée** et relisible |
| **`evidence`** | `evidence.raw` + `evidence.command` : preuve brute, jamais interprétée, aucun secret |

## 16.2 Table des preuves produit utilisées

| Affirmation | Source vérifiée |
|---|---|
| `Severity` inclut `CRITICAL` | `core/finding.py:32-40` |
| 7 CVE `critical` sur 11 | `knowledge/cve_db.json` (comptage) |
| Élévation de sévérité jusqu'à `CRITICAL` | `detect/service_detection.py:12`, `386`, `457` |
| Confiance forcée à `POSSIBLE` si version non confirmée | `detect/service_detection.py:433-445` |
| Inventory = `device_fingerprint` | `recon/device_fingerprint.py:317` ; `core/risk_scorer.py:101` ; `cli.py:1941` |
| Worst Current Threat = max filtré | `core/risk_scorer.py:get_global_score` |
| Barème 90/70/45/20/5, ×confiance ×exposition | `core/risk_scorer.py` ; steering §H |
| `WINDOW = 60 min`, `LIMIT = 3` | `sentinel/notifications.py:7-9` |
| Comptage `displayed` / `reserved` / `available` | `sentinel/notifications.py:host_summary` |
| Six états de notification | `sentinel/notifications.py:notification_state`, `host_summary` ; `alerting.py:164-190` |
| `SILENT_TYPES = {host_ports_initialized}` | `sentinel/alerting.py:77` |
| Table de sévérités Sentinel (MEDIUM/HIGH/HIGH) | `sentinel/alerting.py:59-63` |
| « Contrôle partiel, non enregistré comme réussi » | `sentinel/monitor_view.py:32-36` |
| Couleurs par type d'événement | `sentinel/monitor_view.py:39-47` |
| Reformulation `port N not open` → `Port N closed` | `sentinel/monitor_view.py:48-61` |
| Formats `session_id` / `network_id` | `core/assessment.py` ; `~/.netlab/sentinel/<network_id>.db` |
| `format_finding_id` → `FD-XXXXXXXX` | `core/finding.py:100-112` |
| 21 règles / 29 ports / 11 CVE / 10 profils | comptage sur `knowledge/*.json` |
| Budgets credentials | `docs/T22-CREDENTIALS.md` ; `detect/default_creds.py` |
| `LICENSE` absent sur `a4-arena`, GPLv3 sur `main` | `git ls-files` ; `git show origin/main:LICENSE` |
| 2 083 tests, 91 %, 16 177 lignes | exécution sur copie (`_audit/sandbox4`) |

## 16.3 Traçabilité des corrections

| Point | Version précédente | État actuel |
|---|---|---|
| **S4** | Baisse directe du Worst Current Threat sur `port_not_open` | **Corrigé** : 7 étapes ; baisse uniquement après VERIFY `SUCCESS` + confirmation (§9.7) |
| **Inventory Observations** | Envisagées comme entité distincte | **Corrigé** : `Finding` unique + filtre (§3.2, §7.3) |
| **`CRITICAL`** | Supposé absent des énumérations | **Corrigé** : valeur officielle produite (§3.1) |
| **Quota** | « 3 émissions récentes » | **Corrigé** : `available = 3 − affichées − réservées`, six états, `masked` non comptée (§3.3, §7.5) |
| **Catégories** | Décrites comme un cycle de vie | **Corrigé** : 5 valeurs fonctionnelles indépendantes du statut (§7.2) |
| **Nombre d'écrans** | 14 | **Abandonné** : 19 / 13 / 7 / 9 par nature (§5) |
| **Assistant** | Envisagé avec LLM local | **Corrigé** : déterministe seul ; LLM documenté sans implémentation (§11.8) |
| **Licence** | Non traitée | **Traitée** : aucune copie, textes rédigés, test anti-verbatim (§3.6, Q-D1) |

## 16.4 Fichiers du dossier

| Fichier | Rôle |
|---|---|
| **`SENTINELX_FUTURE_CONCEPTION_MAITRE.md`** | **Ce document — lecture unique suffisante** |
| `maquettes/index.html` | Maquettes autonomes de 8 écrans (aucune ressource externe) |
| `00_INDEX_ET_DECISIONS.md` … `10_INCERTITUDES.md` | Version éclatée, conservée pour la traçabilité de la rédaction |
| `_audit/A_REPORT.md` | Audit de `a4-arena` (preuves, constats C1–C14) |
| `_audit/B_VISION.md` | Vision révisée — **S4 corrigé** |
| `_audit/C_TECH.md` | Proposition technique — option B précisée (`127.0.0.1`, garde-fous testés) |
| `_audit/EVIDENCE.md` | Journal de preuves F-01…F-20 |

## 16.5 Ce qui reste à faire, dans l'ordre

1. **Vous** : trancher Q-D1 (licence) et, si vous le souhaitez, Q-D2 à Q-D7 (§14).
2. **Vous** : valider §5 (inventaire des écrans) et §9 (scénarios, en particulier S4 et S6).
3. **Moi, après autorisation** : L0 uniquement — socle, garde-fous, coquille vide, connexion. Démonstration du lot, puis arrêt.
4. **Moi, après validation de L0** : L1 → L2 → L3 → L4 → L5 → L6 → L7, un lot à la fois, chacun avec ses critères d'acceptation exécutés.

**Aucun code applicatif n'a été écrit à ce stade.** Le dépôt SentinelX est intact.

---

*Fin du dossier de conception maître — version 1.0, 12 novembre 2026.*
