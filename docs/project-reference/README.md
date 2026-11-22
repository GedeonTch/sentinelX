# SentinelX — Point d'entrée documentaire des agents

Ce dossier centralise les documents de référence du projet SentinelX. Il sert de **point d'entrée unique** pour tout agent (humain ou automatique) qui travaille sur le dépôt.

Les documents sont conservés **tels quels**, avec leurs noms, manifestes, sommes SHA-256 et diffs d'origine. Aucun document canonique de `docs/` n'est remplacé par une version proposée ou historique.

---

## A. Où se trouve chaque référence

| Référence | Rôle |
|---|---|
| `docs/MASTER-REFERENCE.md` | **Référence canonique** des décisions approuvées, du périmètre, de l'architecture et de l'ordre de la feuille de route. |
| `docs/IMPLEMENTATION-TRACKING.md` | **État opérationnel** des tickets : statuts, commits, preuves, réserves et points en attente. |
| `docs/project-reference/roadmap-v2.2-final/` | **Paquet de référence V2.2** conservé intégralement : plan global, table des tickets, spécifications A1, master reference et tracking proposés, transmission, diffs, manifeste, sommes SHA-256 et skills proposés. Fichiers originaux non réécrits. |
| `docs/project-reference/historical-references/docs-proposses/` | **Documents historiques** : versions antérieures, audits et variantes de travail. Aucune autorité actuelle. |
| `docs/project-reference/dec-05-cred-01-preparation.md` | **Proposition de travail** pour DEC-05 et CRED-01. Ce n'est pas une décision. |

### Emplacements historiques d'origine

- Paquet prioritaire : `/home/anonymous/Téléchargements/docs-proposees-V2.2-final` (copie intégrale dans `roadmap-v2.2-final/`).
- Versions historiques : `/home/anonymous/Téléchargements/docs-proposses` (copie intégrale dans `historical-references/docs-proposses/`).

Les répertoires sources n'ont pas été supprimés ni déplacés.

---

## B. Hiérarchie d'autorité

En cas de contradiction, appliquer strictement l'ordre suivant :

1. **Les décisions explicites du propriétaire prévalent** sur tout document, rapport ou proposition.
2. **`docs/MASTER-REFERENCE.md`** porte les décisions et l'ordre approuvés.
3. **`docs/IMPLEMENTATION-TRACKING.md`** reflète l'état réel des livraisons (vérifié dans Git, jamais déduit d'un ancien rapport).
4. **Le paquet V2.2** fournit la structure des tickets et les spécifications de référence, **dans les limites de son approbation DEC-02**.
5. **Les documents historiques et les propositions ne peuvent pas annuler une décision approuvée.** Leur présence dans le dépôt ne leur confère aucune autorité actuelle.

### Précision sur le plan V2.2

`docs/project-reference/roadmap-v2.2-final/docs-proposees/PLAN-tickets-global.md` porte encore la mention documentaire interne **PROPOSITION** (le document ne s'auto-approuve pas). Son **ordre** a toutefois été **approuvé par DEC-02**, consigné dans le `docs/MASTER-REFERENCE.md` canonique le **13 novembre 2026** :

```text
Étape 0 (documentation préalable) → SMB-01 (+ SMB-02) → A1 → CRED-01 → D5 → D1
→ TOOL-01 → REP-01 → OS-01 → SCO-01 → SCO-02 → A2-01 → CRED-03 → SCO-03
→ VERIFY-01 → DOC-02 → A2-02
```

D6 reste **indépendant** et hors séquence. La présence d'un ticket dans cette liste **ne vaut pas autorisation d'implémentation** : le propriétaire désigne et autorise chaque ticket.

---

## C. Procédure obligatoire pour tous les agents

Tout agent travaillant sur SentinelX doit :

1. Lire **`docs/project-reference/README.md`** (ce fichier).
2. Lire **`docs/MASTER-REFERENCE.md`**.
3. Lire **`docs/IMPLEMENTATION-TRACKING.md`**.
4. Consulter le ticket et les documents techniques concernés.
5. **Vérifier le statut réel du dépôt Git** (`git status`, `git log`, `git show`) avant toute implémentation.
6. Respecter les décisions et autorisations du propriétaire.

> **Ne jamais sélectionner un ticket uniquement à partir d'un ancien rapport, d'un document historique ou d'une mémoire de conversation.** Les statuts font foi dans `docs/IMPLEMENTATION-TRACKING.md`, après vérification Git.

Aucun agent ne peut, sans autorisation explicite : modifier le périmètre V1, changer l'architecture ou le pipeline, modifier une décision approuvée, changer l'ordre de la feuille de route, ou ajouter/supprimer/différer une tâche.

---

## D. Découvrabilité par les agents

Points d'entrée réellement présents dans le dépôt :

| Point d'entrée | Public | Référence vers ce README |
|---|---|---|
| `AGENTS.md` (racine) | agents génériques | Oui |
| `.kiro/steering/sentinelX.md` | Kiro / Cursor (steering) | Oui (note ajoutée) |
| `.cursor/rules/sentinelX.mdc` | Cursor | Oui (note ajoutée) |
| `.kiro/skills/impl-tracking.md` | Kiro (skill de suivi) | Oui (référence ajoutée) |

Fichiers **absents** du dépôt au moment de la centralisation : `CLAUDE.md`, `GEMINI.md`, `ARENA.md` (hors dépôt), `opencode.json`, `.github/copilot-instructions.md`. Les outils correspondants nécessitent donc encore un **chargement explicite** de `docs/project-reference/README.md` par l'utilisateur ou par l'outil.

> La détection automatique par chaque outil n'est pas garantie. Seuls les points d'entrée listés ci-dessus sont configurés.

---

## E. Intégrité du paquet centralisé

La copie a été vérifiée après duplication :

```bash
cd docs/project-reference/roadmap-v2.2-final
sha256sum -c SHA256SUMS-propositions-globales.txt
```

Résultat attendu : **24/24 fichiers listés OK** (le fichier de sommes ne s'auto-référence pas ; le paquet contient 25 fichiers). Les SHA-256 des 25 fichiers du paquet et des 22 fichiers historiques sont identiques avant et après copie. Les sources d'origine sont intactes.

Aucun secret, token, mot de passe ou donnée personnelle n'a été identifié dans les documents copiés.

---

## F. Documents historiques — avertissement

`docs/project-reference/historical-references/` contient des versions antérieures, des doublons et des rapports d'audit. Ces documents :

- peuvent contenir des statuts obsolètes (par exemple « non commité », « worktree ») ;
- ne doivent pas être utilisés pour désigner un ticket ou modifier un statut ;
- ne remplacent jamais `docs/MASTER-REFERENCE.md` ni `docs/IMPLEMENTATION-TRACKING.md`.
