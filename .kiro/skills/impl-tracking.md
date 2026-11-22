# SentinelX — Skill de suivi de l'implémentation (Kiro)

> **Ce fichier est un point d'entrée Kiro.**
> Le suivi opérationnel canonique est dans **`docs/IMPLEMENTATION-TRACKING.md`**.
> Ce fichier contient les mêmes règles de travail pour que Kiro les charge automatiquement.

---

## Règles de travail des agents

Ces règles s'appliquent à tout agent lisant ou modifiant le suivi opérationnel.

1. **Vérifier le dépôt avant de modifier un statut.** `git log`, `git show --stat`, grep sur les sources, exécution des tests. Un rapport d'agent précédent n'est pas une preuve.
2. **`[x]` uniquement quand les critères d'acceptation sont satisfaits et les preuves vérifiées.** Pas seulement "le code existe" ou "les tests passent".
3. **`[-]` pour une tâche en cours.** Préciser ce qui est terminé et ce qui reste.
4. **Conserver les tâches différées, refusées ou annulées.** Ne jamais supprimer silencieusement.
5. **Distinguer : réserve acceptée ≠ défaut connu ≠ tâche terminée.**
6. **Ne pas considérer un ancien rapport d'agent comme preuve suffisante.**
7. **Ne pas modifier les décisions approuvées** sans autorisation explicite du propriétaire.
8. **Proof line obligatoire pour chaque sous-tâche `[x]`.**

---

## Références

| Document | Rôle |
|---|---|
| `docs/project-reference/README.md` | Point d'entrée centralisé : références, hiérarchie d'autorité, procédure agents |
| `docs/MASTER-REFERENCE.md` | Vision, architecture, règles, décisions, périmètre V1, specs |
| `docs/IMPLEMENTATION-TRACKING.md` | Suivi opérationnel : tâches, preuves, statuts, en-cours |
| `ARENA.md` (téléchargements propriétaire, révision 13) | Spécifications détaillées T23-B et T21 |

---

## État courant

Ce skill ne conserve **aucun état Git local**. Les commits, statuts et livraisons évoluent sans mise à jour de ce fichier.

Références canoniques :
- `docs/MASTER-REFERENCE.md` — décisions et ordre approuvés ;
- `docs/IMPLEMENTATION-TRACKING.md` — état réel des tickets, commits et preuves ;
- `docs/project-reference/README.md` — point d'entrée documentaire.

Vérifier `git log`, `git status` et les documents ci-dessus avant toute action.
