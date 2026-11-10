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
| `docs/MASTER-REFERENCE.md` | Vision, architecture, règles, décisions, périmètre V1, specs |
| `docs/IMPLEMENTATION-TRACKING.md` | Suivi opérationnel : tâches, preuves, statuts, en-cours |
| `ARENA.md` (téléchargements propriétaire, révision 13) | Spécifications détaillées T23-B et T21 |

---

## Résumé de l'état courant

**HEAD :** `3657498` (T23-B, branche `a4-arena`)

| Tâche | Statut |
|---|---|
| T23-B — Extension détections Sentinel | `[x]` Terminé (commit `3657498`) |
| T21 — findings list groupé par machine | `[x]` Terminé (commit `5e2be6b`) |
| T22 — Credentials FTP/SNMP/SSH/SMB | `[x]` Implémenté (validation critère par critère non effectuée par tiers) |
| T24 — dns_enum + passive_recon | `[-]` Code livré (`cf5d821`), validation nécessaire |
| T25 — Multi-host confirmations | `[-]` Code livré (`f87b140`), validation nécessaire |
| **CONFIDENCE-CLI** | `[-]` En cours — modifs locales, 14/14 tests ✓, commit en attente |
| **T20** — Rapport HTML refonte | `[ ]` Non commencé |

Détail complet → `docs/IMPLEMENTATION-TRACKING.md`
