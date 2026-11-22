# Transmission du dossier — revue Kiro et points A1 pour Nova

**Date** : 2026-09-24 (date du jour fournie).
**Référence de code** : `origin/a4-arena` = `9034f01` ; clone de lecture `/tmp/audit-global-ref` (arbre propre).
**Statut** : dossier **prêt pour revue**. Aucun élément n'est appliqué, ni commité, ni poussé. Aucun fichier du dépôt n'a été modifié.

> Remarque de mécanisme : l'agent ne dispose d'aucun canal direct vers Kiro ni vers Nova. La transmission consiste en ce dossier (chemin ci-dessous), à remettre au propriétaire ou à l'opérateur qui gère Kiro et Nova. Les SHA-256 du dossier figurent dans `SHA256SUMS-propositions-globales.txt`.

---

## 1. Demande de revue à Kiro (revue indépendante)

Kiro est invité à vérifier, **sans modifier les fichiers du dépôt** :

1. **Réconciliation A1** : `SPEC-A1-consolidee.md` et `PROPOSITION-A1-formalisation-TCP.md` (statuts [APPROUVÉ] / [OUVERT] ; §0 et §12 de la proposition ; §5, §10, §11, §12 de la spec). Diff : `diffs/PROPOSITION-A1-reconciliation.diff` (la spec a été modifiée en place, sans copie préalable : pas de diff, voir réserve K-3).
2. **Spécification canonique** : `docs-proposees/SENTINEL-TCP-STATES.md`. Points à examiner en priorité :
   - tableau §5 (séquences avant/après) : vérifier chaque ligne contre le harnais `preuves/a1/a1_chain_verify.log` ;
   - §3.2 (attribution `<extraports>`, marqué [PROPOSITION]) ;
   - §7.1 (clés de `proof`, [PROPOSITION]).
3. **Plan de tickets** : `docs-proposees/PLAN-tickets-global.md`. Vérifier : chaque preuve citée, chaque priorité, le statut « Partiel » de SCO-01, l'hypothèse SMB-02, la liste des décisions (§5).
4. **Patches documentaires** : `docs-proposees/MASTER-REFERENCE.md` et `docs-proposees/IMPLEMENTATION-TRACKING.md`, diffs `diffs/master-reference.diff` et `diffs/impl-tracking-v2.diff` (bases `docs-proposees/base-9034f01/`). Vérifier : `git cat-file -e` sur chaque SHA cité ; statut CONFIDENCE-CLI.
5. **Harnais** : `preuves/a1/a1_chain_verify-run5.json` (HOME neuf) : sections `parse` identiques à run 4. Attention : le champ `verdict` de `parse` compare à la production, pas à la spec (voir `RAPPORT-verification-A1` §12).

Questions précises pour Kiro :
- K-Q1. La règle « `[]` n'est pas une preuve de fermeture » (ARENA §9.6 est en contradiction) est-elle correctement isolée dans le plan (§6) ?
- K-Q2. Les tickets P1 (SMB-01, TCP-01 à TCP-03, CRED-01) sont-ils justifiés par les preuves citées ?
- K-Q3. Le statut « Hypothèse » de SMB-02 et OS-01, et « Partiel » de SCO-01, sont-ils corrects ?
- K-Q4. Y a-t-il une incohérence entre `docs-proposees/` et les statuts de `SPEC-A1-consolidee.md` ?

---

## 2. Points A1 restants pour Nova (à soumettre au propriétaire)

Nova ne soumet que les points **non approuvés**. Les points approuvés ne doivent pas être rouverts.

| Réf. | Point | Question |
|---|---|---|
| DEC-03 | Libellé D1 | Quel libellé pour les événements avec preuve, et lequel pour l'historique sans preuve ? Proposition dans `PLAN-tickets-global.md` §5. |
| DEC-04 | Politique D6 (ports `filtered` à l'apprentissage) | C2 (exclusion d'hôte), C3 (drapeau), ou statu quo D6-A (= C1) ? Hors A1. |
| DEC-13 | ARENA §9.6 | Le texte « règle définitive » contredit les décisions approuvées (`[]` incrémente). Accepter la révision proposée (`PLAN-tickets-global.md` §6) ? |
| DEC-01 | Emplacement canonique de la spec A1 | `docs/SENTINEL-TCP-STATES.md` ? |
| DEC-15 | Réserve S3 (redémarrages répétés) | Accepter explicitement qu'un redémarrage avant chaque cycle empêche toute fermeture confirmée ? |

Décisions **déjà approuvées** (ne pas soumettre de nouveau) : V4 (remise à zéro) ; G-a (fermetures individuelles après deux `closed` explicites) ; G-b écartée ; G-c reportée ; aucune fermeture sur `closed` → `filtered` ; validation XML commune ; D5-B ; D6 hors A1 ; compteurs non restaurés.

---

## 3. Réserves à transmettre avec le dossier

- **K-1 / R-1 — Horloge.** Date du jour fournie : 2026-09-24. Horloge de la sandbox : 2026-11-12. Dates de commit : 2026-11-10 et 2026-11-11. À vérifier avant toute conclusion chronologique.
- **K-2 — Lecture seule.** Aucun scan réel, aucune lecture de `~/.netlab`, aucun secret demandé, aucune migration de coffre. Les tests ont utilisé HOME et bases temporaires, fixtures XML et sondes remplacées.
- **K-3 — Diff manquant.** `SPEC-A1-consolidee.md` a été réconcilié en place : aucune copie antérieure n'existe pour un diff. Ce qui est consigné : le contenu final, et la liste des remplacements effectués (35 remplacements de statuts et de références, comptage contrôlé).
- **K-4 — Corrections d'audit.** Trois constats sont revus (B5-1 partiel, B2-2 décision produit, B3-2 hypothèse). Voir `PLAN-tickets-global.md` §7.
- **K-5 — Harnais.** Le champ `verdict` de la section `parse` mesure la conformité au comportement de production, pas à la spécification. Le critère de conformité à la spec est `spec_expected`.
- **K-6 — Versions.** `ARENA.md` rév. 13 utilisée ; la rév. 12 n'a pas été comparée.
- **K-7 — Clones non touchés.** `/home/user/sentinelX` (`2eb1b20`, 27 modifications), `sentinelX-impl` (`13e7849`, 12), `sentinelX-reference` (`2283166`, 6) : non modifiés, non alignés sur `9034f01`.
- **K-8 — Skills canoniques.** Non modifiées. Les propositions de Skills de l'audit précédent (`skills-proposees/`) restent non appliquées.

## 4. Fichiers du dossier (point d'entrée)

- Plan : `docs-proposees/PLAN-tickets-global.md`
- Spécification A1 : `docs-proposees/SENTINEL-TCP-STATES.md` (et `SPEC-A1-consolidee.md` réconciliée)
- Proposition A1 : `PROPOSITION-A1-formalisation-TCP.md` (réconciliée)
- Documents maîtres proposés : `docs-proposees/MASTER-REFERENCE.md`, `docs-proposees/IMPLEMENTATION-TRACKING.md`
- Diffs : `diffs/master-reference.diff`, `diffs/impl-tracking-v2.diff`, `diffs/PROPOSITION-A1-reconciliation.diff`
- Preuves : `preuves/a1/a1_chain_verify-run5.json` et `.log`, `preuves/a1/a1_chain_verify.json` et `.log` (run 4), `RAPPORT-verification-A1-chaine-production.md` §12
- Empreintes : `SHA256SUMS-propositions-globales.txt`
