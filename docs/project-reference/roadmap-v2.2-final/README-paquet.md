# Paquet de revue Kiro — propositions documentaires globales (version 2.2)

- Date de rédaction : 2026-11-12 (référence de mission : 12 novembre 2026).
- Commit de référence : `9034f0131ebeaf63dc51bf217cea3ec3f6ab068e` (`origin/a4-arena`, date git 2026-11-11). Voir `COMMIT-REFERENCE.txt`.
- Statut : **PROPOSITION**. Version 2.2 : Étape 0 documentaire préalable à SMB-01 ; CA-16 rattaché à D1 ; Skill Kiro retiré du paquet actif. Rien n'est approuvé, implémenté ni validé par ce paquet. Aucun fichier du dépôt n'est modifié.
- Transmission à Nova/Kiro : **non effectuée** (aucun canal disponible). Ce paquet est déposé pour revue.

## Contenu

- `docs-proposees/PLAN-tickets-global.md` : plan global de tickets (version 2.2).
- `docs-proposees/MASTER-REFERENCE.md` : proposition de document maître (remplace `docs/MASTER-REFERENCE.md` après validation).
- `docs-proposees/IMPLEMENTATION-TRACKING.md` : proposition de suivi d'implémentation.
- `docs-proposees/IMPLEMENTATION-TRACKING-section-audit.md` : section d'audit du suivi.
- `docs-proposees/SENTINEL-TCP-STATES.md` : spécification canonique proposée de A1 (emplacement proposé `docs/SENTINEL-TCP-STATES.md`, à vérifier).
- `docs-proposees/TABLEAU-tickets-dependances.md` : tableau des tickets, dépendances, ordre.
- `docs-proposees/TRANSMISSION-revue-Kiro-et-Nova.md` : points de contrôle pour Kiro, décisions ouvertes, réserves.
- `SPEC-A1-consolidee.md`, `PROPOSITION-A1-formalisation-TCP.md` : spécification A1 consolidée et formalisation.
- `skills-proposees/sentinelX.mdc` : proposition de Skill Cursor, limitée à la correction de casse (non appliquée au Skill canonique). La proposition de Skill Kiro est retirée du paquet actif (V2.2).
- `diffs/` : un diff par proposition, plus `GLOBAL-documentaire.diff` (concaténation).
- `MANIFEST-propositions-globales.txt`, `SHA256SUMS-propositions-globales.txt`, `COMMIT-REFERENCE.txt`.

## Vérification

Depuis la racine du paquet :

    sha256sum -c SHA256SUMS-propositions-globales.txt

Les diffs dont la base est le dépôt (`docs/…`, `.cursor/…`, `.kiro/…`) s'appliquent à une copie de `9034f0131ebeaf63dc51bf217cea3ec3f6ab068e` : `git archive 9034f0131ebeaf63dc51bf217cea3ec3f6ab068e | tar -x -C <dossier>` puis `patch -p1 --dry-run -i diffs/<fichier>.diff`. Les diffs marqués « informatif » (PLAN, SPEC, PROPOSITION, TRANSMISSION) comparent à des versions antérieures non incluses ; ils servent à la lecture des changements.

## Réserves

Voir `docs-proposees/TRANSMISSION-revue-Kiro-et-Nova.md` §6 et `docs-proposees/PLAN-tickets-global.md` §10 (R-1 à R-13). Points ouverts : DEC-02 (condition de l'Étape 0), DEC-03, DEC-04, DEC-05, DEC-07, DEC-08, DEC-09, DEC-11, DEC-12, DEC-14, DEC-16, DEC-17.
