# Transmission — propositions documentaires globales (version 2) — pour Nova, puis seconde vérification par Kiro

**Statut : dossier déposé, NON TRANSMIS.** Cet environnement ne dispose d'aucun canal de transmission vers Kiro ou Nova. Le dossier doit être remis par le propriétaire ou transmis par un canal disponible.

| Élément | Valeur |
|---|---|
| Date de rédaction | 2026-11-12 |
| Commit de référence | `9034f01` (`origin/a4-arena`, HEAD réel, clone de lecture propre) |
| Dossier | `/home/user/AUDIT-SentinelX-global/` |
| Périmètre | Documents et diffs uniquement. Aucune modification du dépôt, aucun code, test, Skill appliqué, commit, push, nettoyage ni scan réel. |

## 1. Ce qui est demandé

1. **Nova** : vérification indépendante des corrections (§3) et de leurs références.
2. **Kiro** : seconde vérification indépendante. Les points de contrôle sont au §4.
3. **Propriétaire** : décisions ouvertes au §5. Rien n'est approuvé par ce dossier.

## 2. Livrables

| Livrable | Chemin | Statut |
|---|---|---|
| Plan global corrigé (v2) | `docs-proposees/PLAN-tickets-global.md` | Proposition |
| Table des tickets et dépendances | `docs-proposees/TABLEAU-tickets-dependances.md` | Proposition |
| Spécification A1 canonique proposée | `docs-proposees/SENTINEL-TCP-STATES.md` | Proposition (emplacement proposé `docs/SENTINEL-TCP-STATES.md`) |
| Spécification A1 consolidée | `SPEC-A1-consolidee.md` | Spécification pour ticket futur, aucune implémentation |
| Formalisation A1 (rapport de proposition) | `PROPOSITION-A1-formalisation-TCP.md` | Proposition, distinction approuvé / ouvert |
| Master Reference proposé | `docs-proposees/MASTER-REFERENCE.md` | Proposition ; `docs/MASTER-REFERENCE.md` non modifié |
| Implementation Tracking proposé | `docs-proposees/IMPLEMENTATION-TRACKING.md` | Proposition ; `docs/IMPLEMENTATION-TRACKING.md` non modifié |
| Section d'audit du suivi | `docs-proposees/IMPLEMENTATION-TRACKING-section-audit.md` | Proposition |
| Skill Cursor (casse seule) | `skills-proposees/sentinelX.mdc` | Proposition ; `.cursor/rules/sentinelX.mdc` non modifié |
| Skill Kiro d'implémentation | **Retiré du paquet actif (V2.2)** ; fichier conservé dans le dossier d'audit, non inclus | Skill canonique non modifié ; aucune proposition de Skill Kiro dans le paquet |
| Diff global documentaire | `diffs/GLOBAL-documentaire.diff` | Généré |
| Diffs individuels | `diffs/*.diff` (voir `MANIFEST-propositions-globales.txt`) | Générés |
| Manifeste et sommes | `MANIFEST-propositions-globales.txt`, `SHA256SUMS-propositions-globales.txt` | Générés ; à vérifier par `sha256sum -c` |
| Versions antérieures | `docs-proposees/archive-v1/`, `diffs/archive-v1/` | Historique, non intégré au paquet |

**Commit et état Git** : `git -C /tmp/audit-global-ref rev-parse HEAD` → `9034f01` ; `git status --short` → vide ; `git ls-remote origin a4-arena` → `9034f0131ebeaf63dc51bf217cea3ec3f6ab068e`. Ce clone est un clone de lecture, à recréer s'il a disparu (le répertoire `/tmp` n'est pas conservé).

## 3. Corrections intégrées (revue Kiro)

| Point | Correction |
|---|---|
| CRED-02 | Reclassé **conforme à T22**, sans ticket, sans ajout de candidat SSH |
| SMB-01 / SMB-02 | `enum4linux-ng` 1.3.10 ; `--json` absent ; export `-oJ OUT_JSON_FILE` (rapporté par le propriétaire, vérifié sur son poste, non reproduit ici). SMB-01 : commande compatible, lecture du JSON, code retour, stdout/stderr séparés, repli texte. Code non nul jamais « aucun résultat ». SMB-02 : vérification de compatibilité. |
| NET-01 | Non reproduite ; `--target` obligatoire ; P1 provisoire et DEC-10 retirés ; aucun ticket de code |
| A1 | Ticket parent unique « Fiabilisation des états TCP de Sentinel Monitor » ; TCP-01/02/03 sous-tâches ; TCP-04 non-régression ; inclut hôte absent, hôte entièrement filtré, fermetures individuelles, `closed → filtered`, attributions ambiguës |
| D5 / D1 / D6 | D5-B : conception approuvée, implémentation non autorisée, après A1 ; D1 : distinction approuvée, libellé ouvert, après D5 ; D6 : ticket indépendant hors A1 |
| ARENA §9.6 / DEC-13 | Supersédée par la politique A1 approuvée ; `docs/MASTER-REFERENCE.md` est le document maître officiel ; rôle de `ARENA.md` à vérifier |
| DEC-15 | Retirée comme arbitrage ; risque des redémarrages répétés documenté comme conséquence de R7 |
| DEC-01 | Proposition d'emplacement `docs/SENTINEL-TCP-STATES.md`, justifiée par la convention de nommage de `docs/` |
| DOC-02 | Casse reproduite dans `.cursor/rules/sentinelX.mdc` l.9 ; Skill Kiro retiré du constat ; chemins absolus `docs/MASTER-REFERENCE.md` l.26, l.310-311 conservés |
| Chemins | Vérifiés dans `9034f01` ; `docs-processes/` et `(1)`/`(2)` introuvables, non intégrés |
| Dates | Rédaction et référence : 2026-11-12 ; 2026-09-24 retiré de toutes les propositions |
| Ordre | SMB-01 ; A1 ; CRED-01 ; D5 après A1 ; D1 après D5 ; autres selon dépendances ; D6 indépendant |
| Spec A1 | `ScanFailedError` l.629-636 (et non l.626-636) ; fixture `filtered` « annotée », non prouvée (V6) |

## 3bis. Corrections V2.2 (seconde revue Kiro : recevable après corrections)

| Correction | Application |
|---|---|
| Étape 0 préalable | DOC-01 (Master, Tracking, spec A1 canonique, réconciliation des commits et références) sort de la séquence technique. Patch appliqué par le propriétaire, dépôt vérifié, décisions présentes dans les fichiers canoniques. **SMB-01 ne commence qu'après.** (`PLAN` §5.0) |
| Skill Kiro retiré du paquet actif | La proposition de Skill Kiro (fichier et diff) n'est plus incluse. Fichiers conservés dans le dossier d'audit. Retirée du manifeste, du README, de la transmission et du diff global. Skill canonique non modifié. Diff Cursor (casse seule) conservé. |
| CA-16 séparé de A1 | CA-16 est rattaché à D1 (`SENTINEL-TCP-STATES.md` §9.2). D5 produit la preuve dans `events.details` ; D1 distingue événements nouveaux et historiques. A1 n'exige ni `proof` ni changement de libellé. Chaîne : A1 → D5 → D1. |

## 4. Points de contrôle demandés à Kiro (seconde vérification)

1. **Dossier examiné** : identifier le dossier réellement examiné par Kiro. `docs-processes/` et les doublons `(1)`/`(2)` n'existent pas dans l'environnement d'audit.
2. **A1** : vérifier que le ticket parent unique couvre tous les points approuvés (§2 du plan) et qu'aucun autre ticket A1 autonome ne subsiste.
3. **Chemins** : `ls` sur chaque chemin cité dans les propositions, dans le clone `9034f01`.
4. **Références de lignes** : `detect/smb_enum.py` l.133, l.150, l.157, l.169, l.183, l.509 ; `tests/test_smb_enum.py` l.122 ; `sentinel/monitor.py` l.264, l.276-282 ; `detect/tcp_scan.py` l.337, l.444, l.558, l.601 ; `sentinel/baseline.py` l.481-483 (appel sans `strict=True`) ; `sentinel/sentinel_manager.py` l.291, l.300-362, l.460-505, l.629-636 (vidage l.632-633) ; `tests/test_tcp_scan.py` l.291-315, l.442-455, l.897-909 ; `.cursor/rules/sentinelX.mdc` l.9.
5. **Emplacement de la spec** : valider `docs/SENTINEL-TCP-STATES.md` (EMP-01).
6. **Statut de `ARENA.md`** : confirmer son rôle canonique ou non.
7. **Statuts** : aucune proposition présentée comme décision approuvée ; aucun ticket présenté comme validé.
8. **SMB-02** : la version 1.3.10 et `-oJ` sont rapportés, non reproduits dans l'environnement d'audit. À confirmer par Kiro si possible, par lecture de `--help`.
9. **L1 et L2** : valider leur rattachement à **D6** (ticket indépendant hors A1), et non à A1.
10. **CRED-01** : valider que le périmètre se limite aux chemins dont la divergence sous sudo est démontrée (§4.3 du plan), et que le constat NFC/NFD reste un constat distinct, sans ticket.
11. **Étape 0** : vérifier que DOC-01 est sorti de la séquence technique (`PLAN` §5.0) et que SMB-01 ne commence qu'après l'Étape 0.
12. **CA-16 et numérotation** : vérifier que CA-16 est rattaché à D1 et que les critères A1 (CA-1 à CA-15, CA-17, CA-18) n'exigent ni `proof` ni changement de libellé. Les identifiants CA-n sont propres à chaque document : `SPEC-A1-consolidee.md` (CA-11 = libellé) ne correspond pas à `SENTINEL-TCP-STATES.md` (CA-11 = anciens événements). Référence canonique : `SENTINEL-TCP-STATES.md`.

## 5. Décisions ouvertes au propriétaire

DEC-02 (validation du plan ; condition de l'Étape 0) ; DEC-03 (libellé D1) ; DEC-04 (D6 C2/C3, au ticket D6) ; DEC-05 (procédure de migration, seulement si CRED-01 change un chemin) ; DEC-07 (SCO-02) ; DEC-08 (SCO-03) ; DEC-09 (SCO-01) ; DEC-11 (A2-01) ; DEC-12 (OS-01) ; DEC-14 (chemins absolus, défauts et messages de code) ; DEC-16 (REP-01) ; DEC-17 (normalisation NFC/NFD de la phrase du coffre, constat distinct).

## 6. Réserves

- Aucune exécution d'`enum4linux-ng` réel ; aucun scan réel ; harnais A1 avec sondes remplacées.
- Paquet de revue : `paquet-Kiro-propositions-globales-v2.2.zip` (SHA-256 dans `SHA256-paquet-zip.txt`, hors du zip). Le paquet v2.1 (`paquet-Kiro-propositions-globales-v2.zip`) est remplacé ; il contient encore le Skill Kiro retiré en V2.2 et ne doit pas être transmis. **Non transmis** à Nova ni à Kiro : aucun canal disponible ; le paquet est déposé.
- `~/.netlab` non lu, non modifié (4744 entrées mesurées antérieurement). Aucun secret demandé.
- Dates des rapports antérieurs non réconciliées (leur date de rédaction d'origine n'est pas tracée).
- Structure réelle des `<extrareasons>` Nmap et sémantique de `extraports state=open` : non vérifiées hors fixtures.
- Les clones locaux non alignés (`/home/user/sentinelX`, `sentinelX-impl`, `sentinelX-reference`) n'ont pas été touchés.

## 7. Sommes antérieures (historique, non recalculées)

Les fichiers suivants ont été corrigés volontairement dans ce cycle. Leurs sommes antérieures ne correspondent donc plus. **Ces écarts sont attendus.** Les sommes antérieures sont conservées, non réécrites. La somme de référence pour la version 2 est `SHA256SUMS-propositions-globales.txt`.

| Fichier de sommes | Écarts constatés | Motif |
|---|---|---|
| `SHA256SUMS-A1-formalisation.txt` | `PROPOSITION-A1-formalisation-TCP.md` | Date et `ScanFailedError` corrigés (l.3, l.248) |
| `SHA256SUMS-A1-verification.txt` | `SPEC-A1-consolidee.md`, `PROPOSITION-A1-formalisation-TCP.md` | Corrections l.3, l.49, l.195, l.264 (spec) et date (proposition) ; corrections de cohérence de la v2.1 (§12 du plan). Somme de remplacement : `SHA256SUMS-A1-verification-v2.txt` |
| `SHA256SUMS.txt` | proposition de Skill Kiro (retirée en V2.2), `skills-proposees/sentinelX.mdc`, `docs-proposees/IMPLEMENTATION-TRACKING-section-audit.md`, `diffs/impl-tracking.diff`, `diffs/sentinelX.mdc.diff` | Propositions remplacées (version 2) ; anciens diffs déplacés dans `diffs/archive-v1/` |

Les autres fichiers de sommes (`SHA256SUMS-A1.txt`, `SHA256SUMS-B2.txt`) sont **OK**.
