# Tableau des tickets et dépendances — plan global v2

**Statut : PROPOSITION.** Aucun ticket n'est approuvé, autorisé ni validé. Commit de référence : `9034f01` (`origin/a4-arena`). Date de rédaction : 2026-11-12. Source détaillée : `docs-proposees/PLAN-tickets-global.md`.

**Légende.** *Bloqué par* : ce qui doit être réglé avant. *Bloque* : tickets qui attendent celui-ci. *Suivant* : ticket désigné à la validation.

| Ticket | Titre | Priorité | Statut | Bloqué par | Bloque | Suivant (si validé) |
|---|---|---|---|---|---|---|
| SMB-01 | `smb_enum` : échec d'outil lu comme « aucun résultat » (rc ignoré, stdout/stderr fusionnés, repli texte cassé) | P1 | Proposition ; premier après l'Étape 0 | Étape 0 | A1 (ordre) | A1 |
| SMB-02 | Vérification de compatibilité `enum4linux-ng` (1.3.10 rapportée ; `-oJ` ; `--json` absent) — intégrée à SMB-01 | P2 | Vérification | SMB-01 | TOOL-01 | — (dans SMB-01) |
| A1 | Fiabilisation des états TCP de Sentinel Monitor (ticket parent ; TCP-01 à TCP-03 sous-tâches ; TCP-04 non-régression) | P1 | **Non terminé** ; autorisation d'implémentation requise | — | CRED-01 (ordre), D5 | CRED-01 |
| TCP-01 | (sous-tâche A1) Parsing, attribution, validation XML commune | — | Inclus dans A1 | — | TCP-02 | — |
| TCP-02 | (sous-tâche A1) Compteurs par port connu ; hôte absent ; `closed → filtered` | — | Inclus dans A1 | TCP-01 | TCP-03 | — |
| TCP-03 | (sous-tâche A1) Hôte entièrement filtré ; tests S1–S11 | — | Inclus dans A1 | TCP-02 | — | — |
| TCP-04 | (non-régression A1) Compteurs non restaurés après redémarrage (S2, S3, S10) | — | Inclus dans A1 | TCP-02 | — | — |
| CRED-01 | Résolveurs de chemins sous `Path.home()` ≠ utilisateur réel (sudo) | P1 | Planifié, après A1 | A1 (ordre), DEC-05 | D5 (ordre) | D5 |
| D5 | Preuve de fermeture dans `events.details` (D5-B) | P3 | **Conception approuvée** ; implémentation non autorisée | A1 | D1 | D1 |
| D1 | Présentation : distinction preuve / historique | P2 | Distinction approuvée ; libellé ouvert | D5, DEC-03 | — | TOOL-01 |
| D6 | Politique des ports filtrés à l'apprentissage baseline (hors A1) | P2 | Proposition ; **indépendant** | DEC-04 (au moment du ticket) | — | — (hors séquence) |
| TOOL-01 | `netlab doctor` ne vérifie que `--help` | P2 | Proposition | SMB-02 | — | REP-01 |
| DOC-01 | Dérives de la documentation maître (HEAD, commits, CONFIDENCE-CLI) | P2 | **Étape 0** (hors séquence technique) ; patch prêt, non appliqué à `docs/` | DEC-02 | SMB-01 (ordre) | SMB-01 |
| REP-01 | « 0 » du rapport = quota de notification | P2 | Proposition | DEC-16 | — | OS-01 |
| OS-01 | Timeouts OS Nmap et messages (causes non mesurées) | P2 | Hypothèse ; mesure d'abord | DEC-12 | — | SCO-01 |
| SCO-01 | Libellé « CVSS » | P2 | Partiel ; à confirmer | DEC-09 | — | SCO-02 |
| SCO-02 | Port `info` CONFIRMED dans le score global | P2 | Décision produit | DEC-07 | — | A2-01 |
| A2-01 | Résolution d'identifiants `findings show` / `sentinel findings show` | P2 | Proposition ; décision | DEC-11 | — | CRED-03 |
| CRED-03 | Message de coffre incomplet | P3 | Proposition | — | — | SCO-03 |
| SCO-03 | Ports 512–514 sans règle | P3 | Décision produit | DEC-08 | — | VERIFY-01 |
| VERIFY-01 | Findings `sentinel.*` en PARTIAL « Unsupported module » | P3 | Décision | — | — | DOC-02 |
| DOC-02 | Casse `.cursor/rules/sentinelX.mdc` l.9 ; chemins absolus `docs/MASTER-REFERENCE.md` | P3 | Proposition (casse reproduite ; Skill `impl-tracking.md` retiré du constat) | — | — | A2-02 |
| A2-02 | Nom de commande « rescan findings » (documentation) | P3 | Proposition | — | — | — (fin de l'ordre) |
| CRED-02 | `--service ssh` sans candidat SSH | — | **Conforme à T22 ; sans ticket** | — | — | — |
| NET-01 | Réseau `192.168.57.0/24` | — | **Non reproduite ; sans ticket de code** | — | — | — |

## Points de décision et de vérification (non des tickets)

| Réf. | Point | Type |
|---|---|---|
| DEC-02 | Validation du plan et des propositions documentaires après revue Kiro | Décision ouverte |
| DEC-03 | Libellé exact de D1 | Décision ouverte |
| DEC-04 | Politique D6 (C2 ou C3) | Décision ouverte, examinée au ticket D6 |
| DEC-05 | Emplacement du coffre et migration (CRED-01) | Décision ouverte |
| DEC-07, DEC-08, DEC-09, DEC-11, DEC-12, DEC-16 | Points produit ou mesure (SCO, A2, OS, REP) | Décisions ouvertes |
| DEC-14 | Chemins absolus : docs (DOC-02) et défauts de code `core/dependencies.py` l.48-49 | Décision ouverte pour le code |
| EMP-01 | Emplacement canonique de la spec A1 : `docs/SENTINEL-TCP-STATES.md` | Proposition, vérification Kiro |
| ARENA-ROLE | Statut canonique de `ARENA.md` (hors dépôt ; révisions 12 et 13 citées) | Point à vérifier |
| KIRO-DOSSIER | Dossier réellement examiné par Kiro (`docs-processes/`, `(1)`/`(2)` introuvables) | Point à vérifier |
