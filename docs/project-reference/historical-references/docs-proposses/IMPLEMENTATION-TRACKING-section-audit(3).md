# Section à insérer dans `docs/IMPLEMENTATION-TRACKING.md`

> **PROPOSITION — en attente de décision du propriétaire.** Non insérée dans le fichier en place.
> Aucune de ces lignes ne vaut approbation d'un ticket. Aucun statut `[x]` n'est modifié.
> Sources : `RAPPORT-audit-global.md` et `PLAN-correction.md` (référence `origin/a4-arena` = `9034f01`).

## Anomalies d'audit (en attente de décision du propriétaire)

| ID | Domaine | Anomalie | Statut | Priorité proposée | Décision requise |
|---|---|---|---|---|---|
| C-1 | Réseau | `192.168.57.0/24` surveillé de façon inattendue | Cause non établie (diagnostic propriétaire requis) | P1 (P0 si confirmé) | Origine ; arrêt éventuel |
| B3-1/2/3 | Outils externes | `smb_enum` : échec de l'outil présenté comme « no shares » ; option `--json` probablement inexistante ; repli texte sans comptes | Reproduit (faux binaire, isolé) ; `--json` à vérifier sur version installée | P1 | Politique d'échec ; syntaxe retenue |
| B2-1 | Credentials | Coffre sous `Path.home()` (sudo : `/root`), bases sous `_real_user_home()` | Reproduit (simulation de chemin) | P1 | Emplacement ; procédure de migration |
| A3-1 | Rapport | « 0 » = quota de notification 60 min, sans filtre de type | Reproduit | P2 | Libellé |
| A1-1 | Transitions | Port `filtered` = `port_not_open` identique à fermé | Reproduit ; spec silencieuse | P2 | Événement distinct ou non |
| A1-2 | Transitions | Compteurs d'absence non restaurés au redémarrage | Silence de `ARENA.md` §9.8 | P3 | Restaurer ou documenter |
| B5-1 | Scoring | « CVSS 5.0 » = `risk_score` interne (info 5 × 1,00 × 1,00) | Confirmé (code) | P2 | Libellé |
| B5-2 | Scoring | Port `info` CONFIRMED dans le score global | Confirmé (code) | P2 | Inventaire hors score ? |
| B5-3 | Règles | Aucune règle pour 512-514 | Confirmé (absence) | P3 | Risque voulu ? |
| B4-1/2 | Découverte OS | Timeout 60 s codé en dur, sortie jetée ; messages confondus | Causes non mesurées | P2 | Mesure ; délai configurable |
| A2-1 | UX identifiants | `sentinel findings show` refuse un préfixe accepté par `findings show` | Confirmé (code) | P2 | Option (a), (b) ou (c) |
| B2-2 | Credentials | `--service ssh` : aucun candidat SSH au catalogue par défaut | Reproduit | P2 | Catalogue SSH ou `--dict` |
| B2-3 | Credentials | Message de coffre incomplet (règle des 8 caractères distincts absente) | Confirmé (code) | P3 | Message |
| B3-4 | Outils externes | `netlab doctor` ne vérifie qu'avec `--help` | Confirmé (code) | P2 | Contrôle des options |
| B1-1 | VERIFY | Findings `sentinel.*` en PARTIAL « Unsupported module » | Confirmé (code) | P3 | Contrôle dédié ou non |
| A2-2 | CLI | `findings rescan` existe ; nom demandé « rescan findings » | Documentation | P3 | Aucune nouvelle commande |

## Dérives de documentation constatées

- HEAD `3657498` déclaré dans ce fichier, `MASTER-REFERENCE.md` (§2, §6.4) et `impl-tracking.md` ; `9034f01` non consigné.
- CONFIDENCE-CLI « commit en attente » alors que `85870ac` existe.
- `MASTER-REFERENCE.md` §2 : chemin `/home/anonymous/sentinelX` (autre poste).
- `ARENA.md` cité comme téléchargement propriétaire : chemin réel `uploads/ARENA.md`.

## Restrictions de l'audit (à conserver)

- Aucune modification de code ni de tests ; aucun commit ni push sans demande.
- Aucune lecture ou modification de `~/.netlab` ; aucune saisie de secret.
- Aucun scan réel ni test de credential ; reproduction seulement en isolation.
- `docs/MASTER-REFERENCE.md` n'est pas modifié.
- Clone `/tmp/audit-sentinelX` créé pendant l'audit : à supprimer sur demande seulement.
