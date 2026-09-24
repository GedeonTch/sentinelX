# A4 — Pipeline CLI non relié : requirements

## Problème

`netlab scan` crée une session et affiche un message stub. Aucun module
de scan n'est appelé. Le produit est inutilisable de bout en bout.

`netlab sentinel start/status/stop` et `netlab report generate` sont
également des stubs.

## Objectif

Relier le CLI aux modules existants pour produire un audit complet
et utilisable en une commande :

```
netlab scan --target 192.168.1.0/24 --profile normal
```

Résultat attendu :
1. Découverte des hôtes actifs (device_fingerprint)
2. Scan TCP/UDP des ports ouverts (tcp_scan, udp_scan)
3. Enrichissement CVE (service_detection)
4. Détection des misconfigurations (misconfig_detection)
5. Enrichissement des explications depuis la KB (knowledge_base)
6. Scoring des risques (risk_scorer)
7. Sauvegarde de tous les Findings en DB (database)
8. Affichage du résumé de la session

## Périmètre exact

### Ce qui est branché

| Commande | Modules appelés |
|---|---|
| `netlab scan` | device_fingerprint → tcp_scan → udp_scan → service_detection → misconfig_detection → knowledge_base → risk_scorer → save_findings |
| `netlab sentinel start` | sentinel_manager.start() |
| `netlab sentinel status` | sentinel_manager.status() |
| `netlab sentinel stop` | sentinel_manager.stop() |
| `netlab report generate` | reports.generator.generate_report() |

### Ce qui reste stub (hors scope A4)

- `netlab findings rescan` — nécessite une logique de diff entre deux scans
- `netlab cleanup` — tickets #018–#019 pas encore implémentés
- `netlab sentinel allow/unallow/whitelist/history` — Point B de la spec Sentinel

## Règles

- ZERO logique métier dans cli.py — uniquement des appels et de l'affichage
- Chaque étape du pipeline peut être skippée si elle échoue (scan partiel > pas de scan du tout)
- La confirmation y/n a déjà lieu dans chaque module de scan — le CLI ne la redemande pas
- `netlab scan` demande UNE confirmation globale avant de lancer la chaîne, puis laisse chaque module gérer ses propres confirmations si nécessaire
- Les Findings sont sauvegardés en DB au fur et à mesure (pas en bloc à la fin) pour ne pas perdre les résultats si une étape échoue

## Critères de succès

1. `netlab scan --target 192.168.1.26` produit des Findings réels en DB
2. `netlab findings list --session <id>` affiche ces Findings
3. `netlab report generate --session <id> --format html` produit un fichier HTML
4. `netlab sentinel start --target 192.168.1.0/24` démarre la surveillance
5. `netlab sentinel status` affiche ACTIF/DÉGRADÉ/INACTIF
6. `netlab sentinel stop` arrête proprement
