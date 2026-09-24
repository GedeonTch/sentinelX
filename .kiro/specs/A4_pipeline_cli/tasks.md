# A4 — Tasks

## Périmètre exact

Fichier modifié uniquement :
- `cli.py` — remplacement des stubs par les appels réels

Tests mis à jour :
- `tests/test_cli.py` — mocks pour les modules appelés

Aucun autre fichier modifié.

---

## Task 1 — `netlab scan` : pipeline complet

Remplacer le stub scan par le pipeline DISCOVER → DETECT → ASSESS → EXPLAIN.

Étapes dans l'ordre :
1. Créer session (déjà en place)
2. Confirmation unique `--yes` / `-y` ou prompt
3. `device_fingerprint(target, session_id)` → save_findings
4. `tcp_scan(ip, session_id, profile)` par hôte → save_findings
5. `udp_scan(ip, session_id, profile)` par hôte → save_findings
6. `enrich_findings(port_findings + udp_findings)` — CVE
7. `detect_misconfigs(ip_findings, session_id)` par hôte
8. `get_explanation_for_finding` par Finding
9. `score_findings(all)` + `update_finding_risk_score` en DB
10. `close_session(session_id)`
11. `_render_scan_summary(session_id, findings)`

Gestion des erreurs : try/except par étape, scan partiel acceptable.

Nouvelle option : `--yes / -y` pour bypasser les confirmations intermédiaires.

---

## Task 2 — `netlab sentinel start/status/stop`

Remplacer les 3 stubs sentinel par :
- `start` : appel à `sentinel_manager.start(target, session_id, force_relearn)`
  → ajouter `--target` et `--relearn` comme options
- `status` : appel à `sentinel_manager.display_status(session_id)`
  → ajouter `--session` comme option obligatoire
- `stop` : appel à `sentinel_manager.stop(session_id)`
  → ajouter `--session` comme option obligatoire

---

## Task 3 — `netlab report generate`

Remplacer le stub report par :
- Appel à `reports.generator.generate_report(session_id, format, output_path)`
- Option `--output / -o` pour le chemin de sortie (défaut : `~/.netlab/reports/<session>.<format>`)
- PDF refusé explicitement avec message clair

---

## Task 4 — `_render_scan_summary()`

Nouvelle fonction d'affichage (dans cli.py, pas de logique métier) :
- Table Rich avec counts par sévérité
- Score global si calculé
- Session ID
- Suggestions de commandes suivantes

---

## Task 5 — Mettre à jour tests/test_cli.py

Pour `netlab scan` :
- Mocker `recon.device_fingerprint.fingerprint` → return []
- Mocker `detect.tcp_scan.tcp_scan` → return []
- Mocker `detect.udp_scan.udp_scan` → return []
- Mocker `detect.service_detection.enrich_findings` → return []
- Mocker `detect.misconfig_detection.detect_misconfigs` → return []
- Mocker `core.risk_scorer.score_findings` → return []
- Mocker `core.database.save_findings`
- Vérifier exit_code=0 et que les modules sont appelés

Pour sentinel et report : mettre à jour les tests de stub → tests d'appel.

---

## Critère de DONE

```
[ ] netlab scan --target 192.168.1.26 produit des Findings réels en DB
[ ] netlab findings list --session <id> les affiche
[ ] netlab report generate --session <id> --format html produit un fichier
[ ] netlab sentinel start --target ... démarre réellement la surveillance
[ ] netlab sentinel status --session ... affiche ACTIF/DÉGRADÉ/INACTIF
[ ] netlab sentinel stop --session ... arrête proprement
[ ] Tests CLI mis à jour, 0 régression
[ ] ZERO logique métier dans cli.py
[ ] Commit propre
```
