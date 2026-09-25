# #018 — Tasks

## Périmètre

Fichiers créés :
- `cleanup/__init__.py`
- `cleanup/artifact_detector.py`
- `tests/test_artifact_detector.py`

Aucun autre fichier modifié.

---

## Task 1 — cleanup/artifact_detector.py

Créer le module complet :

- `ArtifactType` enum
- `Artifact` dataclass
- `detect_artifacts(session_id: str) -> List[Artifact]`
- `_detect_session_db()`, `_detect_reports()`, `_detect_tmp_dir()`

Contraintes :
- ZERO import sqlite3
- ZERO print() direct
- Validation session_id via `_validate_session_id`
- Retourne `[]` si aucun artefact — jamais d'exception pour absence

---

## Task 2 — tests/test_artifact_detector.py

Tests requis :

| Test | Ce qu'il vérifie |
|---|---|
| Nominal session DB | DB existe → retournée dans la liste |
| Nominal rapport HTML | Report existe → retourné |
| Nominal rapport JSON | Report existe → retourné |
| Nominal tmp dir | `/tmp/netlab-<id>/` existe → retourné |
| Aucun artefact | Rien n'existe → retourne `[]` |
| session_id invalide | `ValueError` levée |
| session_id avec `..` | `ValueError` levée (path traversal) |
| Seuls les fichiers du bon session_id | Fichier d'une autre session ignoré |
| Sentinel DB non listée | `~/.netlab/sentinel/*.db` jamais dans la liste |

Tous les tests utilisent `tmp_path` (pas de vrais fichiers `~/.netlab`).

---

## Task 3 — README pédagogique

`cleanup/artifact_detector_README.md` (français) :
- Qu'est-ce qu'un artefact
- Pourquoi les sentinel DBs sont exclues
- Relation avec restore.py

---

## Critère de DONE

```
[ ] artifact_detector.py créé et tourne sans erreur
[ ] ArtifactType, Artifact, detect_artifacts implémentés
[ ] Sentinel DBs exclues
[ ] Tests passent (nominal + edge + sécurité)
[ ] ZERO sqlite3, ZERO print()
[ ] README créé
[ ] Commit propre
```
