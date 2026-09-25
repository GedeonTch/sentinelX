# #019 — Tasks

## Prérequis

#018 doit être DONE avant de commencer #019.

## Périmètre

Fichiers créés :
- `cleanup/restore.py`
- `tests/test_restore.py`

Fichiers modifiés :
- `cli.py` — brancher `netlab cleanup --session` sur `restore_session()`

---

## Task 1 — cleanup/restore.py

Implémenter :
- `restore_session(session_id: str) -> None`
- `_validate_artifacts(artifacts, session_id) -> (safe, skipped)`
- `_render_preview(artifacts)`
- `DeletionResult` dataclass
- `_delete_artifacts(artifacts) -> List[DeletionResult]`
- `_render_results(results)`

Contraintes :
- ZERO sqlite3, ZERO print()
- "yes" obligatoire (case-sensitive, mot entier)
- DB de session supprimée en dernier
- Vérification après chaque suppression

---

## Task 2 — tests/test_restore.py (MANDATORY before integration)

Tests requis :

| Test | Ce qu'il vérifie |
|---|---|
| Nominal complet | DB + rapport → supprimés après "yes" |
| Annulation "n" | Rien supprimé, exit propre |
| Annulation "y" seul | Refusé, rien supprimé |
| Annulation "YES" | Refusé (case-sensitive) |
| Annulation "" vide | Refusé |
| Artefact hors scope | Skippé avec warning, pas supprimé |
| Liste vide | Message + sortie propre |
| Erreur permission | Erreur affichée, autres traités |
| Artefact disparu entre preview et action | Pas d'erreur fatale |
| Verify échec | DeletionResult.success=False |
| session_id invalide | ValueError levée |

---

## Task 3 — Brancher cli.py

Remplacer le stub `netlab cleanup --session` par :

```python
from cleanup.restore import restore_session
restore_session(session)
```

---

## Task 4 — README pédagogique

`cleanup/restore_README.md` (français) :
- Les 5 étapes du cycle de cleanup
- Pourquoi "yes" en entier
- Pourquoi la DB est supprimée en dernier
- Règles de sécurité (out-of-scope = skip)

---

## Critère de DONE

```
[ ] restore_session() implémentée
[ ] "yes" enforced (case-sensitive, mot entier)
[ ] DB supprimée en dernier
[ ] Verify après chaque suppression
[ ] Out-of-scope → skip + warning
[ ] Tous les tests passent (nominal + edge + sécurité)
[ ] ZERO sqlite3, ZERO print()
[ ] cli.py branché sur restore_session
[ ] README créé
[ ] Commit propre
```
