# #019 — restore.py : design technique

## Dépendance

`restore.py` dépend directement de `artifact_detector.py` (#018).
Il ne peut être implémenté qu'après #018.

---

## Signature publique

```python
def restore_session(session_id: str) -> None:
    """Interactive cleanup of all NetLab artifacts for a session.

    Steps: detect → validate → preview → confirm ("yes") → delete → verify.

    Args:
        session_id: The session to clean up.

    Raises:
        ValueError: If session_id is invalid.
    """
```

---

## Flux interne

```python
def restore_session(session_id: str) -> None:
    from core.database import _validate_session_id
    _validate_session_id(session_id)

    # Step 1 — Detect
    artifacts = detect_artifacts(session_id)
    if not artifacts:
        display("[green]No artifacts found for this session.[/green]")
        return

    # Step 2 — Validate ownership
    safe, skipped = _validate_artifacts(artifacts, session_id)
    for a in skipped:
        display(f"[yellow]⚠ SKIP — out of scope: {a.path}[/yellow]")

    if not safe:
        display("[yellow]No artifacts passed ownership validation.[/yellow]")
        return

    # Step 3 — Preview
    _render_preview(safe)

    # Step 4 — Confirmation ("yes" in full)
    raw = input("Type 'yes' to confirm deletion: ").strip()
    if raw != "yes":
        display("[yellow]Cleanup cancelled.[/yellow]")
        return

    # Step 5 — Action + Verify
    results = _delete_artifacts(safe)
    _render_results(results)
```

---

## Validation d'ownership

```python
_ALLOWED_ROOTS = [
    Path.home() / ".netlab",
]

def _is_owned(path: Path, session_id: str) -> bool:
    """Return True if path is under an allowed root and belongs to session_id."""
    tmp_root = Path("/tmp") / f"netlab-{session_id}"
    allowed = list(_ALLOWED_ROOTS) + [tmp_root]

    # Must be under an allowed root
    for root in allowed:
        try:
            path.relative_to(root)
            break
        except ValueError:
            continue
    else:
        return False

    # Name must match session_id convention
    name = path.name
    return (
        name == f"{session_id}.db"
        or name.startswith(f"{session_id}.")
        or path == tmp_root
    )
```

---

## Suppression

```python
@dataclass
class DeletionResult:
    artifact: Artifact
    success: bool
    error: str = ""

def _delete_artifacts(artifacts: List[Artifact]) -> List[DeletionResult]:
    results = []
    for artifact in artifacts:
        try:
            if artifact.artifact_type == ArtifactType.TMP_DIR:
                import shutil
                shutil.rmtree(artifact.path, ignore_errors=False)
            else:
                artifact.path.unlink()
            # Verify
            if artifact.path.exists():
                results.append(DeletionResult(artifact, False, "File still exists after deletion"))
            else:
                results.append(DeletionResult(artifact, True))
        except Exception as exc:
            results.append(DeletionResult(artifact, False, str(exc)))
    return results
```

---

## Ordre de suppression

Les artefacts sont supprimés dans cet ordre :
1. Rapports (HTML, JSON) — les moins critiques
2. Répertoire tmp — s'il existe
3. DB de session — en dernier

Pourquoi la DB en dernier : elle contient l'historique de la session.
La supprimer en dernier garantit qu'en cas d'interruption,
les données de session sont encore disponibles pour un retry.

---

## Règles

- ZERO import sqlite3
- ZERO print() direct
- Toujours vérifier après suppression (step 5 du contrat)
- En cas d'erreur sur un artefact → continuer avec les autres
- L'input "yes" doit être lu depuis stdin standard — compatible avec les tests
