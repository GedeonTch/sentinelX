# #018 — Design technique

## Fichier unique

```
cleanup/artifact_detector.py
cleanup/__init__.py
```

Pas de dépendance vers `core/database.py` pour lire les données —
uniquement les chemins qui y sont définis sont réutilisés via import
des constantes de chemin (pas de connexion SQLite).

---

## Implémentation

```python
# cleanup/artifact_detector.py

from pathlib import Path
from dataclasses import dataclass
from enum import Enum
from typing import List

from core.logger import display


class ArtifactType(str, Enum):
    SESSION_DB  = "session_db"
    SENTINEL_DB = "sentinel_db"
    REPORT      = "report"
    TMP_DIR     = "tmp_dir"


@dataclass
class Artifact:
    path: Path
    artifact_type: ArtifactType
    session_id: str
    exists: bool
    size_bytes: int


def detect_artifacts(session_id: str) -> List[Artifact]:
    """Return all NetLab artifacts for a session that currently exist on disk.

    Validates session_id, then checks known paths by convention.
    Returns only artifacts that exist. Never modifies anything.

    Args:
        session_id: Audit session identifier.

    Returns:
        List[Artifact]: Existing artifacts owned by this session.

    Raises:
        ValueError: If session_id is invalid.
    """
    from core.database import _validate_session_id
    _validate_session_id(session_id)

    artifacts = []
    artifacts.extend(_detect_session_db(session_id))
    artifacts.extend(_detect_reports(session_id))
    artifacts.extend(_detect_tmp_dir(session_id))
    # Note: sentinel DBs are keyed by network_id, not session_id.
    # They are long-lived and should NOT be deleted by a session cleanup.
    # Sentinel DB cleanup requires a separate explicit command (out of V1 scope).

    return [a for a in artifacts if a.exists]
```

### Fonctions internes

```python
def _detect_session_db(session_id: str) -> List[Artifact]:
    path = Path.home() / ".netlab" / "sessions" / f"{session_id}.db"
    return [Artifact(
        path=path,
        artifact_type=ArtifactType.SESSION_DB,
        session_id=session_id,
        exists=path.exists(),
        size_bytes=path.stat().st_size if path.exists() else 0,
    )]


def _detect_reports(session_id: str) -> List[Artifact]:
    """Find report files matching <session_id>.<format>."""
    reports_dir = Path.home() / ".netlab" / "reports"
    artifacts = []
    if reports_dir.exists():
        for path in reports_dir.iterdir():
            # Strict: filename must start with session_id followed by a dot
            if path.name.startswith(f"{session_id}.") and path.is_file():
                artifacts.append(Artifact(
                    path=path,
                    artifact_type=ArtifactType.REPORT,
                    session_id=session_id,
                    exists=True,
                    size_bytes=path.stat().st_size,
                ))
    return artifacts


def _detect_tmp_dir(session_id: str) -> List[Artifact]:
    path = Path("/tmp") / f"netlab-{session_id}"
    return [Artifact(
        path=path,
        artifact_type=ArtifactType.TMP_DIR,
        session_id=session_id,
        exists=path.exists(),
        size_bytes=0,  # directories don't have a simple size
    )]
```

---

## Pourquoi les sentinel DBs sont exclues

Les DBs sentinel (`~/.netlab/sentinel/<network_id>.db`) sont liées à
une **identité réseau**, pas à une session d'audit. Les supprimer dans
un cleanup de session casserait la baseline persistée (violant la règle A2).

Si l'utilisateur veut effacer une baseline sentinel, cela doit être
une commande dédiée explicite (`netlab sentinel reset`) — hors scope V1.

---

## Sécurité

Le module valide `session_id` via `_validate_session_id()` (regex stricte)
avant toute construction de chemin. Aucune interpolation libre dans les paths.

Tous les chemins construits sont explicitement sous :
- `~/.netlab/sessions/`
- `~/.netlab/reports/`
- `/tmp/netlab-<session_id>/`

Aucune traversée parent (`../`) possible avec une `session_id` valide.
