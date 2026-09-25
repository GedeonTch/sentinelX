# #018 — cleanup/artifact_detector.py : requirements

## Rôle

`artifact_detector.py` est la première étape du cycle de cleanup.
Il répond à une seule question : **"Quels fichiers NetLab a-t-il créés ou
modifiés pendant cette session ?"**

Il ne supprime rien. Il détecte uniquement.
`restore.py` (#019) prend ensuite cette liste et exécute les suppressions.

---

## Qu'est-ce qu'un artefact NetLab ?

En V1, NetLab crée exactement deux types de fichiers :

### Type 1 — DB de session

```
~/.netlab/sessions/<session_id>.db
```

Créé par `core/database.init_db()` au démarrage de `netlab scan`.
Appartient à la session si son nom correspond exactement au `session_id`.

### Type 2 — DB sentinel

```
~/.netlab/sentinel/<network_id>.db
```

Créé par `core/database.init_sentinel_db()` au démarrage de `netlab sentinel`.
Appartient à la session Sentinel identifiée par `network_id`.

### Type 3 — Rapports générés

```
~/.netlab/reports/<session_id>.<format>
```

Créé par `reports/generator.py`. Appartient à la session si son nom commence
par le `session_id`.

### Type 4 — Répertoire temporaire (si utilisé)

```
/tmp/netlab-<session_id>/
```

Réservé pour une utilisation future (scans avec artefacts temporaires).
En V1, ce répertoire n'est pas créé automatiquement — mais le détecteur
doit en vérifier l'existence par précaution.

---

## Comment l'ownership est déterminé

L'ownership est déterminé par **convention de nommage**, pas par métadonnées OS :

| Fichier | Règle d'ownership |
|---|---|
| `~/.netlab/sessions/<session_id>.db` | Nom = `session_id` exact |
| `~/.netlab/sentinel/<network_id>.db` | Lié à une session via `sentinel_state.target_network` |
| `~/.netlab/reports/<session_id>.*` | Nom commence par `session_id` |
| `/tmp/netlab-<session_id>/` | Nom = `netlab-` + `session_id` exact |

**Règle de sécurité absolue** : tout fichier dont le nom ne correspond pas
exactement à la convention → SKIP + warning. Jamais de glob large.

---

## Structure de retour

```python
from dataclasses import dataclass
from enum import Enum
from typing import List
from pathlib import Path


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
    exists: bool        # True si le fichier existe au moment de la détection
    size_bytes: int     # 0 si inexistant
```

`detect_artifacts(session_id: str) -> List[Artifact]`

Retourne uniquement les artefacts qui **existent** (`exists=True`).
Un artefact inexistant n'est pas listé — il n'y a rien à supprimer.

---

## Contraintes

- ZERO import sqlite3 (n'a pas besoin d'accéder aux données, seulement aux chemins)
- ZERO print() — display via core/logger.py
- ZERO modification de fichiers
- Retourne une liste vide si aucun artefact trouvé — pas d'erreur
- Validation stricte des chemins : ne jamais traverser en dehors de `~/.netlab/` et `/tmp/netlab-<session_id>/`
- Le `session_id` doit passer la validation existante (`_validate_session_id` de `core/database.py`)

---

## Critères de succès

1. `detect_artifacts("session-abc123")` retourne la DB de session si elle existe
2. `detect_artifacts("session-xyz")` retourne aussi les rapports associés
3. Un `session_id` invalide lève `ValueError` (via `_validate_session_id`)
4. Aucun fichier hors scope n'est jamais listé
5. Si aucun artefact n'existe → `[]` sans erreur
