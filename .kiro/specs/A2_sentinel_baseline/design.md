# A2 — Design technique

## Principe

Introduire un `network_id` stable dérivé de l'identité réseau.
Ce `network_id` sert de clé pour ouvrir toujours la même DB Sentinel
pour un réseau donné, indépendamment du run courant.

---

## 1. network_id — calcul

Le `network_id` est un hash SHA-256 tronqué (12 caractères hex) du triplet :

```python
import hashlib

def compute_network_id(identity: NetworkIdentity) -> str:
    """Derive a stable, filesystem-safe identifier from a NetworkIdentity.

    Uses SHA-256 of "target_network|gateway_ip|gateway_mac" (lowercase).
    Truncated to 12 hex chars — collision probability negligible for lab use.

    Example:
        NetworkIdentity("192.168.1.0/24", "192.168.1.1", "aa:bb:cc:dd:ee:ff")
        → "a3f9c2b1e047"
    """
    raw = f"{identity.target_network}|{identity.gateway_ip}|{identity.gateway_mac}".lower()
    return hashlib.sha256(raw.encode()).hexdigest()[:12]
```

Propriétés :
- Déterministe : le même réseau donne toujours le même `network_id`
- Stable : survit aux redémarrages, aux changements de process
- Safe : utilisable comme nom de fichier sur Linux et Windows
- Compact : 12 chars suffisent pour un usage lab

---

## 2. DB Sentinel dédiée

Nouveau chemin : `~/.netlab/sentinel/<network_id>.db`

```python
def get_sentinel_db_path(network_id: str) -> Path:
    db_dir = Path.home() / ".netlab" / "sentinel"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / f"{network_id}.db"
```

Cette DB contient les mêmes tables que les sessions d'audit (assets, baseline,
events) mais son cycle de vie est lié au réseau, pas à un run.

Validation du `network_id` : même regex que `session_id`
(`^[a-zA-Z0-9_-]{1,64}$` — les 12 chars hex satisfont cette contrainte).

---

## 3. Modifications par fichier

### core/database.py

Ajouter :
```python
def get_sentinel_db_path(network_id: str) -> Path
def get_sentinel_connection(network_id: str) -> sqlite3.Connection
def init_sentinel_db(network_id: str) -> None  # CREATE TABLE IF NOT EXISTS
```

Les fonctions existantes (`get_db_path`, `get_connection`, `init_db`) restent
inchangées — elles continuent de gérer les sessions d'audit standard.

Les fonctions Sentinel CRUD existantes (`save_baseline_entry`,
`get_baseline_entries`, `baseline_exists`, `delete_baseline_for_identity`,
`save_event`, `get_events`, etc.) reçoivent un paramètre supplémentaire
optionnel `use_sentinel_db: bool = False` — quand True, elles utilisent
`get_sentinel_connection(network_id)` au lieu de `get_connection(session_id)`.

Alternative plus propre (recommandée) : dupliquer les fonctions Sentinel CRUD
avec un préfixe `sentinel_` qui prennent `network_id` au lieu de `session_id`.
Cela évite de modifier les signatures existantes et garde la séparation nette.

**Option retenue : fonctions dédiées avec préfixe `sentinel_`.**

### sentinel/baseline.py

Ajouter `compute_network_id(identity: NetworkIdentity) -> str`.

Modifier `learn_baseline`, `get_baseline`, `baseline_exists` pour utiliser
`network_id` (via les nouvelles fonctions DB) au lieu de `session_id`.

La signature publique reste compatible :
```python
# Avant
def baseline_exists(session_id: str, identity: NetworkIdentity) -> bool

# Après
def baseline_exists(network_id: str, identity: NetworkIdentity) -> bool
```

Le `network_id` est toujours calculé depuis l'identité réseau avant l'appel.

### sentinel/sentinel_manager.py

Modifier `start()` :

```python
# Avant (cassé)
session_id = session_id or f"sentinel-{uuid.uuid4().hex[:8]}"

# Après
identity = detect_network_identity(target_network)
network_id = compute_network_id(identity)
# session_id reste pour le tracking du run courant
run_session_id = session_id or f"sentinel-run-{uuid.uuid4().hex[:8]}"
```

Le `network_id` sert à ouvrir la DB baseline.
Le `run_session_id` sert à enregistrer ce démarrage spécifique dans la table
sessions (pour savoir quand Sentinel a tourné, combien de temps, etc.).

`status()` et `stop()` utilisent le `network_id` pour retrouver l'état.

---

## 4. Flux corrigé

```
netlab sentinel start --target 192.168.1.0/24
    ↓
detect_network_identity() → identity
compute_network_id(identity) → "a3f9c2b1e047"
    ↓
get_sentinel_db_path("a3f9c2b1e047")
→ ~/.netlab/sentinel/a3f9c2b1e047.db
    ↓
baseline_exists("a3f9c2b1e047", identity) ?
    OUI → charger baseline existante
    NON → learn_baseline → stocker dans ~/.netlab/sentinel/a3f9c2b1e047.db
    ↓
Boucle de surveillance (inchangée)
    ↓
netlab sentinel stop
→ state=inactive dans ~/.netlab/sentinel/a3f9c2b1e047.db
→ baseline conservée (même fichier)

Prochain démarrage sur même réseau :
compute_network_id(identity) → "a3f9c2b1e047" (identique)
→ ouvre ~/.netlab/sentinel/a3f9c2b1e047.db
→ baseline trouvée ✅
```

---

## 5. Ce qui ne change pas

- `core/finding.py` — inchangé
- `core/risk_scorer.py` — inchangé
- Schéma des tables — inchangé (mêmes CREATE TABLE)
- NetworkIdentity et règles MAC="" — inchangés
- `sentinel/monitor.py` — inchangé
- `sentinel/alerting.py` — inchangé
- `sentinel/whitelist.py` — inchangé
- Sessions d'audit standard (`~/.netlab/sessions/`) — inchangées

---

## 6. Impact sur les tests existants

Les tests sentinel existants patchent `db.get_db_path` sur `tmp_path`.
Il faudra aussi patcher `db.get_sentinel_db_path` de la même façon.
Les tests de logique (baseline, monitor, alerting, manager) restent valides —
seul le chemin de la DB change.
