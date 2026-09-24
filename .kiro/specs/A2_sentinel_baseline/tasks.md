# A2 — Tasks

## Périmètre exact

Fichiers modifiés :
- `core/database.py` — nouvelles fonctions sentinel_ (DB path + CRUD)
- `sentinel/baseline.py` — compute_network_id + utilisation network_id
- `sentinel/sentinel_manager.py` — calcul network_id, séparation run/baseline
- `tests/test_sentinel_baseline.py` — patch get_sentinel_db_path
- `tests/test_sentinel_manager.py` — patch get_sentinel_db_path

Aucun autre fichier.

---

## Task 1 — core/database.py : fonctions sentinel_

### 1a. Nouveau chemin DB

```python
def get_sentinel_db_path(network_id: str) -> Path:
    """~/.netlab/sentinel/<network_id>.db"""
```

Validation du `network_id` via `_validate_session_id()` existante
(les 12 chars hex la satisfont).

### 1b. Nouvelle connexion

```python
def get_sentinel_connection(network_id: str) -> sqlite3.Connection
def init_sentinel_db(network_id: str) -> None
```

`init_sentinel_db` crée les mêmes tables que `init_db`
(assets, sessions, findings, baseline, events) — réutilise le même SQL.

### 1c. CRUD sentinel_ dédié

Dupliquer les fonctions CRUD baseline et events avec préfixe `sentinel_` :

```python
def sentinel_save_baseline_entry(network_id, ...)
def sentinel_get_baseline_entries(network_id, ...)
def sentinel_baseline_exists(network_id, ...)
def sentinel_delete_baseline_for_identity(network_id, ...)
def sentinel_save_event(network_id, ...)
def sentinel_get_events(network_id, ...)
def sentinel_count_unresolved_events(network_id)
def sentinel_update_state(network_id, ...)
def sentinel_get_state(network_id)
```

Les fonctions existantes sans préfixe `sentinel_` restent inchangées.

---

## Task 2 — sentinel/baseline.py : compute_network_id

### 2a. Ajouter compute_network_id

```python
def compute_network_id(identity: NetworkIdentity) -> str:
    import hashlib
    raw = f"{identity.target_network}|{identity.gateway_ip}|{identity.gateway_mac}".lower()
    return hashlib.sha256(raw.encode()).hexdigest()[:12]
```

### 2b. Modifier baseline_exists, get_baseline, learn_baseline

Remplacer les appels aux fonctions DB `baseline_exists`, `get_baseline_entries`,
etc. par leurs équivalents `sentinel_` qui prennent `network_id`.

Signatures publiques mises à jour :
```python
def baseline_exists(network_id: str, identity: NetworkIdentity) -> bool
def get_baseline(network_id: str, identity: NetworkIdentity) -> Dict[str, BaselineEntry]
def learn_baseline(target_network, network_id, identity, force_relearn) -> bool
```

---

## Task 3 — sentinel/sentinel_manager.py : séparation run / baseline

### 3a. Modifier start()

```python
# 1. Détecter l'identité réseau
identity = detect_network_identity(target_network)
network_id = compute_network_id(identity)

# 2. Initialiser la DB sentinel (baseline persistante)
init_sentinel_db(network_id)

# 3. Créer un run_session_id pour ce démarrage spécifique
run_session_id = session_id or f"sentinel-run-{uuid.uuid4().hex[:8]}"
```

### 3b. Modifier status() et stop()

Utiliser `sentinel_get_state(network_id)` et
`sentinel_update_state(network_id, ...)` au lieu des fonctions session.

### 3c. Propagation du network_id

Passer `network_id` à `baseline_exists`, `get_baseline`, `learn_baseline`,
`check_network`, `process_changes` partout où `session_id` était utilisé
pour accéder à la baseline.

---

## Task 4 — Mettre à jour les tests

### test_sentinel_baseline.py

Ajouter le patch de `get_sentinel_db_path` dans le fixture `patch_db_path`.

Mettre à jour les appels qui passaient `session_id` → `network_id`.

### test_sentinel_manager.py

Même mise à jour du fixture.

### Vérifier les 5 tests critiques

```
[ ] Redémarrage sur même réseau → baseline retrouvée (pas de réapprentissage)
[ ] Redémarrage sur réseau différent → nouvelle baseline
[ ] --relearn → remplace uniquement le réseau courant
[ ] stop → baseline conservée dans ~/.netlab/sentinel/
[ ] compute_network_id(identityA) != compute_network_id(identityB) si MACs différentes
```

---

## Critère de DONE

```
[ ] get_sentinel_db_path() retourne ~/.netlab/sentinel/<network_id>.db
[ ] compute_network_id() est déterministe (même entrée → même sortie)
[ ] baseline_exists() utilise la DB sentinel, pas la session DB
[ ] learn_baseline() stocke dans la DB sentinel
[ ] sentinel_manager.start() calcule network_id avant tout
[ ] Redémarrage retrouve la baseline (test ou vérification manuelle)
[ ] Tests sentinel existants passent toujours (0 régression)
[ ] Commit propre
```
