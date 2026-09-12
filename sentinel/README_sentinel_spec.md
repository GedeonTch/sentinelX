# Ticket #016 — Sentinel : spec complète

## C'est quoi le Sentinel ?

Le Sentinel est la fonctionnalité de surveillance continue de NetLab. Là où les modules DISCOVER et DETECT font un audit ponctuel (tu lances un scan, tu obtiens un résultat), le Sentinel tourne en arrière-plan et surveille les changements sur le réseau.

**Principe** : il apprend d'abord l'état "normal" du réseau (la baseline), puis il compare régulièrement l'état actuel à cette baseline. Si quelque chose change, il crée un événement.

Ce n'est **pas** un EDR, pas un SIEM, pas CrowdStrike. C'est simple, déterministe, et local.

---

## Ce que le Sentinel détecte (V1)

Trois types de changements uniquement :

| Changement | Exemple | Pourquoi c'est important |
|---|---|---|
| **Nouveau host** | Une machine inconnue apparaît sur le réseau | Intrusion, appareil non autorisé |
| **Nouveau port ouvert** | Le port 4444 s'ouvre sur une machine connue | Backdoor, malware, service non autorisé |
| **Changement de MAC** | L'IP 192.168.1.1 répond avec un MAC différent | ARP spoofing, remplacement d'équipement |

Rien d'autre en V1. Pas d'analyse comportementale, pas de détection d'anomalies, pas de machine learning.

---

## Décisions architecturales validées

### 1. Intervalle de surveillance
60 secondes par défaut, configurable dans `config.yaml` :
```yaml
sentinel:
  interval_seconds: 60
```

### 2. Restart — réutiliser la baseline existante par défaut

Si une baseline existe déjà **pour le même réseau cible**, elle est réutilisée. Le Sentinel ne réapprend pas à chaque démarrage — ce serait inutile et coûteux en trafic réseau.

La baseline n'est réapprise que dans deux cas :
- Aucune baseline n'existe encore pour ce réseau
- L'utilisateur lance explicitement `netlab sentinel start --relearn`

### 3. Ctrl+C — la baseline est persistée

L'arrêt du Sentinel (Ctrl+C ou `netlab sentinel stop`) ne supprime **pas** la baseline. Elle reste en DB pour la prochaine session. Seule une action explicite `--relearn` ou une suppression manuelle efface la baseline.

### 4. La baseline est liée au réseau cible — pas à une session générique

**Règle critique** : une baseline appartient à un `(target_network, session_id)` précis.

Sans cette contrainte, le scénario suivant serait possible :
```
Sentinel hier → réseau 192.168.1.0/24  → baseline apprise
Aujourd'hui  → réseau 10.0.0.0/24     → même baseline réutilisée  💀
```

La baseline doit donc être cherchée par `target_network`. Si le réseau cible est différent, aucune baseline existante ne correspond → on apprend une nouvelle baseline.

En pratique dans la DB (table `baseline`) : chaque entrée est liée à un `asset_id`, et chaque asset a une IP. La baseline est récupérée en filtrant les assets dont l'IP commence par le préfixe du `target_network` passé à `sentinel start`.

---

## Les 5 fichiers

```
sentinel/
├── __init__.py
├── baseline.py          — apprend et stocke l'état normal
├── monitor.py           — compare état actuel vs baseline
├── alerting.py          — crée les événements (events table + Findings)
├── whitelist.py         — charge ~/.netlab/baseline_whitelist.yaml
└── sentinel_manager.py  — orchestre start/status/stop
```

---

## sentinel/baseline.py

**Responsabilité** : capturer l'état normal du réseau et le stocker dans la table `baseline`.

```python
def learn_baseline(target_network: str, session_id: str) -> None
def get_baseline(target_network: str, session_id: str) -> Dict[str, BaselineEntry]
def baseline_exists(target_network: str, session_id: str) -> bool
```

`BaselineEntry` est un dataclass interne :
```python
@dataclass
class BaselineEntry:
    asset_id: str
    ip: str
    mac: str
    ports: List[int]        # liste des ports TCP ouverts normaux
    last_scan: str          # ISO 8601
```

**Garantie DB — Option A approuvée :**

La table `baseline` contient un champ `target_network TEXT NOT NULL` qui stocke
la valeur exacte passée à `learn_baseline` (ex. `"192.168.1.0/24"`).

`baseline_exists` et `get_baseline` filtrent **uniquement** sur ce champ —
jamais par inférence de préfixe IP. La relation est explicite, stockée,
et testable par une requête SQL simple :

```sql
SELECT * FROM baseline WHERE target_network = '192.168.1.0/24'
```

Cela garantit qu'une baseline apprise sur `192.168.1.0/24` ne sera
jamais retournée pour `10.0.0.0/24`, même si des assets des deux réseaux
coexistent dans la même DB de session.

**Ce que `learn_baseline` fait :**
1. Lance `device_fingerprint(target_network, session_id)` → liste des hosts actifs
2. Pour chaque host → `tcp_scan(ip, session_id)` → liste des ports ouverts
3. Lit le cache ARP → MACs
4. Sauvegarde dans la table `baseline` avec `target_network` renseigné

**Ce que `get_baseline` fait :**
```sql
SELECT b.* FROM baseline b
JOIN assets a ON b.asset_id = a.id
WHERE b.target_network = :target_network
```
Retourne uniquement les entrées du bon réseau. Jamais de cross-contamination.

**Ce que `baseline_exists` fait :**
```sql
SELECT COUNT(*) FROM baseline WHERE target_network = :target_network
```
Retourne `True` si au moins une entrée existe pour ce réseau exact.

---

## sentinel/monitor.py

**Responsabilité** : comparer l'état actuel du réseau à la baseline stockée.

```python
def check_network(
    target_network: str,
    session_id: str,
    baseline: Dict[str, BaselineEntry],
) -> List[NetworkChange]
```

`NetworkChange` est un dataclass interne :
```python
@dataclass
class NetworkChange:
    change_type: str    # "new_host" | "new_port" | "mac_change"
    asset_ip: str
    detail: str         # description lisible du changement
    evidence: str       # preuve brute (sortie nmap ou ARP)
```

**Logique de comparaison :**

```
État actuel :
  - hosts actifs (via ping scan)
  - ports ouverts par host (via tcp_scan léger)
  - MACs (via ARP cache)

Pour chaque host actif :
  → Si IP inconnue de la baseline → NetworkChange("new_host", ...)
  → Pour chaque port ouvert :
      Si port non dans baseline.ports → NetworkChange("new_port", ...)
  → Si MAC différent de baseline.mac → NetworkChange("mac_change", ...)
```

`monitor.py` ne crée pas de Finding. Il retourne des changements bruts.

---

## sentinel/alerting.py

**Responsabilité** : transformer les `NetworkChange` en événements DB et en Findings.

```python
def process_changes(
    changes: List[NetworkChange],
    session_id: str,
    whitelist: Whitelist,
    max_alerts_per_hour: int,
) -> List[Finding]
```

**Règles :**
- Chaque changement → INSERT dans la table `events` (qu'il soit whitelisté ou non)
- Changement whitelisté → `events.resolved = 1`, pas de Finding
- Changement non whitelisté → Finding de catégorie `NETWORK`
- Si le nombre d'alertes dans la dernière heure dépasse `max_alerts_per_hour` → mode silencieux (enregistrement DB uniquement, pas de Finding retourné, pas d'affichage)

**Sévérité des Findings Sentinel :**

| Changement | Sévérité | Raison |
|---|---|---|
| `new_host` | `MEDIUM` | Appareil non autorisé — risque réel mais non confirmé dangereux |
| `new_port` | `HIGH` | Port inattendu — vecteur de compromission probable |
| `mac_change` | `HIGH` | ARP spoofing possible — attaque active probable |

---

## sentinel/whitelist.py

**Responsabilité** : charger `~/.netlab/baseline_whitelist.yaml` et tester si un changement est autorisé.

```python
def load_whitelist() -> Whitelist
def is_whitelisted(change: NetworkChange, whitelist: Whitelist) -> bool
```

`Whitelist` est un dataclass :
```python
@dataclass
class Whitelist:
    allowed_new_macs: List[str]
    allowed_port_changes: List[Dict]   # [{host: ip, ports: [n, n]}]
    allowed_new_hosts: List[str]
    sentinel_max_alerts_per_hour: int
```

Format du fichier :
```yaml
allowed_new_macs: []
allowed_port_changes:
  - host: 192.168.1.10
    ports: [8080]
allowed_new_hosts: []
sentinel_max_alerts_per_hour: 3
```

Si le fichier n'existe pas → whitelist vide avec `max_alerts_per_hour: 3`.

---

## sentinel/sentinel_manager.py

**Responsabilité** : orchestrer start / status / stop. Appelé par `cli.py`.

```python
def start(
    target_network: str,
    session_id: str,
    force_relearn: bool = False,
) -> None

def status(session_id: str) -> dict

def stop(session_id: str) -> None
```

**Flux de `start()` :**

```python
# 1. Charger la whitelist
whitelist = load_whitelist()

# 2. Vérifier si une baseline existe pour CE réseau
if not baseline_exists(target_network, session_id) or force_relearn:
    display("Aucune baseline pour ce réseau — apprentissage en cours...")
    learn_baseline(target_network, session_id)
else:
    display("Baseline existante trouvée — surveillance démarrée.")

# 3. Boucle de surveillance
while True:
    sleep(interval_seconds)
    current_baseline = get_baseline(target_network, session_id)
    changes = check_network(target_network, session_id, current_baseline)
    if changes:
        findings = process_changes(changes, session_id, whitelist, max_alerts)
        for f in findings:
            display(f)    # affiche l'alerte
    # Mise à jour du statut en DB
    update_session_status(session_id, "sentinel_running")
```

**`--relearn` :** flag optionnel qui force la réapprentissage même si une baseline existe, quel que soit le réseau.

**`status()` :** lit la table `sessions` et retourne le statut actuel (running / stopped / last_check timestamp).

**`stop()` :** met à jour le statut en DB. La baseline n'est PAS effacée.

---

## Le flux complet

```
netlab sentinel start --target 192.168.1.0/24
        ↓
[Confirmation y/n] — trafic réseau actif
        ↓
sentinel_manager.start(target_network="192.168.1.0/24", ...)
        ↓
baseline_exists("192.168.1.0/24") ?
    NON → learn_baseline() → scan + stockage DB
    OUI → réutiliser baseline existante
        ↓
Boucle toutes les 60s :
    check_network() → List[NetworkChange]
        ↓
    [si changements]
        ↓
    is_whitelisted() → filtrage
        ↓
    process_changes() → events DB + Findings
        ↓
    display() alertes
        ↓
[Ctrl+C]
        ↓
sentinel_manager.stop() → statut DB mis à jour, baseline CONSERVÉE
```

---

## Ce qui NE fait PAS partie du Sentinel V1

- Pas de capture de paquets (pas de Scapy, pas de tcpdump)
- Pas d'analyse comportementale
- Pas de corrélation d'événements
- Pas d'alertes email/webhook
- Pas de démon système (systemd)
- Pas d'interface graphique

---

## Règles absolues

- **Jamais modifier la configuration système** — observe uniquement
- **Confirmation y/n avant le scan initial** — trafic réseau actif
- **Pas de Finding sans preuve** — `evidence.raw` documente le changement observé
- **ZERO print()** — `display()` de `core/logger.py`
- **ZERO import sqlite3** hors `core/database.py`
- **ZERO risk_score** calculé ici
- **La baseline ne disparaît jamais à l'arrêt**

---

## Dépendances

Le Sentinel réutilise ce qui existe :

| Module | Usage |
|---|---|
| `recon/device_fingerprint.py` | Découverte des hosts pour la baseline et la surveillance |
| `detect/tcp_scan.py` | Scan des ports pour la baseline et la surveillance |
| `core/database.py` | Lecture/écriture tables `baseline` et `events` |
| `core/finding.py` | Création des Findings d'alerte |
| `core/logger.py` | Affichage Rich |
| `knowledge/knowledge_base.py` | Enrichissement des Findings avec `explanation` |

---

*Spec validée — prête à coder.*
