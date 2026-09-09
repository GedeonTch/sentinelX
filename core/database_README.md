# core/database.py — La couche de persistance SQLite

## Ce que fait ce fichier

`database.py` est le **seul fichier autorisé à importer `sqlite3`** dans tout le projet. Il lit et écrit les données — c'est tout. Il ne contient aucune logique métier, aucun calcul de score, aucun affichage.

Chaque session d'audit produit un fichier SQLite indépendant : `~/.netlab/sessions/<session_id>.db`. Les données de deux sessions ne se mélangent jamais — c'est une garantie structurelle, pas une convention.

---

## Pourquoi SQLite et pas un fichier JSON ?

Un fichier JSON fonctionne bien pour stocker quelques données. Mais NetLab doit pouvoir :
- Retrouver tous les Findings d'une session après un redémarrage
- Filtrer par sévérité, par module, par statut
- Mettre à jour le statut d'un Finding sans réécrire tout le fichier
- Garantir qu'une écriture partielle (crash en cours de scan) ne corrompt pas les données

SQLite répond à tous ces besoins. C'est une base de données complète, stockée dans un seul fichier, sans serveur, incluse dans la bibliothèque standard Python. C'est le bon outil pour un CLI local.

---

## Les 5 tables et leurs rôles

### `sessions` — une ligne par audit

Chaque fois que tu lances `netlab scan`, une session est créée. Elle enregistre la cible, le profil utilisé (normal/stealth/aggressive), l'heure de début, l'heure de fin, et le statut (running / completed / failed).

```
sessions
├── id          → identifiant unique (ex: "session-abc123")
├── target      → ce qui a été scanné ("192.168.1.0/24")
├── profile     → profil de scan utilisé
├── start_time  → début ISO 8601
├── end_time    → fin ISO 8601 (NULL si en cours)
├── status      → running / completed / failed
└── notes       → texte libre optionnel
```

### `assets` — les machines découvertes

Un asset = une machine identifiée sur le réseau. Il est créé lors de la phase DISCOVER et mis à jour au fur et à mesure que d'autres modules collectent des informations (hostname, OS, MAC).

```
assets
├── id          → UUID
├── ip          → adresse IP
├── mac         → adresse MAC (optionnelle)
├── hostname    → nom résolu (optionnel)
├── os          → OS détecté (optionnel)
├── first_seen  → première détection ISO 8601
└── active      → 1 si joignable, 0 sinon
```

### `findings` — le cœur du système

Un Finding = une faiblesse détectée, avec sa preuve. C'est la table la plus importante. Chaque ligne correspond à un objet `Finding` de `core/finding.py`.

Les champs `evidence` et `explanation` sont stockés comme du JSON sérialisé (TEXT), puisque SQLite ne connaît pas les dataclasses Python. La désérialisation est entièrement gérée par `_row_to_finding()`.

```
findings
├── id              → UUID du Finding
├── session_id      → session qui l'a produit
├── asset_id        → machine concernée (optionnel)
├── module          → scanner d'origine ("tcp_scan", "smb_enum"...)
├── category        → config / service / network / credential / trace
├── severity        → critical / high / medium / low / info
├── cvss            → score CVSS si connu (REAL, peut être NULL)
├── confidence      → 1.00 / 0.85 / 0.60 (REAL)
├── exposure        → internal / external
├── score           → risk_score calculé par risk_scorer (NULL jusqu'au calcul)
├── status          → open / verified / remediated / accepted
├── evidence        → JSON {"raw": "...", "command": "..."}
├── explanation     → JSON {"what": "...", "attack": "...", "defense": "..."} ou NULL
├── remediation_cmd → commande de correction V2 (vide en V1)
├── cve_refs        → JSON ["CVE-2017-0144", ...]
├── target_ip       → IP cible
├── target_port     → port cible (NULL si non applicable)
├── target_service  → service détecté
├── service_version → version détectée
└── created_at      → ISO 8601
```

### `baseline` — l'état normal selon Sentinel

Le Sentinel (ticket #016) apprend l'état normal du réseau : quels ports sont ouverts sur quelle machine, quelle est la gateway, quels DNS sont utilisés. C'est la référence. Si quelque chose change, c'est une alerte.

```
baseline
├── id          → UUID
├── asset_id    → machine concernée
├── ports       → JSON [22, 80, 443] — ports ouverts normaux
├── services    → JSON {"22": "ssh", "80": "nginx"} — services normaux
├── mac         → MAC normale (pour détecter les changements ARP)
├── gateway     → gateway normale
├── dns         → serveurs DNS normaux
└── last_scan   → dernière mise à jour de la baseline
```

### `events` — ce que Sentinel a détecté

Quand Sentinel détecte un écart par rapport à la baseline (nouveau port, changement de MAC, nouvel host), il crée un événement dans cette table.

```
events
├── id          → UUID
├── timestamp   → ISO 8601
├── type        → type d'événement ("new_port", "mac_change", "new_host"...)
├── asset_id    → machine concernée (optionnel)
├── details     → JSON avec le détail de l'écart détecté
└── resolved    → 0 = actif, 1 = résolu
```

---

## Pourquoi un fichier par session et pas une base centrale ?

Deux raisons principales :

**Isolation** : une session corrompue (crash, test raté) n'affecte pas les autres. Tu peux supprimer une session en effaçant un seul fichier.

**Portabilité** : un fichier `.db` peut être copié, archivé, ou envoyé à quelqu'un d'autre. La session entière voyage avec lui — assets, findings, baseline, events.

---

## La sérialisation Evidence et Explanation

SQLite stocke des types simples (TEXT, INTEGER, REAL). Les dataclasses Python doivent être converties.

Pour un Finding sauvegardé :
```python
# Evidence devient →
'{"raw": "PORT 445/tcp open", "command": "nmap 192.168.1.1"}'

# Explanation devient →
'{"what": "SMBv1 is enabled.", "attack": "EternalBlue...", "defense": "Disable SMBv1."}'

# explanation=None devient →
NULL  (pas de chaîne vide, pas de "{}", mais NULL)
```

Pour la lecture, `_row_to_finding()` fait l'inverse : il parse le JSON et reconstruit les dataclasses. C'est la seule fonction qui fait ce travail — pas de logique de désérialisation éparpillée dans le projet.

---

## Pourquoi `risk_score` est `NULL` à la sauvegarde ?

Un Finding est créé par un scanner. Le scanner produit une preuve et estime la sévérité. Mais il n'a pas à décider du score de risque — c'est `core/risk_scorer.py` qui fait ce calcul, après que le Finding est sauvegardé.

Le flux est donc :
```
Scanner → save_finding(f)          # score = NULL dans la DB
    ↓
risk_scorer.py calcule le score
    ↓
update_finding_risk_score(session_id, finding_id, score)  # seul chemin légitime
```

Si tu vois un `score` non NULL dans la DB qui n'est pas passé par `update_finding_risk_score`, c'est un bug à corriger.

---

## Ce que ce fichier ne fait PAS

- **Pas de `print()`** — l'affichage passe par `core/logger.py` + Rich
- **Pas de logique métier** — pas de calcul, pas de règle de détection
- **Pas de calcul de `risk_score`** — uniquement `core/risk_scorer.py`
- **Pas d'import dans d'autres modules** — `sqlite3` reste ici, point final

---

## Fichiers liés

| Fichier | Rôle |
|---|---|
| `core/finding.py` | Définit les objets Finding que database.py persiste |
| `core/risk_scorer.py` | Calcule `risk_score` et appelle `update_finding_risk_score()` |
| `04_sentinel/` | Utilise les tables `baseline` et `events` |
| `reports/generator.py` | Lit les Findings via `get_findings()` pour générer les rapports |
| `06_cleanup/restore.py` | Peut supprimer un fichier `.db` de session après vérification de propriété |
