# A2 — Persistance de la baseline Sentinel : requirements

## Problème

`sentinel_manager.start()` génère un nouveau `session_id` aléatoire à chaque
démarrage quand aucun n'est fourni :

```python
session_id = session_id or f"sentinel-{uuid.uuid4().hex[:8]}"
```

La baseline est stockée dans la DB liée à ce `session_id` temporaire.
Au prochain démarrage, un nouvel identifiant est généré, une nouvelle DB est
créée, et la baseline est introuvable — NetLab réapprend tout depuis zéro.

## Cause racine

Trois identités de durées de vie différentes sont confondues :

| Identité | Signification | Durée de vie |
|---|---|---|
| **Identité réseau** | CIDR + gateway IP + gateway MAC | Permanente |
| **Session d'exécution** | Un démarrage spécifique de Sentinel | Temporaire (un run) |
| **Baseline** | État normal du réseau appris | Permanente |

La baseline appartient à l'identité réseau, pas à une session d'exécution.
La confondre avec une session temporaire la rend éphémère par accident.

## Règle fondamentale

> La baseline d'un réseau doit persister entre les redémarrages de Sentinel,
> aussi longtemps que l'identité réseau est la même.

Elle ne doit jamais être perdue par un simple redémarrage de `netlab sentinel`.

## Solution

Introduire un **network_id stable** dérivé de manière déterministe depuis
l'identité réseau (CIDR + gateway_ip + gateway_mac).

Ce `network_id` identifie toujours le même réseau, quel que soit le run.

La baseline est stockée dans une DB dont le nom est dérivé du `network_id` —
pas du `session_id` de l'exécution courante.

```
~/.netlab/sentinel/<network_id>.db   ← baseline + events Sentinel (persistant)
~/.netlab/sessions/<session_id>.db   ← session d'audit standard (temporaire)
```

## Ce qui ne change pas

- Modèle `Finding` — inchangé
- Schéma des tables — inchangé
- Règles NetworkIdentity (triplet CIDR + gateway_ip + gateway_mac) — inchangées
- Logique de surveillance (monitor, alerting, whitelist) — inchangée
- Règle MAC="" jamais wildcard — inchangée

## Critères de succès

1. `netlab sentinel start --target 192.168.1.0/24` → baseline apprise, stockée
2. `netlab sentinel stop` → baseline conservée
3. `netlab sentinel start --target 192.168.1.0/24` (redémarrage) → baseline retrouvée automatiquement
4. Réseau différent (autre CIDR ou autre gateway MAC) → baseline différente, pas de cross-contamination
5. `--relearn` → remplace uniquement la baseline du réseau courant
