# Sentinel V1 — Document de conception (révision 3)

> Révision 2 → Révision 3 : intégration de la revue finale produit/architecture.
> **Aucun code, aucune migration DB, aucune modification de structure avant validation finale.**
> Points d'approbation A, B, C mis à jour ci-dessous.

---

## 1. Ce qui reste inchangé (validé en révision 2)

- 5 fichiers : baseline.py, whitelist.py, monitor.py, alerting.py, sentinel_manager.py
- 3 types de changements : new_host, new_port, mac_change
- Intervalle : 60s par défaut, configurable dans config.yaml
- Baseline persistée à l'arrêt (Ctrl+C et stop propre)
- ZERO print(), ZERO import sqlite3, ZERO risk_score dans sentinel/
- Pas de capture de paquets, pas de ML, pas de daemon système
- removed_host hors scope V1
- Séparation Event / Alerte / Finding (matrice inchangée)
- Whitelist visible en INFO (whitelisté ≠ invisible)
- Mode silencieux non permanent
- Status compact deux lignes
- Format `37/42 machines`
- États ACTIF / DÉGRADÉ / INACTIF
- Host disparu : pas d'alerte V1, baseline conservée
- Arrêt propre : baseline et événements conservés
- Scheduler V3 hors scope

---

## 2. Identité réseau — triplet NetworkIdentity

### Définition

Un réseau Sentinel est identifié par un triplet exact :

```python
@dataclass
class NetworkIdentity:
    target_network: str   # CIDR — "192.168.76.0/24"
    gateway_ip:     str   # IP de la gateway du réseau cible
    gateway_mac:    str   # MAC de la gateway (minuscules, format aa:bb:cc:dd:ee:ff)
                          # "" si la gateway ne répond pas à l'ARP
```

### Règle MAC vide — définitive et verrouillée

> `gateway_mac = ""` n'est jamais un wildcard.

Comportement exact selon les cas :

| MAC stockée en baseline | MAC détectée actuellement | Résultat |
|---|---|---|
| `aa:aa:aa:aa:aa:aa` | `aa:aa:aa:aa:aa:aa` | Match exact → baseline chargée |
| `aa:aa:aa:aa:aa:aa` | `bb:bb:bb:bb:bb:bb` | Identité non correspondante → confirmation requise |
| `aa:aa:aa:aa:aa:aa` | `""` (ARP sans réponse) | Identité incomplète → **jamais chargée automatiquement** |
| `""` | `""` | Match exact (deux identités partielles) → baseline chargée |
| `""` | `bb:bb:bb:bb:bb:bb` | Identité non correspondante → confirmation requise |

**Règle absolue :** une identité avec `gateway_mac=""` ne peut jamais réutiliser automatiquement une baseline dont `gateway_mac` est renseignée. L'identité partielle est non confirmée et suit le flux de confirmation/apprentissage.

### Détection de l'identité courante au démarrage

```
1. Lire la table de routage OS → gateway_ip du réseau cible
2. Lire le cache ARP → gateway_mac correspondant à gateway_ip
   Si pas de réponse ARP → gateway_mac = ""
3. Construire NetworkIdentity(target_network, gateway_ip, gateway_mac)
```

### Lookup baseline

```sql
SELECT * FROM baseline
WHERE target_network = :cidr
  AND gateway_ip     = :gw_ip
  AND gateway_mac    = :gw_mac
```

La comparaison est toujours exacte sur les 3 colonnes, incluant `""`.

### Identité non correspondante (CIDR connu, MAC différente ou incomplète)

Sentinel affiche :

```
[!] Identité réseau non reconnue pour 192.168.76.0/24.
    Gateway connue  : aa:aa:aa:aa:aa:aa
    Gateway actuelle: bb:bb:bb:bb:bb:bb  (ou: inconnue)
    Une baseline existe pour ce CIDR mais avec une identité différente.
    Aucune baseline ne sera chargée automatiquement.
    Voulez-vous apprendre une nouvelle baseline pour ce réseau ? [y/N]
```

- Le système ne dit pas "nouveau réseau" ni "ARP spoofing"
- Il signale une **identité non correspondante**
- L'historique de l'ancienne identité est conservé intact
- Si l'utilisateur répond N → Sentinel ne démarre pas

---

## 3. Session Sentinel — identité complète

### Règle

Une session Sentinel active est associée à l'identité réseau **complète**, pas seulement au CIDR.

La table `sessions` stockera :

| Colonne | Type | Description |
|---|---|---|
| `sentinel_state` | TEXT | `"active"` / `"degraded"` / `"inactive"` |
| `last_check_time` | TEXT | ISO 8601 du **dernier check réussi uniquement** |
| `sentinel_target_network` | TEXT | CIDR surveillé |
| `sentinel_gateway_ip` | TEXT | IP de la gateway au moment du démarrage |
| `sentinel_gateway_mac` | TEXT | MAC de la gateway au moment du démarrage |

### Règle last_check_time — précision

`last_check_time` est mis à jour **uniquement** si le check se termine avec succès.
Un timeout ou une erreur ne modifie jamais `last_check_time`.

```
10:00 → check réussi   → last_check_time = "10:00:00"
10:01 → check réussi   → last_check_time = "10:01:00"
10:02 → timeout        → last_check_time reste "10:01:00"
10:03 → timeout        → last_check_time reste "10:01:00"
  → 2 × 60s dépassés depuis 10:01 → sentinel_state = "degraded"
10:04 → check réussi   → last_check_time = "10:04:00", sentinel_state = "active"
```

### États et transitions

```
INACTIF
  ↓  sentinel start
ACTIF
  ↓  2 × interval_seconds sans check réussi
DÉGRADÉ
  ↓  check réussi
ACTIF
  ↓  sentinel stop / Ctrl+C / fermeture NetLab
INACTIF
```

Retour DÉGRADÉ → ACTIF : immédiat dès qu'un check réussit, sans délai.

### [APPROBATION REQUISE — Point A]

Table `baseline` : ajouter `gateway_ip TEXT NOT NULL DEFAULT ''` et `gateway_mac TEXT NOT NULL DEFAULT ''`.

### [APPROBATION REQUISE — Point C — mis à jour]

Table `sessions` : ajouter les 5 colonnes :
- `sentinel_state TEXT DEFAULT 'inactive'`
- `last_check_time TEXT`
- `sentinel_target_network TEXT`
- `sentinel_gateway_ip TEXT`
- `sentinel_gateway_mac TEXT`

Option retenue : **C1** — colonnes dans `sessions`. La session représente l'identité réseau complète, cohérent avec le reste du schéma.

**Ni A ni C ne sont implémentés avant le GO final.**

---

## 4. Cycle de vie du compteur d'alertes et du mode silencieux

### Règle fondamentale

> Le compteur d'alertes et le mode silencieux sont liés à l'exécution courante de Sentinel.

Un arrêt de Sentinel réinitialise le compteur. Le prochain démarrage constitue une nouvelle période de surveillance. Les événements/Findings/historiques précédents restent en DB.

**Exemple :**
```
14:05 → Sentinel passe en mode silencieux (3 alertes en 1h)
14:30 → Sentinel est arrêté
15:00 → Sentinel redémarre → compteur = 0, pas de silence hérité
        Les 35 minutes restantes de l'ancien silence ne sont PAS reprises
```

### Déclenchement du mode silencieux

```python
if alert_count >= sentinel_max_alerts_per_hour:
    enter_silent_mode()
```

- Seuil : `sentinel_max_alerts_per_hour` (config.yaml, défaut : `3`)
- Condition : `>=` (atteint ou dépasse)
- Fenêtre : 1 heure glissante depuis le démarrage de la session courante
- Durée du silence : 1 heure à partir du déclenchement
- **Ce qui compte** : alertes de sécurité non whitelistées uniquement
- **Ce qui ne compte pas** : changements whitelistés (INFO)

### Pendant le mode silencieux

| Action | Comportement |
|---|---|
| Surveillance | Continue normalement |
| Événements en DB | Écrits |
| Findings en DB | Créés et écrits |
| Compteur | Continue d'incrémenter |
| Affichage terminal alertes | Suspendu |
| Changements INFO (whitelistés) | Toujours affichés discrètement |

Message au déclenchement :
```
[!] Sentinel passe en mode silencieux (3 alertes atteintes en 1h).
    La surveillance continue. Les événements sont enregistrés.
    Les nouvelles alertes ne seront plus affichées pendant 1h.
    › netlab sentinel history  pour consulter l'historique
```

### Sortie du mode silencieux (après 1h)

```
[●] Sentinel reprend les alertes normales.
    Période silencieuse : 14:05 → 15:05
    Événements enregistrés pendant le silence : 7
    › netlab sentinel history  pour consulter
```

### Si le seuil est à nouveau atteint après la reprise

Nouveau cycle de silence. Le mode silencieux n'est jamais permanent :
chaque heure, la fenêtre glisse et le compteur repart.

---

## 5. `--relearn` — remplacement atomique

### Règle

`--relearn` remplace la baseline de l'identité réseau **courante** uniquement.
Toutes les autres identités réseau, même avec le même CIDR, sont intouchables.

### Comportement — remplacement, pas DELETE simple

Pour éviter de laisser la baseline absente si l'apprentissage échoue en cours :

```
1. Apprendre la nouvelle baseline en mémoire
2. Vérifier qu'elle est complète (au moins 1 host détecté)
3. Seulement alors → DELETE de l'ancienne baseline pour cette identité exacte
4. INSERT de la nouvelle baseline
```

Si l'apprentissage échoue à l'étape 1 ou 2 :
→ pas de DELETE, ancienne baseline conservée, message d'erreur affiché.

Si l'apprentissage réussit et que la baseline est vide (0 host) :
→ avertissement affiché, pas de remplacement automatique, confirmation requise.

---

## 6. Whitelist — interface CLI

### [APPROBATION REQUISE — Point B]

Nouvelles commandes dans `cli.py` :

```bash
netlab sentinel allow port <ip> <port>        # autoriser un port sur un host
netlab sentinel allow host <ip>               # autoriser un nouveau host
netlab sentinel allow mac <ip> <mac>          # autoriser un changement de MAC

netlab sentinel unallow port <ip> <port>      # retirer l'autorisation
netlab sentinel unallow host <ip>
netlab sentinel unallow mac <ip>

netlab sentinel whitelist                     # afficher la whitelist courante
netlab sentinel history                       # afficher l'historique des événements
netlab sentinel help                          # aide complète
```

- `allow` et `unallow` écrivent dans `~/.netlab/baseline_whitelist.yaml`
- Le YAML reste la source de vérité — les commandes CLI l'éditent proprement
- L'utilisateur peut toujours éditer le YAML manuellement
- Pas d'impact sur le schéma DB

**Non implémenté avant le GO final.**

---

## 7. Séparation Event / Alerte / Finding

### Définitions formelles

```
Événement  = quelque chose s'est produit
             Toujours en DB (table events), toujours dans l'historique
             Qu'il soit autorisé ou non

Alerte     = événement qui mérite l'attention de l'utilisateur
             Affiché dans le terminal
             Comptabilisé dans le compteur anti-spam
             Uniquement pour les changements non whitelistés

Finding    = objet de sécurité structuré (catégorie, sévérité, evidence, explanation)
             Stocké dans la table findings
             Uniquement pour les changements non whitelistés
             Utilisé par risk_scorer et reports
```

### Matrice de décision

| Changement | Event DB | Historique | Alerte terminal | Finding DB | Compteur |
|---|---|---|---|---|---|
| Non whitelisté | ✅ | ✅ | ✅ | ✅ | +1 |
| Whitelisté | ✅ `resolved=1` | ✅ | ❌ | ❌ | 0 |
| Mode silencieux | ✅ | ✅ | ❌ | ✅ | +1 |

Affichage d'un changement whitelisté :
```
[INFO] 192.168.1.10:8080 ouvert — changement autorisé (whitelisté)
```

---

## 8. Status compact — format définitif

```
[●] SENTINELX: ACTIF | 192.168.76.0/24 | 37/42 machines | 12 changements
    dernière vérif. 12s | prochaine 48s | 3 alertes
```

### Compteurs — définitions précises

**machines** : `actives/connues`
- actives = répondent lors du dernier scan
- connues = enregistrées dans la baseline de cette identité réseau

**changements** : tous les changements (whitelistés ou non) depuis le démarrage de la session Sentinel courante

**alertes** : alertes de sécurité non résolues (`resolved=0`, non whitelistées) de la session courante. Les alertes de sessions précédentes ne sont pas mélangées.

### Ne s'affiche PAS dans le status

IP spécifiques, ports, MACs, détails événements, preuves, explications, timestamps détaillés, descriptions Finding.

### Règle UX

```
STATUS    → résumé (savoir s'il se passe quelque chose)
HISTORIQUE → détails (comprendre ce qui s'est passé)
EXPLAIN   → compréhension (savoir pourquoi c'est un risque)
```

---

## 9. Aide contextuelle discrète

Suggestions affichées sur une ligne, rotation lente, en bas du status :

```
Sentinel actif, pas d'alerte     →  › status  › history  › allow  › stop
Sentinel actif, nouvelle alerte  →  › history  › findings  › allow  › explain
Sentinel inactif                 →  › sentinel start  › sentinel status
Mode silencieux actif            →  › history  (surveillance active, affichage suspendu)
```

Aide complète à la demande :
```bash
netlab sentinel help
```
Affiche une table Rich statique, une ligne par commande. Pas de pagination.

---

## 10. Arrêt propre

### Fermeture NetLab ou Ctrl+C

```
signal SIGINT / fermeture normale
    ↓
sentinel_manager : fin de boucle propre (pas en plein milieu d'un check)
    ↓
sentinel_state = "inactive" en DB
    ↓
[○] Sentinel arrêté proprement. Baseline conservée.
    ↓
baseline → conservée
events   → conservés
findings → conservés
compteur anti-spam → réinitialisé au prochain démarrage
```

---

## 11. Host déconnecté — V1

Si un host de la baseline ne répond plus :
- Pas d'alerte (removed_host hors scope V1)
- Baseline de ce host conservée intacte
- Entrée assets conservée en DB
- Compteur actives descend : `37/42` au lieu de `38/42`
- Si le host revient sans changement de MAC ni nouveau port → reconnu normalement

---

## 12. Impact architecture — résumé

### Modifications schéma DB requises

| Table | Colonnes à ajouter | Point |
|---|---|---|
| `baseline` | `gateway_ip TEXT NOT NULL DEFAULT ''`, `gateway_mac TEXT NOT NULL DEFAULT ''` | **[A]** |
| `sessions` | `sentinel_state TEXT DEFAULT 'inactive'`, `last_check_time TEXT`, `sentinel_target_network TEXT`, `sentinel_gateway_ip TEXT`, `sentinel_gateway_mac TEXT` | **[C]** |

### Modifications CLI requises

| Commandes | Fichier | Point |
|---|---|---|
| `sentinel allow/unallow/whitelist/history/help` | `cli.py` | **[B]** |

### Non impacté

`core/finding.py`, `core/risk_scorer.py`, `knowledge/`, `detect/`, `recon/`, `reports/`, structure générale de `core/database.py`.

---

## 13. Cas limites

| Situation | Comportement |
|---|---|
| `gateway_mac=""`, baseline avec MAC connue | Jamais chargée automatiquement — confirmation requise |
| `gateway_mac=""`, baseline avec `mac=""` | Match exact — baseline chargée |
| Identité non correspondante | Avertissement + confirmation + ancienne baseline intacte |
| `--relearn`, apprentissage échoue | Pas de DELETE — ancienne baseline conservée |
| `--relearn`, 0 host détecté | Avertissement + confirmation avant remplacement |
| `--relearn` autre réseau | Intouchable |
| Mode silencieux, Sentinel redémarre | Compteur réinitialisé — pas de silence hérité |
| Seuil atteint à nouveau après reprise | Nouveau cycle silencieux — jamais permanent |
| Check timeout | `last_check_time` inchangé — DÉGRADÉ si > 2×interval |
| Check réussit après dégradé | Retour ACTIF immédiat |
| Whitelist YAML absent | Whitelist vide, `max_alerts_per_hour=3` par défaut |
| Host disparu | Pas d'alerte V1, compteur actives mis à jour |

---

## 14. Tests nécessaires (liste non exhaustive)

### baseline.py
- `baseline_exists` : retourne False si triplet inconnu
- `baseline_exists` : retourne False si CIDR connu mais MAC différente
- `baseline_exists` : MAC `""` actuelle ≠ match sur baseline avec MAC connue
- `get_baseline` : ne retourne jamais de baseline d'un autre triplet
- `--relearn` : DELETE uniquement pour l'identité courante
- `--relearn` : si apprentissage échoue → ancienne baseline conservée

### monitor.py
- new_host détecté correctement
- new_port détecté correctement
- mac_change détecté correctement
- host disparu → pas de NetworkChange

### alerting.py
- Non whitelisté → Event + Finding + alerte terminal + compteur +1
- Whitelisté → Event resolved=1, pas de Finding, pas d'alerte, compteur 0
- Mode silencieux → Event + Finding en DB, pas d'affichage terminal
- `count >= seuil` → déclenchement silence (pas `>`)
- Arrêt + redémarrage → compteur = 0

### whitelist.py
- `allow port` écrit dans le YAML
- `unallow port` retire du YAML
- `is_whitelisted` retourne True pour entrée présente
- Fichier absent → whitelist vide sans crash

### sentinel_manager.py
- `last_check_time` mis à jour uniquement sur check réussi
- Timeout → `last_check_time` inchangé
- `2 × interval` dépassé → DÉGRADÉ
- Check réussi → retour ACTIF immédiat
- Ctrl+C → state=inactive, baseline conservée, compteur non hérité

---

## 15. Points d'approbation

```
[A] Modifier table baseline :
    + gateway_ip  TEXT NOT NULL DEFAULT ''
    + gateway_mac TEXT NOT NULL DEFAULT ''

[B] Ajouter dans cli.py :
    netlab sentinel allow port/host/mac
    netlab sentinel unallow port/host/mac
    netlab sentinel whitelist
    netlab sentinel history
    netlab sentinel help

[C] Modifier table sessions (Option C1 retenue) :
    + sentinel_state          TEXT DEFAULT 'inactive'
    + last_check_time         TEXT
    + sentinel_target_network TEXT
    + sentinel_gateway_ip     TEXT
    + sentinel_gateway_mac    TEXT
```

**Aucun fichier sentinel/*.py créé, aucune migration DB exécutée avant validation finale.**

---

*Révision 3 — Septembre 2026*
*Spec Sentinel V1 — SentinelX NetLab*
