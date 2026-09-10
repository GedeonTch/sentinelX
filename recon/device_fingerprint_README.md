# recon/device_fingerprint.py — Découverte et fingerprinting des machines

## Ce que fait ce module

C'est le **premier module qui envoie du trafic réseau** dans NetLab. Son rôle dans le pipeline : **DISCOVER** — répondre à la question *"Qui est sur ce réseau ?"*

Pour chaque machine active trouvée, il produit un `Finding` contenant l'IP, le MAC si disponible, le hostname si résolvable, et l'OS estimé par nmap.

Il ne scanne pas les ports — c'est `detect/tcp_scan.py` qui s'en charge plus tard.

---

## Comment fonctionne nmap ici

Le module fait **deux passes nmap** :

### Passe 1 — Ping scan (`-sn`)

```bash
nmap -sn -oX - 192.168.1.0/24
```

`-sn` signifie "scan sans port" — nmap envoie uniquement des paquets ICMP echo (ping) et ARP pour savoir qui répond. Il ne touche à aucun port. C'est rapide et peu intrusif.

`-oX -` demande à nmap de produire la sortie au format XML sur stdout. C'est ce XML qu'on parse pour extraire les IPs actives, les MACs et les hostnames.

### Passe 2 — OS detection (`-O --osscan-guess`)

```bash
nmap -O --osscan-guess -oX - 192.168.1.10
```

`-O` active la détection d'OS. nmap envoie des paquets TCP/IP spécialement construits et analyse les réponses (TTL, taille de fenêtre TCP, flags) pour déterminer quel OS tourne sur la machine.

`--osscan-guess` dit à nmap de tenter une estimation même quand il n'est pas certain. Sans ce flag, nmap ne rapporte rien s'il n'est pas assez sûr.

**Note** : la détection d'OS nécessite des privilèges root sur Linux (raw sockets). Sur Windows, nmap l'exécute avec les droits administrateur.

---

## Pourquoi deux passes séparées ?

La passe 1 est rapide et non-intrusive — elle s'exécute sur tout le réseau en quelques secondes. La passe 2 est plus lente et envoie plus de paquets — elle est exécutée machine par machine, seulement sur les hosts actifs.

Si on faisait les deux en une seule commande (`nmap -sn -O 192.168.1.0/24`), on perdrait la clarté sur ce qu'on a fait et pourquoi. Deux passes = deux responsabilités séparées, deux blocs d'evidence distincts dans le Finding.

---

## La règle de confidence pour l'OS

nmap donne un score d'accuracy (0–100) pour chaque estimation d'OS. On le traduit ainsi :

| Accuracy nmap | Confidence | Signification |
|---|---|---|
| ≥ 85% | `PROBABLE` | Déduction forte — le fingerprint TCP/IP correspond bien |
| < 85% | `POSSIBLE` | Estimation incertaine — nmap "devine" |
| Pas de match | (non applicable) | `service_version` reste vide |

On ne retourne jamais `CONFIRMED` pour l'OS — même à 100%, la détection d'OS de nmap est probabiliste par nature. Elle se base sur des heuristiques, pas sur une preuve directe comme un handshake TCP.

En revanche, le fait qu'un **host soit actif** (il a répondu au ping) est `CONFIRMED` — c'est une observation directe.

---

## Ce que contient le Finding produit

| Champ | Valeur |
|---|---|
| `module` | `"device_fingerprint"` |
| `category` | `NETWORK` |
| `severity` | `INFO` — découvrir un host n'est pas une vulnérabilité |
| `confidence` | `CONFIRMED` — le host a répondu |
| `target_ip` | IP de la machine |
| `target_port` | `None` — pas de scan de port ici |
| `target_service` | `"host"` |
| `service_version` | Nom de l'OS détecté (ex. `"Linux 4.15"`) ou vide |
| `evidence.raw` | XML brut des deux passes nmap |
| `evidence.command` | Les deux commandes nmap exécutées |
| `explanation` | `None` — peuplé par la base de connaissances (#015) |
| `risk_score` | `None` — calculé par `risk_scorer.py` uniquement |

---

## La sortie XML de nmap — pourquoi pas du texte ?

nmap peut produire sa sortie en texte lisible (`-oN`) ou en XML (`-oX`). On utilise XML parce que :

- **Parsable de façon fiable** : le texte nmap change de format selon la version et les options. Le XML est stable.
- **Complet** : le XML contient tous les champs (MAC, vendor, hostname, OS matches avec leur accuracy) dans une structure hiérarchique claire.
- **Traçable** : on stocke le XML brut dans `evidence.raw` — n'importe qui peut le relire et vérifier ce que nmap a trouvé.

---

## Ce que ce module ne fait PAS

- **Pas de `print()`** — affichage via `display()` de `core/logger.py`
- **Pas de `import sqlite3`** — la persistence est dans `core/database.py`
- **Pas de calcul de `risk_score`** — c'est `core/risk_scorer.py`
- **Pas de scan de ports** — c'est `detect/tcp_scan.py`
- **Pas d'explication** — `explanation` reste `None` jusqu'au ticket #015

---

## Fichiers liés

| Fichier | Rôle |
|---|---|
| `core/finding.py` | Définit Finding, Evidence, Confidence, Category |
| `core/database.py` | Persiste les Findings retournés par ce module |
| `core/risk_scorer.py` | Calcule le score après que cli.py appelle ce module |
| `detect/tcp_scan.py` | Étape suivante — scanne les ports des hosts découverts ici |
| `knowledge/vulnerabilities.json` | Peuplera `explanation` pour les règles de ce module (#015) |
