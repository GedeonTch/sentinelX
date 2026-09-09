# core/finding.py — Le contrat central de SentinelX

## Ce que fait ce fichier

`finding.py` définit la structure de données que **tous les modules de scan doivent retourner**. C'est le seul format que le Core accepte. Un scanner produit des `Finding` — il ne touche pas à SQLite, ne calcule pas de score, et n'affiche rien.

---

## Les concepts clés

### Vulnérabilité vs Exposition vs Risque

Ces trois mots sont souvent confondus. Dans SentinelX, ils ont des rôles précis et séparés.

**Vulnérabilité** : une faiblesse identifiée sur un service ou une configuration. Elle doit être justifiée par une preuve concrète. Exemple : SMBv1 activé sur un serveur Windows. Sans preuve, il n'y a pas de Finding.

**Exposition** : la position du service par rapport au réseau. Un service peut être `internal` (accessible seulement depuis le LAN) ou `external` (accessible depuis l'extérieur). L'exposition n'est pas un défaut — c'est un facteur de contexte qui amplifie ou non le risque. Un port SSH ouvert sur internet est plus dangereux que le même port derrière un firewall.

**Risque** : le résultat d'un calcul qui combine la sévérité de la vulnérabilité, la confiance dans la détection, et le niveau d'exposition. Ce calcul est **exclusivement fait par `core/risk_scorer.py`** — jamais ici.

---

### CVE et CVSS

**CVE** (Common Vulnerabilities and Exposures) : un identifiant standardisé pour une vulnérabilité connue. Format : `CVE-AAAA-NNNNN`. Exemple : `CVE-2017-0144` est EternalBlue, la faille SMB exploitée par WannaCry.

**CVSS** (Common Vulnerability Scoring System) : un score de 0 à 10 qui évalue la gravité d'une CVE. Il prend en compte la complexité d'exploitation, les privilèges requis, l'impact sur la confidentialité / l'intégrité / la disponibilité. Un CVSS de 9.3 signifie une vulnérabilité critique, exploitable à distance, sans authentification.

Dans SentinelX, le champ `cvss_score` stocke cette valeur si elle est connue. `risk_scorer.py` l'utilise comme base de calcul (`cvss_score × 10`). Si la CVE n'est pas connue, il utilise la sévérité générique à la place.

---

### La chaîne Evidence → Confidence → Finding

Un Finding ne s'invente pas. Il suit une chaîne stricte :

```
1. Le scanner identifie une cible (IP, port, service)
2. Il recueille une preuve brute (banner, réponse réseau, sortie de commande)
3. Il compare cette preuve à la base de connaissances locale (CVE lookup)
4. Il évalue le niveau de confiance dans sa conclusion
5. Il crée un Finding avec la preuve et le niveau de confiance
```

**La preuve est stockée telle quelle** dans `evidence.raw` — elle n'est jamais interprétée dans le module de scan. Le champ `evidence.command` enregistre la commande exacte qui a produit cette preuve, pour traçabilité.

Exemple concret :
```
evidence.command = "nmap --script smb-security-mode 192.168.1.10"
evidence.raw     = "smb-security-mode: message_signing: disabled"
```

---

### Confidence — trois niveaux, pas de valeur libre

La confiance représente à quel point le scanner est certain de ce qu'il rapporte. Elle est restreinte à trois valeurs via une enum — pas de `0.9` ou `0.7` inventés.

| Niveau | Valeur | Quand l'utiliser |
|---|---|---|
| `CONFIRMED` | 1.00 | Preuve directe et tangible. Port ouvert confirmé par handshake TCP. |
| `PROBABLE` | 0.85 | Déduction forte. Version inférée depuis un banner HTTP ou SSH. |
| `POSSIBLE` | 0.60 | Estimation comportementale. OS deviné par TTL et fenêtre TCP. |

**Si `confidence < 0.7`** (c'est-à-dire `POSSIBLE`) → le Finding est affiché en gris dans le rapport, marqué "unconfirmed", et exclu du calcul du score global. Il existe quand même — il n'est pas supprimé.

`Confidence` hérite de `float` : dans `risk_scorer.py`, on peut écrire `Confidence.PROBABLE * base_score` directement, sans conversion.

---

### Explanation — ce qui est affiché à l'utilisateur

Le champ `explanation` contient une explication à trois angles, destinée à l'apprentissage :

- `what` : qu'est-ce que cette vulnérabilité et pourquoi elle est dangereuse
- `attack` : comment un attaquant l'exploiterait concrètement
- `defense` : comment la détecter et la corriger

Ces explications **ne sont pas générées ici** — elles viennent de la base de connaissances locale (`knowledge/vulnerabilities.json`), indexée par règle de détection (ex. `smb_v1_active`).

Si aucune règle ne correspond dans la base, `explanation` reste `None`. Jamais un texte générique. Le Finding existe et est valide — il manque juste son explication pour l'instant.

---

### Le cycle de vie d'un Finding

```
OPEN → (rescan) → VERIFIED
     → (fix appliqué + rescan) → REMEDIATED
     → (risque accepté) → ACCEPTED
```

Un Finding créé par un scanner est toujours `OPEN`. C'est l'utilisateur (via `netlab findings rescan`) ou une action manuelle qui le fait progresser.

---

## Ce que ce fichier ne fait PAS

- **Pas de `print()`** — l'affichage passe par `core/logger.py` + Rich
- **Pas de `import sqlite3`** — la persistence est dans `core/database.py`
- **Pas de calcul de `risk_score`** — c'est `core/risk_scorer.py` uniquement
- **Pas d'import de `cli`** — zéro couplage avec la couche d'affichage

---

## Fichiers liés

| Fichier | Rôle |
|---|---|
| `core/risk_scorer.py` | Calcule `risk_score` à partir du Finding |
| `core/database.py` | Persiste les Findings en SQLite |
| `knowledge/vulnerabilities.json` | Peuple `explanation` par règle de détection |
| `knowledge/ports.json` | Aide à identifier le service (fingerprinting) |
| `reports/generator.py` | Lit les Findings pour générer les rapports |
