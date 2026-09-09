# core/risk_scorer.py — Le calcul du risque

## Ce que fait ce fichier

`risk_scorer.py` est le **seul fichier autorisé à calculer `risk_score`**. Il reçoit un `Finding` en entrée et retourne un nombre entre 0 et 100 qui représente le niveau de risque de cette vulnérabilité dans son contexte.

Aucun scanner, aucun module de détection, aucune fonction CLI ne calcule ce score. Si tu vois un `risk_score` non-None qui n'est pas passé par ce fichier, c'est un bug.

---

## La formule — jamais une boîte noire

```
risk_score = min(100, base_severity × confidence_factor × exposure_factor)
```

Trois facteurs multipliés ensemble, plafonnés à 100. Chaque facteur a une signification précise.

---

## Les trois facteurs

### 1. Base severity — la gravité brute

C'est le point de départ. Deux cas :

**Si le CVSS est connu** (la CVE a un score officiel) :
```
base = cvss_score × 10
```
Un CVSS de 9.3 (EternalBlue) donne une base de 93. Un CVSS de 5.0 donne 50.

**Si le CVSS n'est pas connu** (pas de CVE référencée, ou CVE sans score) :
```
CRITICAL → 90
HIGH     → 70
MEDIUM   → 45
LOW      → 20
INFO     →  5
```

Ces valeurs sont stockées dans `config.yaml` — elles peuvent être ajustées si nécessaire, à condition de retester les 5 cas de référence.

Le CVSS prend toujours la priorité sur la sévérité enum. Un Finding `HIGH` avec `cvss_score=5.0` aura une base de 50, pas 70.

### 2. Confidence factor — la certitude de la détection

```
CONFIRMED (1.00) → ×1.00  — aucune réduction
PROBABLE  (0.85) → ×0.85  — réduction de 15%
POSSIBLE  (0.60) → ×0.60  — réduction de 40%
```

Si on n'est pas certain qu'une vulnérabilité existe vraiment, on réduit son impact sur le score. Un banner qui dit "Apache 2.4.x" ne confirme pas une CVE Apache — c'est `PROBABLE` au mieux.

### 3. Exposure factor — la position sur le réseau

```
INTERNAL → ×1.00  — pas de modification
EXTERNAL → ×1.15  — amplification de 15%
```

Le même service vulnérable est plus dangereux s'il est accessible depuis internet. L'exposition ne crée pas la vulnérabilité — elle amplifie le risque.

---

## Exemples concrets (cas de référence des tests)

| Scénario | Base | Confidence | Exposure | Calcul | Score |
|---|---|---|---|---|---|
| EternalBlue (CVE-2017-0144, cvss=9.3) | 93.0 | ×1.00 | ×1.00 | 93.0 | **93.0** |
| SSH banner probable, interne | 70 | ×0.85 | ×1.00 | 59.5 | **59.5** |
| HTTP ouvert, externe, confirmé | 45 | ×1.00 | ×1.15 | 51.75 | **51.75** |
| Credentials par défaut, externe | 70 | ×1.00 | ×1.15 | 80.5 | **80.5** |
| OS fingerprint estimé, bas | 20 | ×0.60 | ×1.00 | 12.0 | **12.0** |
| CVSS 10.0, externe (dépasserait 100) | 100 | ×1.00 | ×1.15 | 115.0 → **100.0** (plafonné) |

Ces cas sont codés dans `tests/test_risk_scorer.py` avec leurs calculs documentés. Si tu modifies les coefficients dans `config.yaml`, ces tests doivent tous repasser.

---

## Le score global du réseau

```python
get_global_score(findings) → Optional[float]
```

Le score global d'une session n'est **jamais une moyenne**. C'est le score le plus élevé parmi tous les Findings qualifiants.

Un Finding est qualifiant si :
- Son statut est `OPEN`
- Sa confiance est ≥ 0.7 (donc `CONFIRMED` ou `PROBABLE` — pas `POSSIBLE`)

Pourquoi le pire cas et pas la moyenne ? Parce qu'une seule vulnérabilité critique suffit à compromettre un réseau. Moyenner diluerait l'information qui compte.

---

## Pourquoi les coefficients sont dans config.yaml

Les coefficients (base_severity, confidence_factor, exposure_factor) sont dans `config.yaml` pour deux raisons :

**Transparence** : n'importe qui peut lire le fichier et comprendre exactement comment le score est calculé, sans lire le code.

**Ajustabilité** : si un contexte particulier justifie de modifier les poids (ex. lab interne où l'exposition externe est moins critique), on change le fichier — pas le code. Mais tout changement doit être retesté sur les 5 cas de référence avant d'être utilisé.

Si `config.yaml` est absent (ex. première installation), le scorer utilise des valeurs par défaut codées en dur — il ne crash pas.

---

## Ce que ce fichier ne fait PAS

- **Pas de `print()`** — aucun affichage
- **Pas de `import sqlite3`** — pas d'accès à la base de données
- **Pas d'écriture en base** — `score_findings()` retourne de nouveaux objets Finding, c'est `core/database.update_finding_risk_score()` qui persiste le résultat
- **Pas de décision de détection** — il reçoit un Finding déjà créé, il ne décide pas si une vulnérabilité existe

---

## Fichiers liés

| Fichier | Rôle |
|---|---|
| `config.yaml` | Source des coefficients — modifiable, mais retester les 5 cas |
| `core/finding.py` | Définit Finding, Severity, Confidence, Exposure |
| `core/database.py` | Persiste le score via `update_finding_risk_score()` |
| `reports/generator.py` | Inclut `FORMULA_DESCRIPTION` dans chaque rapport généré |
| `tests/test_risk_scorer.py` | 7 cas de référence + invariants — à relancer après tout changement de coefficients |
