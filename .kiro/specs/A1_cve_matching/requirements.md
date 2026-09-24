# A1 — Faux positifs CVE : requirements (révision 2)

## Principe fondamental

> L'absence de version ne diminue pas la gravité potentielle de la CVE ;
> elle diminue la certitude de son applicabilité.

Le système dispose déjà d'un mécanisme pour représenter l'incertitude :
`confidence`. C'est ce mécanisme qui doit être utilisé — pas un abaissement
artificiel de la sévérité.

---

## Problème

Le matching CVE actuel (`detect/service_detection.py`) déclare des
vulnérabilités CRITICAL (EternalBlue CVE-2017-0144, BlueKeep CVE-2019-0708)
à partir de la seule présence d'un port ouvert (445, 3389), sans confirmation
de version ni de système d'exploitation.

Exemple observé en lab :
- Port 445 ouvert sur Windows Server 2019 → Finding CRITICAL EternalBlue
- EternalBlue n'affecte que Windows XP/7/Server 2003/2008 non patchés
- Windows Server 2019 n'est pas vulnérable

C'est une violation directe du steering doc (Section G) :
> "banner says Apache 2.4.x ≠ Apache vulnerability confirmed.
>  A Finding requires evidence. A CVE ref requires version confirmation."

---

## Règle définitive

Pour une entrée CVE avec `requires_version_confirmation: true`
ET sans `service_version` détectée sur le Finding :

- **severity** : conservée telle quelle (CRITICAL reste CRITICAL)
- **confidence** : forcée à `POSSIBLE (0.60)`
- **evidence** : enrichie d'une note indiquant que la version doit être confirmée
- **visibilité** : le Finding reste visible dans les rapports et listings
- **score global** : exclu automatiquement car `confidence < 0.7`
  (règle déjà présente dans `risk_scorer.py` — aucune modification nécessaire)

Le message métier :
> "La vulnérabilité potentielle est critique, mais les preuves actuelles
>  ne permettent pas de confirmer qu'elle s'applique à cette machine."

---

## Comportement par cas

| Situation | severity | confidence | Dans le score global |
|---|---|---|---|
| CVE sans `requires_version_confirmation`, service détecté | selon CVE | PROBABLE (upgrade de POSSIBLE) | ✅ oui |
| CVE avec `requires_version_confirmation`, version détectée | selon CVE | selon comportement existant | ✅ oui |
| CVE avec `requires_version_confirmation`, **version absente** | **selon CVE (inchangée)** | **POSSIBLE (0.60)** | ❌ non |

---

## Ce qui ne change PAS

- `core/finding.py` — inchangé
- `core/risk_scorer.py` — inchangé (règle confidence < 0.7 → exclu déjà en place)
- `core/database.py` — inchangé
- Tous les modules de scan — inchangés
- Les entrées CVE avec contraintes de version — inchangées

---

## Ce qui change

1. **`knowledge/cve_db.json`** : ajout du champ `requires_version_confirmation: true`
   sur les entrées sans contrainte de version (microsoft-ds, ms-wbt-server, snmp).
   La `severity` de ces entrées n'est pas modifiée.

2. **`detect/service_detection.py`** : `_apply_cve()` applique
   `confidence = POSSIBLE` quand le flag est présent et `service_version` est vide.
   Enrichit `evidence.raw` avec une note d'avertissement.

3. **`tests/test_service_detection.py`** : 5 nouveaux tests + mise à jour
   du test existant sur le Finding microsoft-ds.

---

## Critères de succès

| Cas | severity attendue | confidence attendue | Dans le score global |
|---|---|---|---|
| Port 445, version inconnue | CRITICAL | POSSIBLE | ❌ non |
| Port 3389, version inconnue | CRITICAL | POSSIBLE | ❌ non |
| Port 161 (SNMP), version inconnue | MEDIUM | POSSIBLE | ❌ non |
| Port 445, version "Windows XP SP3" | CRITICAL | PROBABLE | ✅ oui |
| OpenSSH 7.4 | HIGH | PROBABLE | ✅ oui (inchangé) |
| Apache 2.4.49 | CRITICAL | selon probe | ✅ oui (inchangé) |
