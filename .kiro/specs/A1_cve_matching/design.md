# A1 — Design technique (révision 2)

## Principe retenu

**Préserver la severity originale de la CVE — réduire la confidence.**

`confidence` existe précisément pour représenter le niveau de certitude.
On ne crée pas un deuxième mécanisme. On réutilise le système existant :

- `confidence = POSSIBLE (0.60)` → Finding affiché en gris, marqué "unconfirmed"
- `confidence < 0.7` → exclu automatiquement du score global (règle déjà en place dans risk_scorer)
- La gravité potentielle reste visible pour l'auditeur

Exemple concret :
```
Port 445 ouvert, version inconnue, CVE EternalBlue :
  severity   = CRITICAL  (conservée — la vulnérabilité est réellement critique)
  confidence = POSSIBLE  (0.60 — version non confirmée)
  → exclu du score global
  → affiché en gris avec note "version à confirmer"

Port 445, version "Windows XP SP3", CVE EternalBlue :
  severity   = CRITICAL  (conservée)
  confidence = PROBABLE  (0.85 — banner match)
  → inclus dans le score global
```

---

## Modification 1 — cve_db.json

Ajouter le champ `requires_version_confirmation: true` sur les entrées
sans contrainte de version (version_gte=null ET version_lte=null).

**La severity ne change pas.**

Avant :
```json
{
  "service": "microsoft-ds",
  "product": "",
  "version_gte": null,
  "version_lte": null,
  "severity": "critical",
  "cve_refs": ["CVE-2017-0144", "CVE-2017-0145"],
  ...
}
```

Après :
```json
{
  "service": "microsoft-ds",
  "product": "",
  "version_gte": null,
  "version_lte": null,
  "severity": "critical",
  "requires_version_confirmation": true,
  "cve_refs": ["CVE-2017-0144", "CVE-2017-0145"],
  "description": "SMBv1 EternalBlue — applies to Windows XP/7/Server 2003/2008 only. Version confirmation required before concluding exploitability."
}
```

**Entrées concernées** (version_gte=null ET version_lte=null) :
- `microsoft-ds` → ajouter flag
- `ms-wbt-server` → ajouter flag
- `snmp` → ajouter flag

**Entrées inchangées** (ont des contraintes de version, pas de flag) :
- ssh/OpenSSH, http/Apache, http/nginx, ftp/vsftpd, domain/dnsmasq, mysql

---

## Modification 2 — service_detection.py : `_apply_cve()`

### Logique actuelle (simplified)

```python
def _apply_cve(finding, cve_entry):
    new_severity = Severity(cve_entry["severity"])
    new_confidence = finding.confidence
    if finding.confidence == Confidence.POSSIBLE:
        new_confidence = Confidence.PROBABLE  # upgrade existant
    return dataclasses.replace(finding, severity=new_severity, ...)
```

### Nouvelle logique

```python
def _apply_cve(finding, cve_entry):
    new_severity = Severity(cve_entry["severity"])
    requires_confirmation = cve_entry.get("requires_version_confirmation", False)

    if requires_confirmation and not finding.service_version:
        # Version non confirmée pour une CVE qui l'exige
        # → confidence POSSIBLE (0.60) = "unconfirmed"
        # → finding exclu du score global par risk_scorer (confidence < 0.7)
        new_confidence = Confidence.POSSIBLE
        version_note = (
            "\n[service_detection] Version not confirmed. "
            "CVE refs are potentially applicable but exploitability cannot "
            "be assessed without version confirmation. "
            "Confidence set to POSSIBLE — excluded from global risk score."
        )
        # Enrichir evidence.raw avec la note sans écraser la preuve existante
        enriched_evidence = Evidence(
            raw=finding.evidence.raw + version_note,
            command=finding.evidence.command,
        )
    else:
        # Version confirmée, ou pas de contrainte de version requise
        # Règle existante : POSSIBLE → PROBABLE si CVE matchée
        new_confidence = (
            Confidence.PROBABLE
            if finding.confidence == Confidence.POSSIBLE
            else finding.confidence
        )
        enriched_evidence = finding.evidence

    return dataclasses.replace(
        finding,
        severity=new_severity,
        cvss_score=cve_entry.get("cvss_score"),
        cve_refs=cve_entry.get("cve_refs", []),
        confidence=new_confidence,
        evidence=enriched_evidence,
        # risk_score stays None — set by risk_scorer only
    )
```

### Résumé des cas

| Situation | severity | confidence | Dans le score global ? |
|---|---|---|---|
| CVE avec version, version détectée | selon CVE | PROBABLE ou CONFIRMED | ✅ oui |
| CVE sans version requise, service détecté | selon CVE | PROBABLE (upgrade de POSSIBLE) | ✅ oui |
| CVE avec `requires_version_confirmation`, pas de version | selon CVE (CRITICAL) | POSSIBLE (0.60) | ❌ non |

---

## Ce qui ne change PAS

- `core/finding.py` — inchangé
- `core/risk_scorer.py` — inchangé (la règle `confidence < 0.7 → exclu` existe déjà)
- `core/database.py` — inchangé
- Tous les modules de scan — inchangés
- `_lookup_cve()`, `_extract_version()`, `enrich_findings()` — inchangés
- `_service_matches()`, `_product_matches()`, `_version_in_range()` — inchangés

---

## Impact sur le score de risque (sans modifier risk_scorer)

Risk scorer exclut déjà les findings avec `confidence < 0.7` du score global.
`Confidence.POSSIBLE = 0.60 < 0.7` → exclusion automatique.

Port 445 sans version :
- Avant : CRITICAL × CONFIRMED × INTERNAL = **93.0** (inclus dans score global)
- Après : CRITICAL × POSSIBLE × INTERNAL = **54.0** (calculé mais exclu du score global)

Le Finding reste visible dans le rapport et les listings — il n'est pas supprimé.
Il est juste exclu du calcul du pire cas réseau.
