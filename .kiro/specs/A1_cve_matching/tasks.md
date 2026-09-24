# A1 — Tasks (révision 2)

## Périmètre exact

Fichiers modifiés :
- `knowledge/cve_db.json` — ajout du flag `requires_version_confirmation`
- `detect/service_detection.py` — logique confidence dans `_apply_cve()`
- `tests/test_service_detection.py` — nouveaux tests + mise à jour des existants

**Aucun autre fichier.**

---

## Task 1 — Mettre à jour cve_db.json

Ajouter `"requires_version_confirmation": true` sur 3 entrées :

| service | Modification |
|---|---|
| `microsoft-ds` | ajouter flag, **severity reste "critical"** |
| `ms-wbt-server` | ajouter flag, **severity reste "critical"** |
| `snmp` | ajouter flag, severity reste "medium" |

Mettre à jour les `description` pour indiquer clairement la contrainte
de confirmation de version.

---

## Task 2 — Modifier `_apply_cve()` dans service_detection.py

Logique à implémenter :

```
si entry.requires_version_confirmation == True
   ET finding.service_version == "" (aucune version détectée)
alors :
   confidence = Confidence.POSSIBLE    ← nouveau comportement
   evidence.raw += note d'avertissement
sinon :
   comportement existant inchangé
   (POSSIBLE → PROBABLE si CVE matchée)
```

Pas toucher à :
- `_lookup_cve()`
- `_extract_version()`
- `enrich_findings()`
- Toutes les autres fonctions

---

## Task 3 — Adapter les tests

### Tests existants à vérifier

Le test `test_smb_finding_becomes_critical` dans `TestEnrichFindings` crée un
Finding `microsoft-ds` sans service_version. Après la correction, sa
confidence sera `POSSIBLE` (pas PROBABLE comme avant). Il faut mettre à jour
ce test pour refléter la nouvelle règle.

Vérifier aussi `test_returns_smb_entry_without_version` dans `TestLookupCve` —
le lookup lui-même ne change pas, seulement l'application.

### Nouveaux tests à ajouter (5)

1. **`test_smb_no_version_confidence_is_possible`**
   Finding microsoft-ds, service_version="" → après enrich, confidence=POSSIBLE

2. **`test_rdp_no_version_confidence_is_possible`**
   Finding ms-wbt-server, service_version="" → confidence=POSSIBLE

3. **`test_smb_no_version_severity_stays_critical`**
   Finding microsoft-ds, service_version="" → severity reste CRITICAL (pas abaissée)

4. **`test_evidence_contains_version_warning_when_unconfirmed`**
   Finding sans version + flag → evidence.raw contient la note d'avertissement

5. **`test_smb_with_version_keeps_original_confidence`**
   Finding microsoft-ds, service_version="Windows XP SP3" → confidence non forcée à POSSIBLE

---

## Task 4 — Vérification globale

Lancer les 51 tests existants + les 5 nouveaux :
```
pytest tests/test_service_detection.py -v
```

Vérifier manuellement les cas de régression :
- OpenSSH 7.4 → HIGH, confidence PROBABLE (inchangé)
- Apache 2.4.49 → CRITICAL, confidence inchangée (inchangé)
- Port 445 sans version → CRITICAL, confidence POSSIBLE ← nouveau

---

## Critère de DONE

```
[ ] cve_db.json : flag ajouté sur microsoft-ds, ms-wbt-server, snmp
[ ] severity inchangée dans cve_db.json (pas de modification vers medium)
[ ] _apply_cve() : confidence=POSSIBLE quand requires_version_confirmation
    ET service_version vide
[ ] Evidence contient la note d'avertissement dans ce cas
[ ] 5 nouveaux tests passent
[ ] 51 tests existants passent toujours (0 régression)
[ ] Port 445 sans version : severity=CRITICAL, confidence=POSSIBLE
[ ] Port 3389 sans version : severity=CRITICAL, confidence=POSSIBLE
[ ] OpenSSH 7.4 : HIGH, PROBABLE (inchangé)
[ ] Commit avec message clair
```
