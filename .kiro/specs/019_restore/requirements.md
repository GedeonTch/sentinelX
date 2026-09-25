# #019 — cleanup/restore.py : requirements

## Rôle

`restore.py` prend la liste d'artefacts produite par `artifact_detector.py`
et les supprime après confirmation explicite de l'utilisateur.

C'est le module le plus sensible du projet : une erreur peut supprimer
des fichiers qui ne lui appartiennent pas. Chaque étape est vérifiée.

---

## Contrat fonctionnel (5 étapes)

### Étape 1 — Detect

Appelle `artifact_detector.detect_artifacts(session_id)`.
Si la liste est vide → affiche un message et s'arrête proprement.

### Étape 2 — Validate ownership

Pour chaque artefact de la liste :
- Vérifier que le chemin est bien sous `~/.netlab/` ou `/tmp/netlab-<session_id>/`
- Vérifier que le nom correspond au `session_id` (règle de nommage stricte)
- Si l'artefact échappe à ces règles → SKIP + affiche un warning visible
- Ne jamais supprimer un artefact qui échoue la validation

### Étape 3 — Preview

Afficher la liste complète des artefacts qui SERONT supprimés.
Format lisible : type, chemin, taille.
L'utilisateur voit exactement ce qui va se passer avant de confirmer.

### Étape 4 — Confirmation

L'utilisateur doit taper exactement `yes` (minuscule, mot entier).
- `y` seul → refusé, message d'erreur clair
- `YES` → refusé (case-sensitive)
- tout autre input → annulation propre, exit 0
- Si annulation → rien n'est supprimé

### Étape 5 — Action + Verify

Pour chaque artefact validé :
1. Supprimer le fichier / répertoire
2. Vérifier immédiatement que le chemin n'existe plus
3. Si la suppression échoue → afficher l'erreur + continuer avec les autres
4. Reporter le résultat (supprimé / échec) pour chaque artefact

---

## Contraintes de sécurité absolues

```
NEVER delete a file outside ~/.netlab/ and /tmp/netlab-<session_id>/
NEVER delete without confirming ownership first
NEVER revert a security fix applied by the user
NEVER use glob patterns that could match unintended files
"yes" typed in full — never just "y"
Unit tests MANDATORY before integration
```

---

## Ce que restore.py ne fait PAS

- Ne détecte pas les artefacts lui-même (c'est artifact_detector)
- Ne touche pas aux DBs sentinel (cycle de vie différent)
- Ne modifie pas la DB de session avant la suppression
  (la DB est supprimée en dernier, après les autres artefacts)

---

## Critères de succès

1. Session avec DB + rapport → les deux supprimés après `yes`
2. `y` seul → refusé, rien supprimé
3. `YES` → refusé, rien supprimé
4. Annulation → rien supprimé, exit 0
5. Artefact hors scope → skippé avec warning, pas de suppression
6. Artefact déjà supprimé entre preview et action → pas d'erreur fatale
7. Erreur de permission sur un fichier → erreur affichée, autres artefacts traités
