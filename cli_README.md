# cli.py — L'interface de commande NetLab V1

## Ce que fait ce fichier

`cli.py` est le point d'entrée unique de NetLab. C'est lui que tu appelles quand tu tapes `netlab scan` ou `netlab findings list`. Il reçoit les arguments, les valide, affiche les résultats — et c'est tout. Il n'y a aucune logique métier ici.

---

## Typer — pourquoi pas argparse ?

Typer est une bibliothèque qui construit une CLI à partir de fonctions Python annotées. Là où argparse demande de déclarer chaque argument manuellement, Typer les déduit des paramètres de la fonction et de leurs types.

Exemple concret :

```python
@app.command()
def scan(
    target: str = typer.Option(..., "--target"),
    profile: str = typer.Option("normal", "--profile"),
) -> None:
    ...
```

Typer génère automatiquement `--help`, valide les types, et gère les erreurs d'usage. Moins de code à écrire, moins de bugs à introduire.

**Règle absolue** : ce projet utilise Typer uniquement. Jamais argparse, jamais click.

---

## Structure des commandes

`cli.py` utilise une hiérarchie de **sub-apps** Typer :

```
netlab                    ← app principale
├── doctor                ← vérifie l'environnement
├── scan                  ← lance un audit
├── findings              ← sous-app
│   ├── list              ← liste les findings d'une session
│   ├── show <id>         ← détail d'un finding
│   ├── explain <id>      ← explication what/attack/defense
│   └── rescan            ← rescan les cibles de la session
├── sentinel              ← sous-app
│   ├── start             ← apprend la baseline et démarre la surveillance
│   ├── status            ← état actuel de la surveillance
│   └── stop              ← arrête la surveillance
├── report                ← sous-app
│   └── generate          ← exporte PDF/HTML/JSON
├── cleanup               ← sous-app
│   └── (callback)        ← --session <id> ou --sessions --older-than <dur>
└── config                ← sous-app
    ├── set <clé> <val>   ← modifie une valeur de configuration
    └── show              ← affiche la configuration actuelle
```

---

## La règle de confirmation

**Aucune action réseau active ne s'exécute sans confirmation explicite.** C'est une règle non-négociable du projet (Section B.6 du steering).

Dans `cli.py`, cela se traduit par :

```python
confirmed = typer.confirm(f"Start scan on {target}?")
if not confirmed:
    display("[yellow]Scan cancelled.[/yellow]")
    raise typer.Exit(code=0)
```

Tout ce qui envoie du trafic réseau (scan, rescan, sentinel start) doit passer par cette confirmation. Jamais `y` en raccourci — toujours la phrase complète pour `cleanup`.

---

## La séparation des couches

`cli.py` ne contient que deux types de code :

1. **Validation d'entrée** : est-ce que le profil est valide ? est-ce que le session ID est fourni ?
2. **Affichage** : appel à `display()` de `core/logger.py` avec des objets Rich

Il ne calcule jamais un score, n'accède jamais directement à SQLite, n'invoque jamais nmap. Il appelle les modules qui font ces choses.

Si tu vois de la logique métier dans `cli.py` — une formule, une règle de détection, un calcul — c'est un bug architectural à corriger.

---

## Les stubs — modules pas encore implémentés

Les modules de scan (#006–#013), le Sentinel (#016), les reports (#017) et le cleanup (#018–#019) ne sont pas encore codés. Plutôt que de laisser le CLI crasher avec une `ImportError`, chaque commande affiche un message clair :

```
Scan modules not yet implemented (tickets #006–#013).
```

Quand un module est livré, le stub est remplacé par l'import réel — sans changer la signature de la commande.

---

## Rich — affichage structuré

Tout ce qui s'affiche passe par `display()` de `core/logger.py`, qui utilise Rich en dessous.

Rich permet d'afficher des tableaux, des panneaux colorés, du texte stylé — sans une ligne de CSS ni de HTML. Exemples dans ce fichier :

- `Table` pour les listes de findings
- `Panel` pour les détails d'un finding ou une explication
- Markup `[red]...[/red]`, `[green]...[/green]` pour les statuts

**Jamais `print()` dans un module** — cette règle s'applique aussi à `cli.py`.

---

## Codes de sortie

| Code | Signification |
|---|---|
| `0` | Succès ou annulation volontaire par l'utilisateur |
| `1` | Erreur — environnement non prêt, argument invalide, ressource introuvable |

Typer gère les codes de sortie via `raise typer.Exit(code=N)`.

---

## Ce que ce fichier ne fait PAS

- **Pas de `import sqlite3`** — la base de données est dans `core/database.py`
- **Pas de calcul de score** — c'est `core/risk_scorer.py`
- **Pas de logique de détection** — ce sont les modules `02_detect/`
- **Pas de `print()`** — tout passe par `display()`

---

## Fichiers liés

| Fichier | Rôle |
|---|---|
| `core/logger.py` | Fournit `display()` — seul canal d'affichage |
| `core/dependencies.py` | Vérifie l'environnement pour `netlab doctor` |
| `core/database.py` | Accédé par les commandes `findings` et `scan` |
| `core/risk_scorer.py` | Appelé après un scan pour scorer les Findings |
| `04_sentinel/` | Implémentera `netlab sentinel` (ticket #016) |
| `reports/generator.py` | Implémentera `netlab report generate` (ticket #017) |
