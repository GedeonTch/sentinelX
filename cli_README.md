# cli.py — Orchestration Typer (NetLab)

## Ce que fait ce fichier (ticket #003)

Pour l'instant, `cli.py` n'expose que **`doctor`**. Il appelle `check_environment()`, affiche le rapport avec Rich, et choisit le code de sortie. Il ne cherche pas les binaires et ne parse pas les versions.

Les autres commandes (`scan`, `findings`, `sentinel`, …) arriveront plus tard. Ce fichier ne doit jamais contenir de logique métier.

## Lancer doctor

```bash
python cli.py doctor
```
