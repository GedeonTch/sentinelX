# core/dependencies.py — Vérification de l'environnement avant un scan

## Ce que fait ce fichier

`dependencies.py` répond à une seule question : **la machine est-elle prête pour lancer un outil d'audit réseau ?** Il vérifie Python (>= 3.10), `nmap`, `enum4linux`, et le dossier `~/.netlab/`. Il retourne **une fiche typée par item** (`DependencyCheck` : nom, présent, version/détail) — jamais un simple `True`/`False` global comme résultat principal.

Il ne scanne rien. Il ne crée aucun `Finding`. Il n'affiche rien. L'affichage est le rôle de `cli.py` (`netlab doctor`) via Rich et `core/logger.py`.

---

## Pourquoi vérifier l'environnement avant un outil offensif ?

Un scan NetLab n'est pas un `print` inoffensif. `nmap` envoie des paquets sur le réseau. `enum4linux` interroge des services Windows. Même en labo autorisé, deux choses doivent être vraies **avant** le premier paquet :

1. **Les outils existent vraiment.** Si `nmap` est absent, un scan "qui a l'air de marcher" peut en réalité ne rien faire, ou planter au milieu. L'opérateur croit alors qu'une cible est saine alors que rien n'a été testé.
2. **L'opérateur sait ce qui manque.** Un crash Python (`FileNotFoundError`) n'explique pas comment installer `enum4linux`. Un rapport clair (`present=False`, version inconnue) permet de corriger l'environnement sans improviser.

Vérifier d'abord, scanner ensuite : c'est de la hygiène, pas de la politesse. Un outil offensif mal lancé est à la fois un risque opérationnel (trafic involontaire, résultats faux) et un risque pédagogique (on n'apprend pas ce qu'on n'a pas réellement exécuté).

`netlab doctor` ne remplace pas l'autorisation écrite de tester un réseau. Il vérifie seulement que **cet ordinateur** peut faire le travail. Le cadre légal reste : réseaux que tu possèdes ou pour lesquels tu as une autorisation explicite.

---

## Les checks

| Nom | Ce qui est testé | `present` | `version` (détail) |
|---|---|---|---|
| `python` | Interpréteur **en cours d'exécution** | Toujours `True` (le code tourne) | `sys.version_info` (ex. `3.12.3`) |
| `nmap` | Binaire sur le `PATH` (`shutil.which`) | `True` si trouvé | Sortie de `nmap --version` si lisible |
| `enum4linux` | Binaire sur le `PATH` | `True` si trouvé | Sortie de `--version` si lisible |
| `.netlab` | Dossier `Path.home() / ".netlab"` | `True` s'il existe (ou a pu être créé) **et** qu'on peut y écrire | Chemin résolu si OK ; message d'erreur sinon |

Python n'est pas cherché via `which python3` : on audite l'interpréteur qui exécute NetLab, pas un autre Python installé à côté.

Le chemin `~/.netlab/` n'est jamais écrit en dur (`C:\...` ou `/home/...`). Il est construit avec `pathlib` : `Path.home() / ".netlab"`. Ça marche sur Windows et Linux.

`environment_ready(checks)` est un **agrégat** pour le code de sortie du CLI. Le résultat du module, c'est la liste. Un booléen tout seul cacherait *quel* item manque.

Pour Python, "présent" ne veut pas dire "assez récent". NetLab exige **3.10+**. Un Python 3.9 aura `present=True` et le statut `python_too_old`.

---

## Pourquoi vérifier ~/.netlab/ ?

Les sessions d'audit sont des fichiers SQLite : `~/.netlab/sessions/<session_id>.db`. Sans ce dossier inscriptible, `database.py` ne pourra pas créer le fichier au moment du scan.

Si `doctor` ne le vérifiait pas, le scan partirait (nmap tournerait, du trafic partirait sur le labo) puis **échouerait plus tard**, au premier `save_finding` / `init_db`. L'opérateur verrait une erreur SQLite ou un `PermissionError` au milieu d'un scan, pas un diagnostic clair. Pire : il pourrait croire que l'audit a eu lieu alors que **rien n'a été persisté**.

`doctor` échoue **avant** le scan : dossier absent → tentative de création de `~/.netlab/` uniquement (pas de `sessions/`, pas de SQLite). Création impossible ou dossier non inscriptible → `present=False`, détail explicite, code de sortie `1`. Pas de crash.

Ce check ne remplace pas `database.py`. Il ne crée pas les bases. Il confirme seulement que l'emplacement prévu pour les bases est utilisable.

---

## Comportement si un outil manque

Aucun crash. `shutil.which` retourne `None` → `present=False`, `version=None`. Si le binaire existe mais `--version` timeout ou lève une erreur OS → `present=True`, `version=None`. `netlab doctor` affiche la table et quitte avec le code `1` si l'environnement n'est pas prêt.

Windows et Linux utilisent la même API (`shutil.which` gère `nmap.exe` via `PATHEXT`). `enum4linux` est surtout un outil Linux ; sur Windows il sera souvent `missing` — c'est un résultat, pas une exception.

---

## Ce que ce fichier ne fait jamais

- `print()` — affichage via Rich / `core/logger.py` dans le CLI
- `import sqlite3`
- Produire un `Finding`
- Lancer un scan réseau
- Décider d'un `risk_score`
- Créer `~/.netlab/sessions/` ou ouvrir SQLite

---

## Commande

```bash
python cli.py doctor
```

Une fois l'entrée `netlab` branchée (ticket CLI complet), la même commande s'appellera `netlab doctor`.
