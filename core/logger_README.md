# core/logger.py — Sortie terminal via Rich

## Ce que fait ce fichier

`logger.py` expose **une** console Rich partagée (`get_console()`). C'est le chemin d'affichage autorisé dans SentinelX. Les modules ne doivent pas appeler `print()`.

Il ne contient aucune logique métier : pas de check d'environnement, pas de score, pas de base de données.

---

## Pourquoi Rich et pas `print()` ?

`print()` mélange le fond et la forme. Dans NetLab, un scanner calcule des `Finding`, le CLI affiche, le logger est le tuyau. Si chaque module imprime, on ne peut plus tester le fond sans capturer stdout, ni garantir un affichage cohérent (couleurs, tables, pas de mélange avec les logs).

Rich écrit sur le terminal de façon contrôlée. Les modules appellent `display()`, pas `print()`. `netlab doctor` s'en sert pour la table d'environnement.
