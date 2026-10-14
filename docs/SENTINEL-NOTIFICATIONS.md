# Sentinel — notifications par hôte, monitor et rapport réseau

Base : `450d00473dedc4dab2984af5311138cc62e0b66a`. Ce document remplace la règle
historique du compteur global/silence fixe, sans changer les sondes, la baseline,
les types d'événements, les Findings, leur scoring ou le protocole start/stop.

## Quota verrouillé

Trois **notifications émises** au maximum par couple réseau/IP dans une fenêtre
glissante de 60 minutes. La quatrième est masquée. Chaque émission libère sa place
exactement 60 minutes après son horodatage confirmé ; aucune pause fixe n'est
ajoutée. Les IP IPv6 sont normalisées pour le calcul. La portée est une adresse
dans un réseau, pas une identité physique basée sur la MAC.

Le paramètre historique `sentinel_max_alerts_per_hour` reste lu/écrit par les API
whitelist pour compatibilité, mais ne pilote plus ce quota verrouillé à trois.
La whitelist et ses règles restent inchangées. Les INFO ne consomment aucune
place. Tous les événements et Findings suivent les règles de persistance
antérieures, y compris pendant le silence. Aucun événement/Finding n'est fusionné.

## Contrat de données, sans migration

Seule une clé additive `notification` dans le JSON `events.details` est écrite :

- `version: 1` ;
- `state: whitelisted` et `decided_at` : INFO, hors quota ;
- `state: masked` et `decided_at` : notification masquée par quota ;
- `state: preparing` et `decided_at` : intention persistée avant émission ;
- `state: confirmed`, `decided_at`, `emitted_at` : écriture terminal/flush réussis ;
- `state: uncertain`, `recovered_at`, `reserved_until` : issue non confirmée,
  réservation prudente jusqu'à récupération + 60 minutes.

Une émission est un événement distinct envoyé au flux terminal, y compris stdout
redirigée. Un rafraîchissement Rich n'est pas une nouvelle émission. Une émission
confirmée n'atteste pas que l'utilisateur l'a lue. Rich n'élide pas verticalement
les lignes lors de l'émission, pour ne pas confirmer un détail non écrit.

L'événement est persisté avant son Finding et sa décision de notification. Une
interruption avant cette décision peut laisser un événement sans métadonnée :
notification inconnue, jamais requalifiée comme affichée. Un échec d'intention
empêche toute émission. Un échec pendant l'émission ou sa confirmation laisse
une réserve incertaine ; si son écriture échoue aussi, l'intention reste en base
pour récupération au prochain démarrage. L'exception initiale n'est pas remplacée.

Le propriétaire réseau exclusif récupère les intentions une seule fois au
branchement du contrôleur, avant toute nouvelle notification. Les réserves déjà
incertaines ne sont ni réinitialisées ni prolongées par les redémarrages.

Les événements anciens sans métadonnées ne sont jamais réécrits. Chaque
observation non whitelistée récente et attribuable à un hôte réserve prudemment
une place jusqu'à expiration de sa date ; aucun compteur « affichées » ou
« masquées » n'est inventé. Une date invalide entraîne une réserve conservatrice
sans échéance déductible. Les dates futures restent occupantes après un recul de
l'horloge. Les données d'émission sont en UTC pour permettre le redémarrage ; des
sauts en avant de l'horloge système peuvent affecter toute fenêtre civile.

Les méthodes de contrôle et SQLite restent dans `core/database.py`. Les lectures
ne sont pas limitées aux 100 derniers événements. Elles chargent actuellement
l'historique complet : coût mémoire/temps croissant avec la taille de la base,
sans migration/index supplémentaire. Une optimisation future devra conserver
les intentions anciennes non récupérées et les réserves non expirées.

## Monitor

Bandeau réseau, intervalle (attente après le contrôle), phase et dernier contrôle
réellement terminé pendant cette exécution. L'heure de démarrage n'est plus
écrite comme heure du dernier contrôle réussi. Un contrôle partiel/échoué ne
met pas à jour `last_check_time` comme s'il avait réussi.

En TTY, Rich affiche les 20 dernières notifications de cette exécution et les
compteurs de tous les hôtes présents dans l'historique. La vue réévalue les
échéances pendant l'attente sans changer le polling lifecycle. Sur petit terminal,
les colonnes sont présentées en paires libellé/valeur. Beaucoup d'hôtes peuvent
nécessiter du défilement. En non-TTY, chaque notification est écrite une seule fois,
puis des instantanés de phase/compteurs, sans animation ni répétition des détails.

Les alertes masquées n'apparaissent jamais individuellement dans cette vue.
Les compteurs « affichées » et « masquées » couvrent 60 minutes ; les réserves sont
séparées et ne sont jamais présentées comme des émissions confirmées. Les INFO
whitelistées gardent leur affichage discret existant.

## Rapport autonome

```sh
netlab sentinel report -n <network_id> -o html
netlab sentinel report --network <network_id> --output-format html
```

Un nom exclusif `sentinel-status-<network_id>-<UTC-microsecondes>-<suffixe>.html`
est créé dans le répertoire courant et son emplacement affiché. Aucun fichier
existant n'est écrasé. Ce n'est pas `netlab report generate --session ...`.

Lecture seule de la DB réseau dans une transaction cohérente : aucun scan,
serveur, récupération d'intention ou modification de données. Logo existant
`reports/assets/SentinelleX.png` intégré en base64 ; palette rouge/noir/blanc
reprenant le rapport d'audit. CSS intégré et sections natives « Voir plus », sans
JavaScript ni ressource distante. Toutes les valeurs dynamiques sont échappées.
Seuls les champs Sentinel utiles sont sélectionnés ; aucune preuve brute de
Finding, aucun coffre, aucune donnée d'authentification n'est consulté.

Le rapport montre l'état **enregistré**, non la présence d'un processus. Les
statistiques d'assets ne sont pas une mesure actuelle du réseau. La date de
baseline disponible est explicitée ; l'horodatage de contrôle historique n'est
pas recertifié, car les anciennes versions l'écrivaient aussi au démarrage.
Les notifications anciennes sont inconnues même si leur statut whitelist est
connu. Seules les métadonnées explicites permettent d'affirmer un masquage.
L'historique entier est conservé dans le HTML, par groupes repliables de 25.

Sentinel reste un système de sondage périodique : un événement apparu et disparu
entre deux contrôles peut être manqué. Une anomalie persistante peut produire
un événement et un Finding à chaque cycle. La déduplication relève d'un autre
ticket, pas de ce quota d'affichage.

## Validation

Horloge contrôlée et SQLite temporaire : limites exactes, hôtes/réseaux distincts,
whitelist, redémarrage, intentions/confirmation interrompues, données anciennes,
historique >100 événements, dérive arrière, persistance malgré silence. Tests
Rich TTY/non-TTY/terminal étroit, absence de détails masqués, phases dégradées,
HTML échappé et autonome, unicité, aucune écriture DB. Scans simulés uniquement.
Les tests lifecycle A/B restent en place ; quatre vrais processus CLI successifs
vérifient en plus la conservation du quota entre propriétaires.
