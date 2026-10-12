# Sentinel — cycle de vie interprocessus

## Commandes et contrat

```sh
netlab sentinel start --target 192.0.2.0/24
netlab sentinel stop --network <network_id> --timeout 30
```

`--timeout` est une durée positive finie, en secondes, de **confirmation** (30 s
par défaut), pas une durée maximale de scan. Le temps de démarrage de la CLI
n'est pas inclus. Le polling est de 100 ms ; une opération SQLite peut attendre
jusqu'à 200 ms avant de signaler une contention. Ordonnancement/IO peuvent ajouter
une latence : ce n'est pas une garantie temps réel.

Le code de sortie 0 de `stop` exige conjointement :

1. l'acquittement final `completed` de l'instance précisément visée ;
2. l'acquisition possible du verrou réseau ;
3. la terminaison de l'objet processus OS identifié, et non du seul PID.

Une demande enregistrée, un statut `inactive`, un fichier de verrou existant ou
un acquittement seul ne prouvent pas l'arrêt. Un timeout retourne 1 et **laisse la
demande enregistrée**. Un nouveau `stop` peut vérifier sa réalisation ultérieure.
Aucune terminaison forcée ni escalade n'est effectuée.

`--session` est conservé : résolution des identifiants d'exécution et anciens
identifiants réseau uniquement à partir des enregistrements de contrôle. Si un
identifiant correspond à plusieurs réseaux, refus explicite. Un ancien identifiant
d'exécution ne cible jamais le nouveau propriétaire. Avec un autre propriétaire
actif, la confirmation de l'ancien peut échouer faute de verrou libre : utiliser
`--network` pour demander l'arrêt du propriétaire actuel. Exactement une des deux
options est requise. Une ancienne base sans contrôle ne permet pas d'arrêter un
processus lancé avec une ancienne version du logiciel.

## Verrou et stockage additif

- Verrou stable : `~/.netlab/sentinel/control/<network_id>.lock`.
- `portalocker` exclusif/non bloquant, conservé de l'acquisition avant toute
  mutation des données jusqu'à la fin de la finalisation. **Jamais supprimé**.
- Linux : dossier 0700, fichier 0600. Windows : DACL protégée réservée à
  l'utilisateur courant, héritage aux enfants du dossier de contrôle.
- Un concurrent perdant le verrou ne crée/modifie ni session, ni baseline, ni
  état réseau. Les réseaux différents ont des verrous différents.
- La session fournie à `start --session` doit être nouvelle : réservation de son
  fichier par création exclusive pour éviter un remplacement ou une course entre
  réseaux distincts. Un identifiant généré utilise un UUID complet.
- Toute connexion, requête, transaction et création de table de contrôle est
  centralisée dans `core/database.py`. `sentinel/lifecycle.py` n'importe pas
  SQLite et n'exécute aucun SQL.
- Validation ASCII complète de `network_id` avant construction des chemins DB
  et verrou : 1–64 lettres/chiffres/tirets/underscores ; séparateurs, traversal,
  sauts de ligne et noms de périphériques Windows refusés. Les identifiants sûrs
  historiques restent acceptés. `--network` doit correspondre à une base réseau
  connue ET à son enregistrement de contrôle ; un inconnu ne construit pas de
  chemin DB et ne crée pas de fichier.
- Une réservation exclusive qui reste vide et inchangée est retirée à la sortie
  de la tentative, y compris si la préparation réseau ou propriétaire échoue.
  Le nettoyage compare l'identité du fichier et sa date de changement : jamais
  de suppression d'un fichier préexistant ou remplacé. Un fichier non vide, même
  en cas d'écriture incertaine, est conservé plutôt que de risquer une session
  créée. Ce nettoyage conservateur n'est pas une réparation des DB incomplètes.
- Table additive `sentinel_control` dans la base réseau existante. Une ligne par
  instance : UUID d'instance, réseau, véritable session, PID, identité de naissance
  OS, demande, résultat, catégorie d'erreur de finalisation et compteurs
  `cycle_active` / `cycle_number` réservés au contrôle.
- Les lignes restent disponibles pour les attentes tardives et le diagnostic ;
  aucune purge automatique n'est incluse. Aucune table métier n'est migrée.
- B écrit seulement `stop_requested` sur la ligne ciblée, jamais le statut final
  du réseau. Les opérations de lecture/demande utilisent une base existante et ne
  créent pas de fichier DB pour une identité inconnue.

## Propriétaire et fin d'exécution

Pendant l'attente, A consulte le contrôle toutes les 100 ms au plus hors IO.
L'admission du cycle et la demande d'arrêt sont deux écritures sur la même ligne
SQLite. L'admission est un UPDATE conditionnel (`stop_requested=0`, propriétaire
`running`, aucun cycle actif) qui marque le cycle actif et incrémente son numéro.
**Le commit est le point de linéarisation** :

- arrêt enregistré en premier → admission refusée, aucune sonde du nouveau cycle ;
- cycle admis en premier → déjà considéré en cours, même si le processus est
  suspendu avant la première instruction de sonde ; il peut terminer.

Il n'y a plus de décision fondée sur une lecture suivie d'un démarrage non
synchronisé. La fin du cycle remet son indicateur à zéro, sans effacer la demande.
Une sonde/cycle admis en cours est laissé terminer. L'apprentissage initial et la confirmation
interactive ne sont pas annulés : une demande pendant cette phase peut expirer
côté B en attendant que A atteigne sa boucle ou sorte.

La finalisation commune tente indépendamment : clôture de la vraie session,
statut réseau `inactive`, puis acquittement. Le verrou est libéré même en erreur.

| Sortie A | Session | Résultat contrôle |
|---|---|---|
| Arrêt coopératif | `completed` | `completed` |
| Ctrl+C / refus de confirmation | `partial` | `completed` si écritures réussies |
| Erreur fatale / échec d'apprentissage | `failed` | `failed` |
| Échec d'écriture finale | selon écritures effectivement réussies | `finalization_failed` si contrôle accessible |

Une erreur de contrôle empêche l'acquittement ; l'exception reste visible et B ne
confirme pas une fin propre. Le texte conservé en contrôle contient uniquement
la catégorie d'opération et le type d'exception, pas son contenu potentiellement
sensible. Les transactions entre base réseau et base session ne sont pas atomiques.

Un contrôle dégradé ou une erreur de scan attendue conserve le comportement métier
existant et permet toujours la prise en compte de la demande. Une exception
inattendue de contrôle passe désormais par la finalisation fatale.

Événements dans la base réseau, Findings dans la vraie session : inchangé.
Whitelist, mode silencieux, baseline et règles de détection : inchangés.

## Processus, crash et plateformes

- **Linux** : `pidfd_open` épingle l'objet noyau ; comparaison de l'identité
  boot/start-time de `/proc` ; attente de terminaison via le descripteur pidfd.
  Python exposant `os.pidfd_open` et noyau compatible (Linux 5.3+) requis. Un refus
  de permission ou une API indisponible échoue, sans approximation par PID seul.
- **Windows** : handle `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION`, identité
  FILETIME de création complète (100 ns), attente `WaitForSingleObject`.
  `pywin32` est déjà déclaré pour Windows : aucune dépendance ajoutée.
- UUID d'instance et identité OS ont deux rôles différents : le premier lie le
  protocole à une exécution, la seconde protège contre la réutilisation du PID.
- Tous les descripteurs/handles de vérification sont fermés.
- Une instance morte sans acquittement propre produit un diagnostic d'état périmé
  et un code d'échec. B ne réécrit pas le réseau pour simuler un arrêt.
- Au prochain démarrage, sous verrou acquis, les anciennes lignes de contrôle
  `running` sont marquées `stale`. Cela ne répare pas rétroactivement l'ancienne
  session `running` après un crash : elle reste un témoin de sortie non finalisée.
- `status` conserve sa lecture historique des données ; ce n'est pas une preuve
  de vie OS. Pas de refonte visuelle dans cette mission.
- SIGKILL/crash ne permettent pas une finalisation applicative. SIGTERM ne fait
  pas partie du chemin coopératif ; utiliser la CLI d'arrêt ou Ctrl+C.

## Validation

`tests/sentinel_cli_child.py` est exclusivement un adaptateur de test : il appelle
la véritable application Typer, remplace les sondes/découverte/identité, interdit
les sockets et les sous-processus de scan, et utilise des barrières de fichiers.
Il n'existe aucun mode de simulation activable par environnement en production.

`tests/test_sentinel_lifecycle.py` lance de vrais processus A et B. Le test nominal
attend un cycle effectivement commencé, fait demander l'arrêt par B, constate que
B attend, libère le cycle simulé puis vérifie la sortie de A/B, la session, l'état,
le verrou, la baseline, les événements et les Findings, et redémarre sur ce réseau.
Un test retarde explicitement la sortie OS après acquittement/verrou libre : B ne
peut pas encore réussir. Aucun kill de l'orchestrateur dans le chemin nominal.
Le nettoyage forcé du fixture n'est qu'une récupération après test défaillant ;
un test de crash distinct tue volontairement A.

Les scénarios Windows sont présents dans le code portable et les contrats API sont
simulés sous Linux. **Une exécution native Windows reste nécessaire** pour valider
les ACL, le verrouillage et le comportement opérationnel des handles/Ctrl+C.


### Tests de revue : course admission / arrêt

Deux scénarios avec vrais processus CLI placent une barrière dans A exactement
avant ou après le commit d'admission, après que l'attente est revenue. B enregistre
sa demande, le test constate son commit, puis seulement libère A. Arrêt premier :
zéro cycle/événement/Finding. Admission première : exactement un cycle, puis fin.
Les délais servent uniquement de garde-fous d'échec, jamais à décider l'ordre.
Deux tests supplémentaires retiennent la première transaction avant son commit.
L'écriture concurrente utilise réellement SQLite, avec un busy timeout nul pour
ce test uniquement : elle doit produire SQLITE_BUSY avant toute libération de la
première transaction. Le test vérifie ce code natif, libère le premier commit,
puis réessaie la seconde opération et vérifie le résultat. Aucun ordre n'est
déduit d'un délai ou de la simple entrée dans la fonction de connexion.


### Diagnostics d'erreur et frontière CLI

Une exception inattendue du monitor conserve le passage par la finalisation
commune (`failed`) ; Ctrl+C reste `partial`. Le diagnostic du monitor et le champ
d'erreur de contrôle ne contiennent que le type d'exception et la catégorie
d'opération, jamais le message arbitraire de l'exception. La frontière CLI traite
l'échec avec un code 1 et un diagnostic concis, sans traceback ni affichage des
variables locales. Les échecs d'identification, d'attente et de fermeture des
handles Windows sont traduits en erreurs lifecycle explicites. Un refus d'accès
n'est jamais interprété comme la disparition du processus.

Les tests injectent des canaris dans les messages d'erreur fatale et des API
Windows : absence de canari et de traceback dans la CLI, absence de message
arbitraire dans le contrôle persisté. Le cas monitor fatal utilise de vrais
processus CLI avec contrôles simulés et vérifie aussi session `failed`, état
final, verrou libre et absence de succès d'arrêt côté B.

### Échec de préparation avant propriétaire enregistré

La finalisation commune englobe aussi `init_sentinel_db` et la construction du
propriétaire. Le propriétaire est optionnel tant que sa construction n'a pas
réussi. Sous le verrou réseau déjà acquis, une préparation échouée sans ce
propriétaire tente seulement un UPDATE d'un état réseau existant vers `inactive`.
Cette réconciliation ouvre uniquement une base existante en mode `rw` : aucune
création de base, table, ligne d'état ni acquittement. Les événements, assets et
sessions existantes sont conservés. Un état inactif ainsi réconcilié n'est pas une
preuve de terminaison OS.

Sans propriétaire construit, aucun appel à `finish` ni résultat `completed` n'est
émis, même si le constructeur a enregistré une ligne avant de lever une exception
(retour incertain). Cette ligne reste non acquittée. La réservation vide de la
nouvelle session et le verrou sont libérés. Si la base est inaccessible/corrompue
ou si la réconciliation échoue, l'erreur de nettoyage est diagnostiquée uniquement
par sa catégorie et son type ; l'exception initiale reste celle propagée vers la
frontière CLI. Aucun message sensible ni faux succès n'est produit.

### Ctrl+C avant création confirmée de session

L'interruption n'est absorbée en `partial` qu'après le retour réussi de
`save_session`. Avant cette confirmation (initialisation réseau, constructeur du
propriétaire ou préparation de session), le `KeyboardInterrupt` initial est
propagé après la finalisation/nettoyage. La CLI le traduit en code **130**, avec
un diagnostic fixe de démarrage interrompu, sans traceback ni contenu arbitraire
de l'exception. Une erreur de réconciliation ne remplace pas cette interruption.

Sans propriétaire disponible : réconciliation prudente uniquement, aucun
acquittement. Avec propriétaire enregistré mais sans session confirmée : résultat
`failed` (ou `finalization_failed` si l'écriture finale échoue), jamais `completed`.
Une réservation vide est retirée ; un fichier déjà peuplé reste conservé selon
la règle de sécurité existante. Pendant la surveillance, Ctrl+C continue de
clôturer la vraie session en `partial` via la finalisation commune.

### Écriture de session réussie, retour interrompu

Après un échec avant confirmation de `save_session`, la finalisation examine
uniquement le fichier réservé exclusivement par cette tentative. Une opération
DB dédiée ouvre ce fichier existant en mode `rw`, sans initialisation de schéma,
et clôture en `failed` avec `end_time` uniquement une ligne dont l'ID correspond
exactement à la réservation. Un commit réussi suivi de `KeyboardInterrupt` ne
laisse donc plus cette session en `running` si la clôture est possible.

Si aucune ligne valide ne correspond, aucune session n'est créée. Les fichiers
non vides ou incertains restent conservés. Si cette vérification/clôture échoue,
l'erreur est signalée par son type et sa catégorie, le contrôle propriétaire
reçoit `finalization_failed` si possible, et l'interruption initiale reste
propagée : code CLI 130, sans traceback ni message arbitraire. Une session dont
la clôture est impossible peut rester `running` : le diagnostic ne prétend pas
qu'elle a été clôturée. Après clôture réussie du retour incertain, le contrôle
reste `failed`, jamais `completed`. Ctrl+C pendant la surveillance confirmée
conserve la clôture en `partial`.
