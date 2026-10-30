# Consultation dédiée des Findings Sentinel

## Installer la commande autonome

Depuis la racine du projet, dans l'environnement Python destiné à SentinelX :

```sh
python -m pip install .
sentinel --help
sentinel findings show <UUID_COMPLET> -s <SESSION_SENTINEL>
```

L'installation enregistre `sentinel` dans le dossier des exécutables de cet
environnement (`bin` sous Linux, `Scripts` sous Windows). Activer l'environnement
ou utiliser le chemin complet. Aucun alias et aucun préfixe `netlab` nécessaires.
Le groupe Sentinel existant est réutilisé, sans refonte du CLI général.

## Monitor

La session réellement utilisée figure dans l'en-tête et dans la commande du pied.
Chaque alerte émise porte un UUID complet et une sévérité, sans commande par alerte.
En TTY, elle est imprimée une seule fois au-dessus du cadre Live, à son émission ;
le cadre ne contient ni liste ni UUID. Il reste borné à la hauteur du terminal
(une ligne libre) ; si tous les hôtes ne tiennent pas, le nombre d'hôtes non
affichés est indiqué. Un seul pied appartient au cadre courant : les
rafraîchissements le redessinent sur place, ils ne constituent pas de nouvelles
instructions. En non-TTY, l'en-tête et le tableau des hôtes sont émis une fois au
démarrage, chaque alerte une fois, et le pied une fois à la fermeture, y compris
Ctrl+C traité proprement. Une terminaison forcée ne garantit pas cette finalisation.
Après chaque contrôle terminé, une ligne de progression (`[HH:MM:SS] Contrôle terminé — …`)
indique le nombre de notifications affichées pendant ce contrôle ; un contrôle partiel ou en échec
n'est jamais annoncé comme terminé avec succès. Cette ligne n'existe qu'en non-TTY.

Les UUID sont affichés hors des bordures des tableaux, sans ellipsis ni perte de
caractère. En dessous de 36 colonnes, un UUID doit se replier sur plusieurs lignes ;
élargir le terminal à au moins 36 colonnes facilite sa copie en une ligne. Le pied
peut aussi se replier selon la largeur et la longueur de la session.
Les notifications masquées ne révèlent ni UUID ni détail dans cette liste.

## Contrat de consultation

- UUID canonique complet obligatoire ; ni préfixe nu ni FD abrégé.
- Recherche exacte dans la session explicite, jamais par hôte/type/date.
- Profil `sentinel`, fiche cohérente et Findings uniquement `sentinel.*` requis.
- Refus d'un contexte scan, mixte détectable, inconnu ou illisible. Des résultats
  `scan_outcomes` non vides entraînent également un refus.
- Lecture SQLite `mode=ro`, `query_only`, snapshot transactionnel ; aucun DDL,
  aucune migration, initialisation, récupération de notification ou mutation métier.
- Une session inconnue ne crée aucun dossier ni DB. Pour une DB connue en WAL,
  SQLite peut créer/utiliser les fichiers techniques `-wal`/`-shm` de coordination ;
  cela ne constitue pas une écriture de Findings/événements ou une migration.
- Si tous les marqueurs historiques ont disparu, leur provenance ne peut pas être
  reconstituée. Cette commande ne remplace pas le futur ticket d'isolation générale.

Les commandes ordinaires de scan/VERIFY/cleanup et le protocole lifecycle restent
inchangés. La consultation ne lit pas les événements réseau comme des Findings.
La validation Windows native de cette livraison n'a pas été effectuée.

## Tests d'acceptation

Installer d'abord le point d'entrée ; la suite lance réellement `sentinel` depuis
un répertoire temporaire, sur des DB temporaires. Si l'exécutable n'est pas dans
PATH, préciser `SENTINEL_TEST_EXECUTABLE` (chemin absolu).
