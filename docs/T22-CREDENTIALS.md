# T22 — Fondations du dictionnaire, coffre et FTP/SNMP

Ce lot ne rend pas T22 terminé. SSH, Telnet, HTTP(S), SMB et RDP ne sont pas
activés. Aucun test automatique n'effectue de connexion à une cible réelle.

## Commande historique et autorisation

```
netlab creds_check --target 192.0.2.10
netlab creds_check -t 192.0.2.10 --dict "mes dictionnaires/labo.txt"
netlab creds_check -t 192.0.2.10 --service ftp --dict labo.txt
netlab creds_check -t 192.0.2.10 --service snmp --profile cisco-wlc-7.4
```

Une seule IPv4 explicite, ports FTP 21/TCP et SNMP 161/UDP. Pas de résolution DNS,
CIDR, redirection ou cible fournie par le dictionnaire. Sans `--service`, FTP et
SNMP sont sélectionnés. L'option est répétable et remplace cette sélection.
Chaque service testable demande sa propre confirmation. Aucun `--yes` ajouté.
La commande reste autonome : les Findings ne sont pas enregistrés dans SQLite.
Seuls les succès d'authentification sont conservés dans un coffre séparé.

## Dictionnaire personnalisé

`--dict` remplace entièrement la base intégrée. JSON Lines UTF-8 : un objet JSON
par ligne, champs textuels `service`, `username`, `password`, ou `service`,
`community` pour SNMP. `domain` est réservé aux formats SMB/RDP (non activés).
Les noms de service connus mais non sélectionnés ne déclenchent aucun réseau.

Exemple **synthétique**, pas un identifiant réel :

```json
{"service":"ftp","username":"compte de test","password":"valeur fictive : avec ; et \"guillemets\""}
{"service":"snmp","community":"communaute fictive"}
```

Les espaces dans les valeurs sont conservés. Pas de normalisation Unicode, de
variables ou de variantes générées. UTF-8 BOM initial, LF/CRLF et lignes blanches
sont acceptés. Pas de commentaires. Champs inconnus, clés dupliquées et mélange
de schémas sont rejetés. Aucun host/port/profil/budget dans le fichier.

Plafonds : 1 MiB, 16 KiB par ligne, 500 entrées avant déduplication, 256 octets par
identifiant/domaine, 1024 par mot de passe. Dans ce premier lot FTP accepte ASCII
sans contrôles ; SNMP exige 1 à 64 caractères ASCII imprimables. Aucun encodage
avec remplacement. Le fichier entier est validé avant l'ouverture du coffre et
avant le réseau. Les erreurs indiquent un numéro de ligne, jamais son contenu.

Sans candidat pour un service **implicite**, ce service est ignoré avec un motif.
Sans candidat pour un service **explicite**, toute la préparation échoue. Sans
aucun service testable, aucune initialisation ou tentative n'est effectuée.
Le fichier source reste sensible en clair : SentinelX ne le copie, ne le modifie
ni ne l'efface. Le protéger et gérer sa rétention appartient à son propriétaire.

## Catalogue, provenance et qualification

`knowledge/default_credentials.json`, version **2026-10-10.2**, contient
**9 profils, 19 entrées et 14 combinaisons uniques** (8 FTP, 6 SNMP), contre
5 combinaisons uniques dans la première livraison. Aucun import de wordlist.
Les champs `product_family`, `versions`, `limits`, `source` et, si nécessaire,
`corroborating_sources` précisent la portée documentaire de chaque profil.

Le profil implicite `legacy` reste exactement les cinq candidats historiques,
sans fusion avec les nouveaux profils. Leur provenance produit n'est pas établie :
un succès réellement confirmé est conservé sans Finding automatique. L'alias FTP
historique est toujours essayé, mais son acceptation ambiguë n'est plus un succès
conservable (règle ci-dessous).

| Profil explicite | Portée documentaire et limite principale |
|---|---|
| `cisco-wlc-7.4` | Cisco WLC logiciel 7.4, « SNMP Community Strings », p. 2 ; GET uniquement, aucun droit d'écriture inféré. |
| `tp-link-td-w8990-guide` | Exemple TD-W8990 identifié dans l'Overview, LAN Access/Super User ; ne pas extrapoler depuis le nom TD-W8968 V4 de l'URL. Firmware non précisé. |
| `schneider-ion-standard-security` | ION 7550/7650, FA272266, Resolution / Standard Security ; exclut Advanced Security, mot de passe de façade inchangé. Firmware non précisé. |
| `quest-kace-sma-13-14` | KACE Systems Management Appliance, KB 4377346, Resolution / Applies to ; uniquement les treize versions 13.1–14.1 explicitement énumérées dans le catalogue. |
| `axis-2401-upgrade-2.20` | AXIS 2401, notes 2.20 Build 9 du 17/08/2001, instructions 2.20:1 §3 et 2.20:2 §2 ; anciens produits seulement, aucune opération de mise à jour exécutée. |
| `carel-pcoweb-web-files` | pCOWeb PCO1**0WB0 / PCO10*0W*0, fiche +050003238, révision liée 1.2 ; login FTP web-administrateur explicite. Pas d'autre compte ajouté : notamment divergence du tableau root entre traductions. Firmware non précisé. |
| `apc-nmc2-ftp` | NMC2 AP9630/AP9631/AP9635, FA156047, Manual (via FTP) / NMC2, étapes 1–4 ; FTP déjà activé, restrictions particulières AP9635 à vérifier, aucune extension NMC3/NMC4. |
| `brocade-fos-legacy-snmp` | **Non qualifiant** : six communautés documentées, mais portée des défauts contradictoire entre Web Tools 9.2.x et Command Reference. Aucune assertion de défaut usine sur une installation 9.x neuve ni d'historique de mise à niveau vérifié. |

Références fabricant consultées le 10 octobre 2026, avec sections et limites
également enregistrées dans le catalogue :

- Cisco : https://www.cisco.com/en/US/docs/wireless/controller/7.4/configuration/guides/system_management/config_system_management_chapter_0111.pdf
- TP-Link : https://static.tp-link.com/res/down/doc/TD-W8968_V4_FTP_Server_Application_Guide.pdf
- Schneider ION : https://www.se.com/us/en/faqs/FA272266/
- Quest : https://support.quest.com/kace-systems-management-appliance/kb/4377346/what-is-the-default-ftp-user-account-and-password
- AXIS : https://ftp.axis.com/pub_soft/cam_srv/cam_2401/2_20/2401_220.txt
- CAREL : https://www.carel.com/documents/10191/0/+050003238/e0830e90-2704-40bd-a063-92217ada0201?version=1.2
- APC : https://www.se.com/us/en/faqs/FA156047/
- Brocade Web Tools : https://techdocs.broadcom.com/us/en/fibre-channel-networking/fabric-os/fabric-os-web-tools/9-2-x/v26882500/v26815803/v26850344.html
- Brocade Command Reference : https://techdocs.broadcom.com/us/en/fibre-channel-networking/fabric-os/fabric-os-commands/9-2-x/Fabric-OS-Commands/snmpConfig_922.html

Le guide Web Tools présente six valeurs par défaut, alors que Command Reference
indique l'absence de communautés par défaut en 9.x et la reprise des comptes lors
d'une mise à niveau depuis 8.2.x. Les documents divergent aussi sur le retrait ou
la dépréciation de SNMPv1 à partir de 9.2.2. Faute de portée univoque, le profil
Brocade reste `unverified` : une acceptation protocolaire peut être conservée,
mais **ne produit pas de Finding de défaut**. Six candidats ne signifient pas six
essais : le plafond reste trois, les candidats restants sont comptés non testés.

La sélection explicite d'un profil engage l'opérateur à vérifier son applicabilité
au produit autorisé ; elle ne constitue pas une détection automatique. Aucun
fingerprint ni réseau documentaire supplémentaire. `--dict` et `--profile` sont
incompatibles. Un succès personnalisé n'est jamais automatiquement HIGH.

Un profil intégré vérifié et applicable peut produire au maximum un Finding par
service. Sa preuve assainie contient `provenance` : profil, version du catalogue,
URL et section documentaire, dédupliqués au niveau profil. Aucun nom d'utilisateur,
mot de passe, communauté, ID de coffre, index/ID/hash de candidat ou transcript.
Ces références désignent des documents publics et non l'enregistrement secret ;
elles ne promettent pas de cacher les valeurs par défaut publiées par le fabricant.
Un simple booléen `qualified` sans provenance ne suffit plus. Le dictionnaire
personnalisé ne peut fournir ni provenance ni qualification. Le modèle Finding,
le scoring et VERIFY sont inchangés.

## Budgets et preuves

Séquentiel : 3 tentatives/service, 2/compte/exécution, 10 globalement. Les budgets
FTP groupent conservativement les variantes de casse pour ne pas permettre leur
contournement ; les valeurs réellement envoyées et stockées ne sont pas modifiées.
Pour SNMP : une tentative par communauté/endpoint. Deux secondes entre départs,
10 secondes maximum par tentative FTP, 30 par service, opérations au plus 5 s.
Pas de retries cachés. Le lecteur FTP impose une échéance même sur flux lent.
Une authentification réussie est enregistrée immédiatement, puis les autres
candidats de cette identité sont ignorés. La même clé conservatrice `casefold`
est utilisée pour le budget et cet arrêt : après succès de `User`, `user` n'est
plus essayé. Le coffre conserve exactement `User` et le secret reçu ; sa clé de
déduplication reste exacte. Les communautés SNMP restent sensibles à la casse.
D'autres identités peuvent être testées.
Les candidats restants sont comptés sans être conservés.

Une erreur technique grave arrête le service. Un signal de verrouillage dont le
périmètre est incertain ou une erreur de conservation arrête toute l'exécution.
Même une seule tentative peut verrouiller un compte proche de son seuil.
Les erreurs inattendues de backend deviennent une erreur technique explicitement
identifiée, jamais NO_MATCH ; aucune exception contenant des secrets n'est imprimée.

FTP : un rejet d'authentification n'est pas un rejet de connexion. Pas d'ACCT
automatique, aucun fichier distant lu/écrit et aucun essai de contrôle négatif
supplémentaire. Trois issues d'acceptation sont distinguées :

- `SUCCESS / AUTHENTICATED` : échange USER 331 puis PASS 230 conforme pour un
  compte non alias, sans indication Guest/anonymous dans ces réponses. Il s'agit
  d'une preuve protocolaire, pas d'une attestation cryptographique du serveur.
- `ANONYMOUS_ACCESS` : réponse d'acceptation avec indication explicite
  Guest/anonymous, y compris indication au USER 331 suivie d'un PASS 230 générique.
  Ce n'est ni un couple confirmé ni un défaut qualifié ; aucune conservation.
- `INCONCLUSIVE` : acceptation sur USER seul sans qualification identifiable, ou
  PASS 230 pour un alias `ftp`, `anonymous`, `guest`, `ftp-anonymous` sans preuve
  de vérification du mot de passe. La détection d'alias est conservatrice sur la
  casse et les espaces périphériques, sans modifier les octets envoyés/stockés.
  Aucune conservation et aucun Finding, même avec profil qualifiant.

**Changement historique :** `ftp/ftp` reste dans `legacy` et continue d'être
sondé sous le même budget. Même un échange « 331 Password required / 230 Login
successful » ne suffit plus à le conserver : l'absence des mots Guest/anonymous
ne prouve pas que son mot de passe a été vérifié. L'alias `ftp` est notamment
documenté pour l'authentification anonyme IIS :
https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/ftpserver/security/authentication/
Un serveur trompeur ou un mapping anonyme non identifiable reste une limite de
l'observation protocolaire ; validation labo requise, pas d'affirmation que cette
sonde prouve le contrôle interne du mot de passe sur tout serveur.

SNMPv1 : GET sysDescr uniquement. Source/port, BER borné, version, GetResponse,
request-id aléatoire, communauté et OID sont vérifiés. Au plus 16 datagrammes et
5 secondes, pas de retransmission. Lecture réussie = READ_OK. Réponse noSuchName
corrélée/conforme = OID_UNAVAILABLE : acceptation protocolaire, pas lecture réussie.
Les autres erreurs structurées sont indicatives/inconclusives, pas conservées
comme succès. Paquets malformés/non corrélés : jamais SUCCESS ou NO_MATCH ; attente
bornée d'un paquet admissible, sinon INCONCLUSIVE. Silence = TIMEOUT.
SNMPv1 n'offre aucune preuve cryptographique contre la falsification. Aucun droit
d'écriture n'est inféré. La documentation d'un défaut RW ne constitue pas un test RW.

## Coffre local

Emplacement : `~/.netlab/credentials/vault.enc`, distinct des sessions. Terminal
interactif privé requis, sans interface graphique. Première utilisation : accord
de création, phrase saisie deux fois sans écho (20-1024 caractères, diversité
minimale), puis test effectif chiffrer/écrire/relire un marqueur synthétique et le
retirer. La longueur/diversité ne garantissent pas l'entropie : choisir une longue
phrase aléatoire. Aucun secret maître en argument, environnement ou configuration.

AES-256-GCM, clé de données aléatoire, clé enveloppée par une clé dérivée avec
scrypt N=131072, r=8, p=1 (environ 128 MiB). Format versionné, nonces aléatoires,
paramètres bornés et contenu authentifié. Pas de dégradation automatique du KDF.
Fichier borné à 16 MiB ; ce coffre réécrit intégralement est destiné aux petits
laboratoires, pas à un inventaire massif.

Verrou exclusif pendant l'exécution (une autre commande doit attendre la fin ou
réessayer). Fichiers temporaires déjà chiffrés dans le même répertoire, remplacement
atomique, flush/fsync, relecture après écriture. Linux : propriétaire courant,
répertoire 0700, fichiers 0600, liens refusés. Windows : DACL protégée utilisateur
courant + SYSTEM via pywin32, reparse points refusés. Pas de réparation automatique
des permissions d'un coffre existant. **Windows n'est pas pris en charge
opérationnellement tant que des essais Windows réels n'ont pas été validés**,
notamment ACL, remplacement atomique, concurrence et restauration. Les tests ACL
Win32 simulés sont des tests de logique, pas une validation de la plateforme.

La clé de rapprochement est **dans le coffre déverrouillé** : service, endpoint,
contexte, utilisateur, domaine, type et secret exact. Deux utilisateurs avec le
même mot de passe sont distincts. Même combinaison : même ID opaque, dernière
date mise à jour. Un autre secret ou contexte reste distinct. Aucun index externe.

Une mauvaise phrase et une altération authentifiée ne sont pas toujours
distinguables : refus sans remplacement. Absent, droits non privés et verrou
concurrent ont des diagnostics distincts. Échec du contrôle d'écriture : zéro
réseau. Après acceptation protocolaire :

- `save_failures` : échec certain **avant** la frontière de remplacement (par
  exemple chiffrement, écriture ou fsync du temporaire). Le dernier succès n'est
  pas acquitté comme conservé ; arrêt de tous les essais.
- `save_uncertain` : le remplacement a été engagé et l'acquittement, le fsync du
  répertoire ou la relecture échoue. L'exception `VaultWriteUncertain` reste
  distincte jusqu'au bilan. Même une exception levée par l'appel de remplacement
  est classée prudemment incertaine : celui-ci peut avoir remplacé puis échoué à
  acquitter. Une exception non classifiée d'un autre sink est aussi incertaine.
  Arrêt de tous les essais, coffre non prêt, message demandant sa consultation
  avant toute nouvelle tentative ; la dernière entrée peut déjà exister.

`created`, `updated` et `stored` comptent seulement les écritures acquittées, pas
les issues incertaines. L'acceptation distante reste distincte de la conservation
locale. Aucun secret de secours, aucune nouvelle tentative automatique et aucun
rollback supposé. Une interruption pendant la phase incertaine est comptée et
arrête l'exécution. Échec incertain du précontrôle : aucun réseau. Les temporaires
sont chiffrés ; un échec de leur nettoyage ne remplace pas le diagnostic principal
et peut laisser un temporaire chiffré à traiter hors exécution.

Consulter le coffre après rétablissement de l'accès ; une relecture réussie lors
d'un test ne simule pas une coupure de courant. La durabilité de la dernière
écriture n'est pas garantie si le fsync échoue. Aucun stockage atomique distribué
entre serveur distant et disque n'est possible ; une panne entre acceptation et
écriture peut perdre un succès.

```
netlab creds list
netlab creds show <id>
```

`list` révèle seulement ID/service/endpoint/type/dates. `show` demande une
confirmation, révèle un seul enregistrement et échappe les contrôles. Pas de
presse-papiers ou export automatique. Sortie redirigée refusée. L'historique du
terminal/captures peut conserver le secret après révélation autorisée.

Sauvegarde minimale : **commande arrêtée**, copier uniquement `vault.enc` vers un
support privé. Restauration explicite du fichier chiffré avec permissions privées,
puis vérifier avec `creds list/show`. Ne jamais copier de version déchiffrée.
Aucun outil de sauvegarde, rotation de phrase, suppression/historique ni clé de
récupération n'est introduit dans ce premier lot. Phrase perdue = perte des
secrets. Les anciennes sauvegardes restent sensibles et peuvent réintroduire des
secrets retirés. L'effacement physique sur SSD et la détection de rollback ne sont
pas garantis. Un administrateur/malware ou dump mémoire peut accéder aux secrets
pendant le déverrouillage ; Python ne garantit pas leur effacement mémoire.

## Validation et limites

Tests automatisés : transports simulés, fichiers et SQLite temporaires, vraie
cryptographie, subprocess de récupération sans réseau. Aucun secret synthétique
ne doit apparaître dans Findings, DB de session, logs ou exports HTML/JSON. Seul
`show` explicitement autorisé doit révéler une valeur.

À valider séparément : serveur FTP réel (refus aux différentes phases, Guest,
verrouillage, flux lent), agents SNMPv1 (noSuchName, erreurs, réponses tardives),
Windows non administrateur (ACL, deux processus, restauration), Linux terminal
headless. Ces validations labo ne sont pas exécutées par les tests unitaires.

T22 n'est pas terminé. Les nouveaux protocoles, la maintenance avancée du coffre
et les enrichissements supplémentaires du catalogue attendent la revue de ce lot.
