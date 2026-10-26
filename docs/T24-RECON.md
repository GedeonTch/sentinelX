# T24 — Reconnaissance passive, DNS et enregistrement de domaine

Ce document décrit le comportement implémenté par le ticket T24 : filtre réseau,
sources de `passive-recon`, DNS, RDAP/WHOIS (`netlab whois`) et `doctor`.
Il ne couvre ni `scan`, ni le pipeline, ni le scoring.

## Périmètre et principes

- Les commandes `netlab whois` et `netlab passive-recon` sont **autonomes** : `netlab scan`
  et le pipeline ne les appellent pas.
- Aucune commande T24 ne fait de scan actif de la cible.
- Les Findings produits restent des observations d'information (`severity=INFO`). Ils ne
  changent pas le scoring existant.
- Aucune donnée brute (réponse DNS complète, JSON RDAP, texte WHOIS) n'est affichée,
  persistée ni retournée. Les parseurs la lisent puis la jettent.

## `netlab passive-recon`

Usage : `netlab passive-recon [--network <filtre>]`

### Filtre réseau

| Valeur | Sens |
|---|---|
| vide | toutes les entrées IPv4 |
| `192.168.1.0/24` | CIDR IPv4 (les bits d'hôte doivent être nuls) |
| `192.168.1.50` | une seule adresse |
| `192.168.1` | ancien préfixe, équivalent à `192.168.1.0/24` |

Les valeurs invalides sont rejetées avant toute commande (`exit 2`). Le filtre est
évalué avec `ipaddress` : `192.168.1` n'accepte plus `192.168.10.5`.
Les adresses IPv6 ne sont jamais des cibles : elles sont comptées (« IPv6 ignorées »)
et aucun scan IPv6 n'est fait.

### Sources

| Source | Commande ou fichier | Remarque |
|---|---|---|
| ARP / voisinage | `arp -n`, sinon `ip -4 neigh show` | Une entrée de cache prouve une observation passée, pas la présence actuelle. Confiance `PROBABLE`. |
| `/etc/hosts` | lecture seule | Une ligne par couple (IP, premier nom). Les IP répétées sont conservées. Loopback exclu. |
| mDNS | `avahi-browse --all --resolve --terminate --parsable --no-db-lookup` | Envoie des requêtes multicast sur le réseau local. **Lancé seulement après confirmation.** |

#### mDNS et confirmation

1. La commande affiche un avertissement : mDNS envoie des requêtes sur le LAN.
2. Elle demande une confirmation, dont le défaut est **non**.
3. Sans terminal interactif, mDNS n'est pas lancé.
4. Un refus, une absence de terminal ou une interruption (Ctrl+C) ne lancent pas `avahi-browse`.
   Le résumé indique « ignoré (non confirmé) » ; il ne présente pas une liste vide.

Format attendu par avahi (mode `--parsable`) :
`=;interface;protocole;nom_service;type_service;domaine;nom_hôte;adresse;port;txt`.
Seules les lignes `=` (résolues) sont retenues. Les noms de service sont décodés
(`\DDD`, décimal). Les IPv6 sont comptées et ignorées. Plusieurs services par hôte sont
regroupés dans un seul Finding ; plusieurs adresses pour un même hôte donnent un Finding
par adresse. Confiance `POSSIBLE` (annonce non vérifiée, exclue du score).

### Statuts par source

Chaque source affiche un statut distinct : `effectué`, `indisponible (outil ou fichier absent)`,
`échec ou timeout`, `ignoré (non confirmé)`. Une absence d'outil n'est jamais affichée
comme une liste vide. Par exemple, `avahi-browse` absent se lit « indisponible ».

## `netlab whois <domaine ou IPv4>`

### IPv4

Enregistrement PTR, puis confirmation directe (résolution inverse) lorsque le nom
résout vers la même adresse (`CONFIRMED`), sinon `PROBABLE`.

### Domaine : enregistrements DNS

Types interrogés : A, MX, NS, TXT, CNAME, avec un PTR pour chaque adresse A (au plus 8).

| Issue | Statut affiché | Finding ? |
|---|---|---|
| réponse | `réponse reçue` | oui, une par type |
| NXDOMAIN | nom inexistant selon le résolveur | non |
| NoAnswer | aucune donnée pour ce type | non |
| timeout | timeout (inconnu, pas inexistant) | non |
| résolveur indisponible | résolveur ou serveur indisponible | non |
| autre erreur | erreur DNS | non |

- **Confiance** : `CONFIRMED` seulement si la réponse porte le drapeau **AA** (autoritative).
  Sinon `PROBABLE`. L'évidence indique « autoritative (AA) » ou « non autoritative ».
- Toutes les adresses A sont conservées ; les doublons ne sont comptés qu'une fois.
- Les valeurs MX, NS, TXT et CNAME sont conservées (point final retiré des noms).
- Une absence de réponse ou un timeout n'est **jamais** présenté comme une preuve d'inexistence.

### Domaine : enregistrement (RDAP + WHOIS)

Les deux sources sont interrogées séparément, avec leur propre statut.

**RDAP (principal)**
- Service trouvé dans le bootstrap IANA `https://data.iana.org/rdap/dns.json` (RFC 9224),
  mis en cache en mémoire (durée `max-age`, bornée entre 1 h et 7 jours, 24 h par défaut).
  Aucune table de TLD n'est codée en dur.
- HTTPS uniquement, y compris pour les redirections (maximum 3). Un TLD dont le service
  n'est déclaré qu'en HTTP est refusé (`service RDAP non HTTPS, refusé`).
- Délai de 10 s par opération réseau (il ne borne pas le total d'une requête à plusieurs redirections), taille de réponse bornée à 512 KiB.
- Statuts : `OK`, `domaine introuvable selon le serveur compétent`, `TLD sans service RDAP déclaré`,
  `limitation de débit (429)`, `service indisponible`, `annuaire RDAP indisponible`, `timeout`,
  `réponse mal formée`, `erreur`.

**WHOIS (complément)**
- `python-whois` avec `inc_raw=True` et `timeout=10`.
- Statuts : `OK`, `domaine introuvable`, `TLD non géré par WHOIS`, `limitation de débit`,
  `timeout`, `réponse mal formée`, `aucune donnée exploitable`, `erreur`.

**Fusion champ par champ**
- RDAP est prioritaire. WHOIS complète les champs manquants.
- Une contradiction est affichée avec sa provenance (« RDAP « X » ≠ WHOIS « Y » »).
- Un champ masqué par le registre (RFC 9537, `redacted`) s'affiche « Masqué par le registre »
  et **n'est jamais complété par WHOIS**.
- Absence de valeur ≠ masquage : une absence s'affiche « Non communiqué » si au moins une
  source a répondu, « Source en timeout » si toutes les sources ont expiré, « Non disponible » sinon.
- Une réponse RDAP « introuvable » n'est pas remplacée silencieusement : la divergence est
  affichée, et les valeurs WHOIS portent la mention « à confirmer ».
- Dates, statuts et serveurs de noms sont dédoublonnés entre les sources.
- Les contacts (titulaire, administratif, technique, facturation, abus) sont décrits dans
  la section « Contacts et identifiants (T26) » ci-dessous.

**Contacts et identifiants (T26)**
- Données publiques du WHOIS et du RDAP, affichées par `whois` : nom, organisation, adresse
  (rue, ville, état, code postal, pays), téléphone, fax, e-mail, identifiant de contact.
  Pas de masquage ni d'anonymisation supplémentaire : le registre publie ces données.
- WHOIS : les champs sont lus dans le texte brut, avant sa suppression. Le texte brut
  n'est ni conservé ni affiché.
- RDAP : contacts des rôles `registrant`, `administrative`, `technical`, `billing`, `abuse`
  (vCard `fn`, `org`, `adr`, `tel`, `email`, `handle`). Un rôle masqué par RFC 9537 s'affiche
  « Masqué par le registre » et **n'est jamais complété par WHOIS**.
- Fusion : RDAP d'abord, WHOIS complète champ par champ. Les écarts de contacts ne sont pas
  listés comme divergences, pour que les données personnelles n'entrent pas dans la preuve
  des Findings.
- Libellés d'un champ de contact : valeur ; `Masqué par le registre` ;
  `Absent du WHOIS` ou `Absent du RDAP` (une source a répondu sans ce champ) ; `non fourni par …`
  (une source n'a pas répondu) ; `Source en timeout` si aucune source n'a répondu.
- Identifiants du registre : `Identifiant du domaine (registre)` et `Serveur WHOIS du registre`.
- Affichage seulement, sans Finding : compte à rebours d'expiration (« dans N jour(s) »), ligne
  d'information si l'expiration est dans moins de 180 jours ou dépassée, et écart entre les
  serveurs de noms du DNS et ceux du registre (« à vérifier »).
- Les contacts n'entrent ni dans `registration_evidence`, ni dans un Finding, ni dans une
  sauvegarde : `whois` ne persiste rien.

**Confiance du Finding d'enregistrement** : `CONFIRMED` si RDAP a répondu, `PROBABLE` si
seul WHOIS a fourni des données.

### Affichage

Le domaine est affiché en tête. Les tableaux DNS et d'enregistrement sont compacts, avec
les libellés stables ci-dessus. Aucune donnée JSON ou WHOIS brute n'est affichée.
Le domaine n'est jamais placé dans `target_ip` des Findings.

## Exposition des Findings

L'énumération de DNS et d'enregistrements n'observe aucun service. Aucun Finding T24 n'est
marqué `EXTERNAL`, car l'exposition publique n'est pas démontrée. La valeur reste celle
qui existe déjà (`INTERNAL`), faute d'une valeur « inconnue » dans le contrat `Exposure`.
**Décision à prendre** : ajouter une valeur `UNKNOWN` (changement de contrat, non fait ici).

## `netlab doctor`

`arp`, `ip` et `avahi-browse` sont vérifiés comme outils **optionnels** : une absence
n'échoue pas le diagnostic. Le tableau indique l'effet d'une absence :
- `arp` : voisinage ARP via `arp -n` ; repli sur `ip neigh` ;
- `ip` : repli ARP si `arp` est absent ;
- `avahi-browse` : mDNS indisponible pour `passive-recon` (affiché comme indisponible, pas vide).

## Limites connues

- Le trafic réel d'`avahi-browse` et son option `--cache` ne sont pas mesurés ici.
- Le WHOIS réel et le RDAP réel ne sont pas testés (aucun appel réseau dans les tests ; les
  réponses sont des fakes).
- La confirmation directe PTR (`socket.getaddrinfo`) n'a pas de délai explicite.
- Le comportement ARP sur des systèmes sans `arp` ni `ip` n'est pas validé.
- Windows n'est pas validé pour avahi ni pour ARP.
- Les règles de `knowledge/vulnerabilities.json` pour `dns_enum` et `passive_recon` sont
  inchangées, sauf les deux phrases de `passive_recon` qui affirmaient « aucun paquet ».

## Tests

- `tests/test_passive_recon.py` : filtre réseau, ARP et repli `ip neigh`, `/etc/hosts`,
  avahi (ordre des champs, regroupement, IPv6), consentement mDNS et statuts.
- `tests/test_dns_enum.py` : statuts DNS, AA, valeurs conservées, PTR, cible du Finding.
- `tests/test_rdap.py` : bootstrap HTTPS, cache, statuts, parsing RFC 9083, masquage RFC 9537.
- `tests/test_registration.py` : fusion champ par champ, masquage, divergences, WHOIS.
- `tests/test_whois_enrichment.py` : contacts WHOIS et RDAP (fictifs), fusion par rôle, libellés,
  écart NS, expiration, preuve sans contact, rendu CLI.
- `tests/test_t24_recon_cli.py` : rendu réel de `whois`, `passive-recon` et `doctor`.

Aucun test n'utilise le réseau, `/etc/hosts` réel, ni `avahi-browse` réel.
La démonstration des défauts corrigés (9 cas : filtre, avahi, `/etc/hosts`, timeout/NXDOMAIN,
AA, WHOIS `inc_raw`, repli ARP, commande `passive-recon`, avahi absent) a été faite par un
sondage exécuté sur `6ad9a86` puis sur l'arbre T24 ; il n'est pas inclus dans le dépôt.
