# Sécurité des applications web (Node.js / React)

## Introduction

Ce document a pour objectif de donner une introduction aux problématiques de sécurité des applications web.

Le sujet étant très vaste, il est difficile, voire impossible, de le couvrir de façon complète. On a donc cherché à trouver un compromis : certains points seront abordés en détail, notamment au travers de vidéos. Pour les autres, des pistes de recherche seront données.

Une petite mise en garde s'impose avant de poursuivre.

> Malgré le travail de recherche nécessaire à la rédaction de ce guide, il est intrinsèquement limité aux connaissances glanées par son rédacteur au fil des années. Accordez-lui une confiance _relative_ !

Autrement dit : si les risques de sécurité documentés ici sont réels, les parades présentées ne sont pas absolues. Un travail de recherche complémentaire peut s'avérer nécessaire, notamment du fait de l'[obsolescence de la connaissance](https://www.wrike.com/fr/blog/le-savoir-devient-obsolete-voici-comment-votre-entreprise-peut-suivre-le-rythme/), inévitable en informatique !

Cette mise en garde m'a été inspirée par une phrase trouvée dans un article de blog traitant de l'authentification :

> If you’re a beginner, don’t trust your tutorials.

Quelques avertissements seront donnés en cours de route, sur la pertinence (ou non) de copier-coller le code depuis des tutoriels, voire depuis la documentation officielle de certaines bibliothèques.

### Structure

Ce guide est constitué de grandes parties :

1. La sécurisation des applications elles-mêmes : que ce soit du côté du serveur (applications Node.js / Express), ou du côté du client (React)
2. La sécurisation des serveurs sur lesquels sont déployées les applications.

### Sources

La source de référence concernant les bonnes pratiques de sécurité est la [Fondation OWASP®](https://owasp.org/) (Open Web Application Security Project®). Elle réunit des milliers de membres, qui contribuent à diffuser la connaissance dans ce domaine.

L'un des projets phares de l'OWASP est le [OWASP Top Ten](https://owasp.org/www-project-top-ten/) : c'est un document qui identifie les 10 principaux risques de sécurité des applications web.

Ce document est régulièrement actualisé : certains risques sortent de la liste, et d'autres y font leur entrée, à chaque nouvelle version. Cela ne signifie pas pour autant qu'il faille négliger les risques qui n'y figurent plus !

À l'heure de l'écriture de ce document, le "Top 10" en vigueur, référencé sur le [dépôt GitHub du projet](https://github.com/OWASP/Top10), est celui de 2017.

Nous avons pris le parti de couvrir 6 de ces 10 risques :

* Injection SQL (_SQL injection_)
* Authentification défectueuse (_Broken Authentication_)
* Exposition de données sensibles (_Sensitive Data Exposure_)
* Contrôle d'accès défectueux (_Broken Access Control_)
* Mauvaise configuration de sécurité (_Security Misconfiguration_)
* _Cross-Site Scripting (XSS)_

Tous ces points, à l'exception de l'avant-dernier, concernent les applications elles-mêmes : ils seront vus dans la première partie. On ajoutera à cette liste plusieurs risques qui n'apparaissent pas explicitement dans le Top 10 OWASP (mais qui sont des "implicites" de plusieurs risques référéncés) :

* CSRF (_Cross-Site Request Forgery_), qui faisait partie de l'édition 2013 du Top 10, et en est sorti pour l'édition 2017.
* La publication "en dur" de paramètres sensibles de l'application.
* Le passage de données sensibles via une URL.
* Les failles dûes à du code n'étant pas passé au crible d'un _linter_ tel qu'[ESLint](https://eslint.org/).

 La deuxième partie permettra d'adresser l'avant-dernier point : les problématiques de configuration des **serveurs** où sont déployés les applications web.

## Première partie : sécurité des applications

### Injection SQL

#### Qu'est-ce que c'est ?

> L'injection SQL consiste à insérer du code SQL malicieux dans une requête.

Cette attaque concerne donc les applications serveur (Node.js, PHP, Java, etc.).

Ce risque est resté en première place du "Top 10" depuis des années. Il est donc indispensable d'y être sensibilisé ! Malgré la profusion d'outils et de bibliothèques permettant de s'en prémunir, de nombreuses applications y sont encore vulnérables. Le [SQL Injection Hall-of-Shame](https://codecurmudgeon.com/wp/sql-injection-hall-of-shame/) référence les attaques par injection SQL subies par des organisations privées ou publiques : IBM, Cisco, Oracle, le secrétariat d'état de l'Ohio aux États-Unis, etc.

#### Exemple avec Node.js et Express

Prenons comme exemple une application web bancaire, permettant à ses visiteurs de consulter leurs comptes. L'application serveur est écrite avec Node.js et Express, et communique avec une base de données MySQL. Elle est architecturée comme une API REST. Une requête sur `/users/:userId/accounts` permettra d'obtenir la liste des comptes d'un utilisateur identifié par `userId` (correspondant à l'`id` de l'utilisateur dans la table `user`).

Cet exemple est détaillé dans des vidéos, qui reprennent la même chose que les sections qui suivent. Il est important de noter qu'il vise _uniquement_ à couvrir l'injection SQL. Ainsi, il souffre de défauts volontairement laissés en l'état, par souci de simplification :

* Paramètres d'accès à la base de données écrits "en dur" dans le code
* Accès à des données sensibles d'un utilisateur en passant son `id` dans l'URL, ce qui serait évitable si on implémentait un système d'authentification

Dans le code qui suit, `connection` correspond à une connection établie via [mysql.createConnection](https://www.npmjs.com/package/mysql2#first-query)). Elle est exportée depuis `db-connection.js`. On ne fait pas apparaître ici que le code utile pour l'exemple :

```javascript
const connection = require('./db-connection');

app.get('/users/:userId/accounts', (req, res) => {
  const { userId } = req.params;
  const sql = `SELECT * FROM account WHERE user_id = ${userId}`;
  connection.query(sql, (err, accounts) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    return res.json(accounts);
  });
});
```

Le problème vient de cette ligne :

```javascript
const sql = `SELECT * FROM account WHERE user_id = ${userId}`;
```

On y crée une requête SQL, en insérant un paramètre qui a été transmis via l'URL, et récupéré via `req.params.userId` ("déstructuré" selon la syntaxe ES6, pour obtenir `userId`). Si le serveur tourne localement et écoute sur le port 5000, on peut accéder aux comptes de l'utilisateur 235 via cette URL :

```
http://localhost:5000/users/235/accounts
```

Dans ce cas, la variable `userId` vaudra `'235'`, et la requête SQL envoyée au serveur MySQL sera :

```sql
SELECT * FROM account WHERE user_id = 235;
```

Mettons-nous maintenant dans la peau d'un utilisateur mal intentionné, et effectuons une requête sur cette URL :

```
http://localhost:8080/users/235 OR 1=1/accounts
```

Dans ce cas, `userId` vaudra `235 OR 1=1`, et la requête SQL deviendra :

```sql
SELECT * FROM account WHERE user_id = 235 OR 1=1;
```

Pouvez-vous voir le problème ?

Dans le `WHERE`, le `OR 1=1` "annule" le filtrage des données selon un `user_id` spécifique. Autrement dit, on va récupérer la liste de **tous les comptes, de tous les utilisateurs** !

Ici, l'attaque par injection SQL mène au troisième risque du Top 10 OWASP : l'**exposition de données sensibles**.

> Les risques de sécurité sont rarement indépendants les uns des autres. Une vulnérabilité peut mener à une autre !

Des attaques encore pires sont possibles. Imaginons que l'attaquant utilise cette URL :

```
http://localhost:8080/users/235 OR 1=1;DROP TABLE account/accounts
```

On obtiendrait alors la requête suivante - ou plutôt **les** requêtes :

```sql
SELECT * FROM account WHERE user_id = 235 OR 1=1;DROP TABLE account;
```

Fort heureusement, deux facteurs limitent la possibilité pour cette attaque de réussir :

* L'attaquant n'a a priori pas la connaissance du schéma de la BDD, et donc des noms des tables : il procède par essai/erreur jusqu'à trouver le nom correct. Il est cependant possible qu'il finisse par le trouver !
* Surtout, les connexions établies avec le module `mysql2` (ou `mysql` qui l'a inspiré) ne permettent pas d'envoyer plusieurs requêtes lors d'un appel à leur méthode `query` : dans le cas ci-dessus, la requête `DROP TABLE account;` sera ignorée.

Il est cependant possible d'autoriser plusieurs requêtes, en utilisant le paramètre `multipleStatements` de `createConnection` : voir [Multiple statement queries](https://github.com/mysqljs/mysql#multiple-statement-queries) dans la documentation du module `mysql`. À utiliser avec précaution, du moins si on ne se prémunit pas contre les injections !

#### Mitigation

Les risques identifiés dans le Top 10 OWASP sont accompagnés de recommandations permettant de diminuer voire annuler leur impact (mitigation). Ces recommandations sont souvent regroupées dans des [Cheat Sheets](https://cheatsheetseries.owasp.org/) thématiques.

Dans le cas précis des injections SQL, une liste complète des stratégies de mitigation est donnée, logiquement, par la [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).

On va détailler ici la première stratégie : l'utilisation de requêtes préparées (_prepared statements_).

La méthode `query` d'un objet "connection" créé avec la méthode `mysql.createConnection` permet d'utiliser des requêtes préparées : au lieu de d'insérer directement le contenu de variables dans les requêtes, on utilise le signe `?` qui sera remplacé par des paramètres.

Ici, on montre juste l'utilisation de la requête préparée, indépendamment de l'application Express :

```javascript
const connection = require('./db-connection');

// This attack won't work anymore
const sql = 'SELECT * FROM account WHERE user_id = ?';
const userId = '235 OR 1=1';
connection.query(sql, [userId], (err, accounts) => {
  console.log(err, accounts);
});
```

Le `?` sera :

* remplacé par la valeur de `userId`,
* dont tout caractère spécial éventuel (`'`, `"`) aura été [échappé](https://fr.wikipedia.org/wiki/Caract%C3%A8re_d%27%C3%A9chappement),
* le tout étant entouré d'apostrophes.

#### Pour en savoir plus

De nombreux articles et vidéos approfondissent le sujet des injections SQL :

* [FR - Wikipédia] [Injection SQL](https://fr.wikipedia.org/wiki/Injection_SQL)
* [EN - Article] [SQL Injection](https://portswigger.net/web-security/sql-injection) sur le site [PortSwigger](https://portswigger.net/) dédié à la cybersécurité.
* [EN - Article] [SQL (Structured query language) Injection](https://www.imperva.com/learn/application-security/sql-injection-sqli/), dans la section [Application Security](https://www.imperva.com/learn/application-security/) d'Imperva, fournisseur de solutions cloud.
* [FR - Vidéo] [Se CONNECTER à un compte SANS mot de passe (faille injection SQL)](https://www.youtube.com/watch?v=uA6_tCXjs3A) ; exemple volontairement simplifié par l'auteur. Dans la "vraie vie", les mots de passe ne seraient pas affichés sur le site ; de plus, ils seraient stockés après chiffement, et impossible à obtenir "en clair".