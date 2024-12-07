# Configuration de Spring Security avec Authentification JWT

Ce projet présente une configuration de Spring Security comprenant l'authentification via JWT, la protection CSRF, et des paramètres personnalisés pour CORS. Il inclut également des points d'API pour l'inscription des utilisateurs, la connexion, la déconnexion et la gestion des tokens de rafraîchissement.

## Fonctionnalités

* **Authentification JWT:** Authentification sécurisée via des tokens JWT.
* **Protection CSRF:** La protection contre les attaques de type Cross-Site Request Forgery est activée.
* **Configuration CORS:** Paramètres personnalisés pour Cross-Origin Resource Sharing (CORS) permettant aux applications frontend d'interagir avec le backend.
* **Gestion des Sessions:** Authentification sans état (stateless) via JWT, sans création de session côté serveur.
* **Journalisation:** Journalisation détaillée pour le débogage et le suivi du processus d'authentification.
* **Inscription et Connexion Utilisateur:** Points d'API pour l'inscription des utilisateurs, la connexion et la génération de tokens.

## Prérequis

* **Java 17+** (ou une version compatible)
* **Spring Boot 2.7+**
* **Spring Security 5.5+**
* **Maven ou Gradle** pour la construction du projet
* **Postman ou un autre outil de test d'API** pour tester les points d'API

## Construire le projet:
# Maven:
mvn spring-boot:run
# Gradle:
gradle build

## Lancer l'application:
# Bash
mvn spring-boot:run

## Gradle:
# Bash
gradle bootRun



## Points d'API
* Inscription: POST /auth/signup
* Connexion: POST /auth/login
* Rafraîchissement de token: POST /auth/refresh
* Déconnexion: POST /auth/logout

Exemple de requête POST pour l'inscription:
```json
{
  "email": "utilisateur@exemple.com",
  "password": "motdepasse123"
}
```

## Configuration
* CSRF: Activé par défaut.
* JWT: Tokens générés avec une durée de vie configurable.
* CORS: Configurable pour autoriser les origines spécifiques.
## Sécurité
* Mots de passe: Encodés avec BCrypt.
* Tokens JWT: Durée de vie limitée.
* CORS: Restreint aux origines autorisées.
