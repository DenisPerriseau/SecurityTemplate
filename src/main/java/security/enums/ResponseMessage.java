package security.enums;

import lombok.Getter;

@Getter
public enum ResponseMessage {

    //Utilisateur
    USER_LOGIN_SUCCESS("Utilisateur connecté avec succès."),
    USER_REGISTERED_SUCCESS("Utilisateur inscrit avec succès."),
    USER_INVALID_EMAIL("Utilisateur non trouvé avec l'email"),
    USER_NOT_FOUND("Utilisateur non trouvé"),
    USER_ALREADY_EXISTS("L'utilisateur existe déjà."),
    USER_INVALID_CREDENTIALS("Identifiants invalides."),
    USER_LOGOUT_SUCCESS("Déconnexion réussie."),
    USER_LOGOUT_FAILED("Echec de la déconnexion."),
    USER_ACCOUNT_LOCKED("Compte verrouillé."),
    USER_AUTHENTICATION_FAILED("Échec de l'authentification."),

    //Erreurs
    ERROR_400("Erreur de la requête : Les informations fournies sont incorrectes ou manquantes."),
    ERROR_401("Non autorisé : Vous devez vous authentifier pour accéder à cette ressource."),
    ERROR_403("Accès interdit : Vous n'avez pas les autorisations nécessaires pour accéder à cette ressource."),
    ERROR_404("Non trouvé : La ressource demandée n'existe pas ou a été supprimée."),
    ERROR_500("Erreur interne du serveur : Un problème est survenu lors du traitement de votre demande. Veuillez réessayer plus tard."),
    //Roles
    ROLE_ASSIGN_SUCCESS("Rôles assignés avec succès."),
    ROLE_INVALID("Le rôle est invalide."),

    //Messages
    SUCCESS("Succès"),
    ERROR("Erreur");



    private final String message;

    ResponseMessage(String message) {
        this.message = message;
    }

}