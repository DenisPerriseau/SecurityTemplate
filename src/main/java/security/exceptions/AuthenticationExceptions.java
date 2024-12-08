package security.exceptions;

public class AuthenticationExceptions {

    // Constructeur privé pour empêcher l'instanciation
    private AuthenticationExceptions() {
        throw new UnsupportedOperationException("C'est une classe utilitaire et elle ne peut pas être instanciée.");
    }

    public static class AccountLockedException extends RuntimeException {
        public AccountLockedException(String message) {
            super(message);
        }
    }

    public static class InvalidCredentialsException extends RuntimeException {
        public InvalidCredentialsException(String message) {
            super(message);
        }
    }

    public static class InvalidRefreshTokenException extends RuntimeException {
        public InvalidRefreshTokenException(String message) {
            super(message);
        }

        public InvalidRefreshTokenException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class UserAlreadyExistsException extends RuntimeException {
        public UserAlreadyExistsException(String message) {
            super(message);
        }

        public UserAlreadyExistsException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class AuthenticationFailedException extends RuntimeException {
        public AuthenticationFailedException(String message) {
            super(message);
        }
    }
    public static class InvalidPasswordException extends RuntimeException {
        public InvalidPasswordException(String message) {
            super(message);
        }
    }
    public static class InvalidRoleException extends RuntimeException {
        // Constructeur avec un message

        public InvalidRoleException(String message) {
            super(message);  // Appel au constructeur de RuntimeException pour transmettre le message
        }

        // Constructeur avec message et cause
        public InvalidRoleException(String message, Throwable cause) {
            super(message, cause);  // Appel au constructeur de RuntimeException pour transmettre le message et la cause
        }
    }
    public static class UserNotFoundException extends RuntimeException {

        // Constructeur avec un message
        public UserNotFoundException(String message) {
            super(message);  // Appel au constructeur de RuntimeException pour transmettre le message
        }

        // Constructeur avec message et cause
        public UserNotFoundException(String message, Throwable cause) {
            super(message, cause);  // Appel au constructeur de RuntimeException pour transmettre le message et la cause
        }
    }
    public static class RoleNotFoundException extends RuntimeException {
        public RoleNotFoundException(String roleName) {
            super("Le rôle '" + roleName + "' est introuvable.");
        }
    }
}
