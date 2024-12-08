package security.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import security.dto.LoginUserDto;
import security.dto.RegisterUserDto;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import security.entity.User;
import security.enums.ResponseMessage;
import security.exceptions.AuthenticationExceptions;
import security.enums.Role;
import security.repository.UserRepository;

import java.util.regex.Pattern;


@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);
    private static final String PASSWORD_REGEX = "^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+=\\-]).{8,}$";

    public AuthenticationService(
            UserRepository userRepository,
            AuthenticationManager authenticationManager,
            PasswordEncoder passwordEncoder
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User signup(RegisterUserDto input, Role role) {
        logger.info("Tentative d'inscription de l'utilisateur : {}", input.getEmail());

        // Vérification de l'existence de l'email
        if (userRepository.existsByEmail(input.getEmail())) {
            logger.warn("L'utilisateur existe déjà avec l'email : {}", input.getEmail());
            throw new AuthenticationExceptions.UserAlreadyExistsException(ResponseMessage.USER_ALREADY_EXISTS.getMessage());
        }


        // Validation du mot de passe
        if (!Pattern.matches(PASSWORD_REGEX, input.getPassword())) {
            logger.warn("Mot de passe invalide pour l'utilisateur : {}", input.getEmail());
            throw new AuthenticationExceptions.InvalidPasswordException(
                    ResponseMessage.ERROR_403.getMessage()
            );
        }

        // Création et sauvegarde de l'utilisateur
        User user = new User();
        user.setFullName(input.getFullName());
        user.setEmail(input.getEmail());
        user.getRoles().add(role);
        user.setPassword(passwordEncoder.encode(input.getPassword())); // Hachage du mot de passe
        logger.info(ResponseMessage.USER_REGISTERED_SUCCESS.getMessage());
        return userRepository.save(user);
    }

    public User authenticate(LoginUserDto input) {
        logger.info("Authenticating user: {}", input.getEmail());

        // Authentification de l'utilisateur via l'AuthenticationManager
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        input.getEmail(),
                        input.getPassword()
                )
        );

        // Si l'utilisateur est trouvé, retourner l'utilisateur
        return userRepository.findByEmail(input.getEmail())
                .orElseThrow(() -> {
                    logger.warn(ResponseMessage.ERROR_403.getMessage());
                    return new RuntimeException(ResponseMessage.ERROR_403.getMessage());
                });
    }

    public User assignRolesToUser(String email, String role) {
        // Chercher l'utilisateur par son email
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationExceptions.UserNotFoundException(ResponseMessage.USER_INVALID_EMAIL.getMessage()));

        // Convertir le rôle reçu en objet Role
        Role userRole;
        try {
            // Essayer de convertir la chaîne en un rôle valide
            userRole = Role.valueOf(role.toUpperCase());
        } catch (IllegalArgumentException ex) {
            // Si le rôle n'est pas valide, lever une exception personnalisée
            throw new AuthenticationExceptions.InvalidRoleException(ResponseMessage.ROLE_INVALID.getMessage());
        }

        // Assigner le rôle à l'utilisateur (remplaçant tous les rôles précédents)
        user.getRoles().clear();  // On vide les rôles précédents
        user.getRoles().add(userRole);  // On assigne le nouveau rôle

        // Sauvegarder l'utilisateur avec le rôle mis à jour
        return userRepository.save(user);
    }

}

