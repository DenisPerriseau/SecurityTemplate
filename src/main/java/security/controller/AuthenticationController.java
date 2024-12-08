package security.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import security.dto.AssignRolesDto;
import security.dto.LoginUserDto;
import security.dto.RegisterUserDto;
import security.dto.LoginResponseDto;
import security.entity.User;
import security.enums.Role;
import security.enums.ResponseMessage;
import security.services.AuthenticationService;
import security.services.JwtService;
import security.services.RefreshTokenService;
import security.exceptions.AuthenticationExceptions.InvalidRefreshTokenException;

import java.util.Map;

@RequestMapping("/auth")
@RestController
public class AuthenticationController {

    private final JwtService jwtService;
    private final AuthenticationService authenticationService;
    private final UserDetailsService userDetailsService;
    private final RefreshTokenService refreshTokenService;
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);

    // Constructeur
    public AuthenticationController(JwtService jwtService,
                                    AuthenticationService authenticationService,
                                    UserDetailsService userDetailsService,
                                    RefreshTokenService refreshTokenService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
        this.userDetailsService = userDetailsService;
        this.refreshTokenService = refreshTokenService;
    }

    // Endpoint pour l'inscription d'un nouvel utilisateur
    @PostMapping("/signup")
    public ResponseEntity<String> register(@RequestBody RegisterUserDto registerUserDto) {
        logger.info("Tentative d'inscription pour l'utilisateur : {}", registerUserDto.getEmail());

        // Le service gère la logique et lance des exceptions en cas d'erreur
        User registeredUser = authenticationService.signup(registerUserDto, Role.USER);

        logger.info("Utilisateur inscrit avec succès : {}", registeredUser.getEmail());
        return ResponseEntity.ok(ResponseMessage.USER_REGISTERED_SUCCESS.getMessage());
    }


    // Endpoint pour l'authentification de l'utilisateur et la génération des tokens
    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> authenticate(@RequestBody LoginUserDto loginUserDto) {
        logger.info("Login attempt for user: {}", loginUserDto.getEmail());

        // Lancer une exception en cas d'échec d'authentification
        User authenticatedUser = authenticationService.authenticate(loginUserDto);

        String jwtToken = jwtService.generateToken(authenticatedUser);
        String refreshToken = jwtService.generateRefreshToken(authenticatedUser);

        // Sauvegarder le refreshToken en base
        refreshTokenService.createRefreshToken(authenticatedUser.getEmail());
        logger.info("User {} successfully authenticated", authenticatedUser.getEmail());

        LoginResponseDto loginResponseDto = new LoginResponseDto();
        loginResponseDto.setToken(jwtToken);
        loginResponseDto.setExpiresIn(jwtService.getExpirationTime());
        loginResponseDto.setRefreshToken(refreshToken);

        return ResponseEntity.ok(loginResponseDto); // Retourne un LoginResponse
    }

    // Endpoint pour rafraîchir un Access Token
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponseDto> refreshAccessToken(@RequestBody Map<String, String> requestBody) {
        String refreshToken = requestBody.get("refreshToken");
        logger.info("Attempting to refresh token.");

        return refreshTokenService.validateRefreshToken(refreshToken)
                .map(validToken -> {
                    logger.info("Refresh token validated successfully.");
                    UserDetails userDetails = userDetailsService.loadUserByUsername(validToken.getUserEmail());

                    String newAccessToken = jwtService.generateToken(userDetails);
                    LoginResponseDto loginResponseDto = new LoginResponseDto();
                    loginResponseDto.setToken(newAccessToken);
                    loginResponseDto.setExpiresIn(jwtService.getExpirationTime());

                    return ResponseEntity.ok(loginResponseDto); // Retourne un LoginResponse
                })
                .orElseThrow(() -> new InvalidRefreshTokenException(ResponseMessage.ERROR_400.getMessage()));
    }

    // Controller pour la déconnexion
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestBody Map<String, String> requestBody) {
        String refreshToken = requestBody.get("refreshToken");

        if (refreshToken == null || refreshToken.isEmpty()) {
            logger.warn("Logout failed: Refresh token is missing.");
            throw new InvalidRefreshTokenException(ResponseMessage.ERROR_400.getMessage());
        }

        // Supprimer tous les refresh tokens de l'utilisateur
        refreshTokenService.deleteRefreshToken(refreshToken);
        logger.info("User successfully logged out.");
        return ResponseEntity.ok(ResponseMessage.USER_LOGOUT_SUCCESS.getMessage());
    }

    // Endpoint pour attribuer ou modifier les rôles d'un utilisateur
    @PutMapping("/roles")
    public ResponseEntity<String> assignRoles(@RequestBody AssignRolesDto assignRolesDto) {
        logger.info("Tentative d'attribution des rôles pour l'utilisateur : {}", assignRolesDto.getEmail());

        // Assigner ou modifier les rôles de l'utilisateur
        User updatedUser = authenticationService.assignRolesToUser(assignRolesDto.getEmail(), assignRolesDto.getRole());

        logger.info("Rôles assignés avec succès à l'utilisateur : {}", updatedUser.getEmail());
        // Retourner un message de succès

        return ResponseEntity.ok(ResponseMessage.ROLE_ASSIGN_SUCCESS.getMessage()); // Message de succès
    }
}
