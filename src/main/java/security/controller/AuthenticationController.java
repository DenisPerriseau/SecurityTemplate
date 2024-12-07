package security.controller;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import security.dto.LoginUserDto;
import security.dto.RegisterUserDto;
import security.configuration.LoginResponse;
import security.entity.User;
import security.services.AuthenticationService;
import security.services.JwtService;
import security.services.RefreshTokenService;


import java.util.Map;

@RequestMapping("/auth")
@RestController
public class AuthenticationController {

    private final JwtService jwtService;
    private final AuthenticationService authenticationService;
    private final UserDetailsService userDetailsService;
    private final RefreshTokenService refreshTokenService;

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
    public ResponseEntity<User> register(@RequestBody RegisterUserDto registerUserDto) {

        try {
            User registeredUser = authenticationService.signup(registerUserDto);
            return ResponseEntity.ok(registeredUser);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(null);
        }
    }

    // Endpoint pour l'authentification de l'utilisateur et la génération des tokens
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticate(@RequestBody LoginUserDto loginUserDto) {

        try {
            User authenticatedUser = authenticationService.authenticate(loginUserDto);

            String jwtToken = jwtService.generateToken(authenticatedUser);
            String refreshToken = jwtService.generateRefreshToken(authenticatedUser);

            // Sauvegarder le refreshToken en base
            refreshTokenService.createRefreshToken(authenticatedUser.getEmail());

            LoginResponse loginResponse = new LoginResponse();
            loginResponse.setToken(jwtToken);
            loginResponse.setExpiresIn(jwtService.getExpirationTime());
            loginResponse.setRefreshToken(refreshToken);

            return ResponseEntity.ok(loginResponse);
        } catch (Exception e) {
            return ResponseEntity.status(401).body(null);
        }
    }

    // Endpoint pour rafraîchir un Access Token
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refreshAccessToken(@RequestBody Map<String, String> requestBody) {
        String refreshToken = requestBody.get("refreshToken");


        return refreshTokenService.validateRefreshToken(refreshToken)
                .map(validToken -> {

                    UserDetails userDetails = userDetailsService.loadUserByUsername(validToken.getUserEmail());
                    String newAccessToken = jwtService.generateToken(userDetails);

                    LoginResponse loginResponse = new LoginResponse();
                    loginResponse.setToken(newAccessToken);
                    loginResponse.setExpiresIn(jwtService.getExpirationTime());

                    return ResponseEntity.ok(loginResponse); // Retourne un LoginResponse
                })
                .orElseGet(() -> {
                    LoginResponse errorResponse = new LoginResponse();
                    errorResponse.setToken(null);
                    errorResponse.setExpiresIn(0);
                    errorResponse.setRefreshToken("Refresh token invalide ou expiré");

                    return ResponseEntity.status(401).body(errorResponse); // Retourne une erreur
                });
    }

    // Controller pour la déconnexion
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestBody Map<String, String> requestBody) {
        String refreshToken = requestBody.get("refreshToken");

        // Vérification que le refreshToken est bien présent
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.badRequest().body("Refresh token manquant");
        }

        try {
            // Supprimer le refreshToken de la base de données
            refreshTokenService.deleteRefreshToken(refreshToken);

            // Retourner une réponse de succès
            return ResponseEntity.ok("Déconnexion réussie");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Erreur interne du serveur");
        }
    }
}
