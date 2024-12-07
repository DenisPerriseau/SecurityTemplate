package security.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import security.entity.RefreshToken;
import security.repository.RefreshTokenRepository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Value("${security.jwt.refresh-expiration-time}")
    private long refreshTokenExpirationMs;
    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);
    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        logger.info("Service RefreshTokenService initialisé");
    }

    // Création d'un nouveau refresh token
    public RefreshToken createRefreshToken(String userEmail) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpirationMs));
        refreshToken.setUserEmail(userEmail);

        logger.info("Création d'un refresh token pour l'utilisateur : {}", userEmail);
        return refreshTokenRepository.save(refreshToken);
    }

    // Validation du refresh token
    public Optional<RefreshToken> validateRefreshToken(String token) {
        Optional<RefreshToken> refreshToken = refreshTokenRepository.findByToken(token);
        if (refreshToken.isEmpty() || refreshToken.get().getExpiryDate().isBefore(Instant.now())) {
            logger.warn("Refresh token invalide ou expiré : {}", token);
            return Optional.empty(); // Token non valide ou expiré
        }
        return refreshToken;
    }

    // Suppression d'un refresh token spécifique
    public void deleteRefreshToken(String token) {
        logger.info("Suppression du refresh token : {}", token);
        refreshTokenRepository.deleteByToken(token);
    }

    // Suppression des refresh tokens pour un utilisateur
    public void deleteTokensByUser(String userEmail) {
        logger.info("Suppression des refresh tokens pour l'utilisateur : {}", userEmail);
        refreshTokenRepository.deleteByUserEmail(userEmail);
    }
}
