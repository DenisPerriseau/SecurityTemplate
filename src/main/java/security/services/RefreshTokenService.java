package security.services;


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
    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    // Création d'un nouveau refresh token
    public RefreshToken createRefreshToken(String userEmail) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpirationMs));
        refreshToken.setUserEmail(userEmail);

        return refreshTokenRepository.save(refreshToken);
    }

    // Validation du refresh token
    public Optional<RefreshToken> validateRefreshToken(String token) {
        Optional<RefreshToken> refreshToken = refreshTokenRepository.findByToken(token);
        if (refreshToken.isEmpty() || refreshToken.get().getExpiryDate().isBefore(Instant.now())) {
            return Optional.empty(); // Token non valide ou expiré
        }
        return refreshToken;
    }

    // Suppression d'un refresh token spécifique
    public void deleteRefreshToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }

    // Suppression des refresh tokens pour un utilisateur
    public void deleteTokensByUser(String userEmail) {
        refreshTokenRepository.deleteByUserEmail(userEmail);
    }
}
