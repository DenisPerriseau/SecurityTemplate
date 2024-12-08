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

    // Create a new refresh token for a user
    public RefreshToken createRefreshToken(String userEmail) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpirationMs));
        refreshToken.setUserEmail(userEmail);

        return refreshTokenRepository.save(refreshToken);
    }

    // Validate the given refresh token
    public Optional<RefreshToken> validateRefreshToken(String token) {
        Optional<RefreshToken> refreshToken = refreshTokenRepository.findByToken(token);
        // If the token doesn't exist or it is expired, return an empty Optional.
        if (refreshToken.isEmpty() || refreshToken.get().getExpiryDate().isBefore(Instant.now())) {
            return Optional.empty();  // Invalid or expired token
        }
        return refreshToken;
    }

    // Delete a specific refresh token by its token value
    public void deleteRefreshToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }

    // Delete all refresh tokens associated with a specific user (ideal for logging out the user)
    public void deleteTokensByUser(String userEmail) {
        refreshTokenRepository.deleteByUserEmail(userEmail);
    }


}
