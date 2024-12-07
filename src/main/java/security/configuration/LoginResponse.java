package security.configuration;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginResponse {
    
    private String token;
    private long expiresIn;
    private String refreshToken;
}